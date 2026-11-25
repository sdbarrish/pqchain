//! Networked node: storage, gossip, block proposal, sampled-quorum voting
//! over the network, finality certificates and catch-up sync.
//!
//! All protocol state lives in [`Engine`], a synchronous state machine behind
//! a mutex. Async tasks only move bytes: one reader and one writer per peer
//! connection, a ticker, the listener, dialers and the RPC server.

use crate::codec::*;
use crate::consensus::{vote_msg, FinalityCert, LightClient, Params};
use crate::crypto::*;
use crate::ledger::*;
use crate::transport;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

pub const ROUND_TIME: Duration = Duration::from_secs(2);
pub const POLL_TIMEOUT: Duration = Duration::from_millis(400);
pub const TICK: Duration = Duration::from_millis(20);
pub const STATUS_EVERY: Duration = Duration::from_secs(1);
pub const MAX_BLOCK_TXS: usize = 1_000;
pub const MAX_MEMPOOL: usize = 10_000;
pub const MAX_ORPHANS: usize = 256;
pub const SYNC_BATCH: u64 = 32;

/// Testnet consensus parameters. alpha=12 of k=20 keeps the network live
/// when a validator is offline; mainnet would use a higher alpha.
pub fn testnet_params() -> Params {
    Params { k: 20, alpha: 12, beta: 15, max_rounds: 0 }
}

pub const CHAINS: [ChainId; 2] = [ChainId::Kerckhoffs, ChainId::Atbash];

pub fn chain_from_str(s: &str) -> Result<ChainId, String> {
    match s.to_ascii_lowercase().as_str() {
        "kerckhoffs" | "k" => Ok(ChainId::Kerckhoffs),
        "atbash" | "a" => Ok(ChainId::Atbash),
        _ => Err(format!("unknown chain '{s}' (use atbash or kerckhoffs)")),
    }
}

pub fn chain_slug(c: ChainId) -> &'static str {
    match c {
        ChainId::Kerckhoffs => "kerckhoffs",
        ChainId::Atbash => "atbash",
    }
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn short(h: &Hash) -> String {
    hex::encode(&h[..6])
}

// ───────────────────────────── files ─────────────────────────────

fn default_alg() -> String {
    alg_name(ALG_ML_DSA_65).into()
}

#[derive(Serialize, Deserialize)]
pub struct KeyFile {
    /// "ML-DSA-65" (default) or "SLH-DSA-SHAKE-128s".
    #[serde(default = "default_alg")]
    pub algorithm: String,
    pub address: String,
    pub public_key: String,
    /// Secret: the 32-byte ML-DSA-65 seed.
    pub seed: String,
}

pub fn save_key(path: &Path, k: &Keypair) -> Result<(), String> {
    let f = KeyFile {
        algorithm: alg_name(k.alg()).into(),
        address: k.address().to_text(),
        public_key: hex::encode(&k.public.bytes),
        seed: hex::encode(k.seed()),
    };
    let json = serde_json::to_string_pretty(&f).map_err(|e| e.to_string())?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    file.write_all(json.as_bytes()).map_err(|e| e.to_string())
}

pub fn load_key(path: &Path) -> Result<Keypair, String> {
    let s = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let f: KeyFile = serde_json::from_str(&s).map_err(|e| format!("{}: {e}", path.display()))?;
    let seed: [u8; 32] = hex::decode(&f.seed)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "seed must be 32 bytes")?;
    let alg = [ALG_ML_DSA_65, ALG_SLH_DSA_SHAKE_128S]
        .into_iter()
        .find(|a| alg_name(*a) == f.algorithm)
        .ok_or(format!("{}: unknown algorithm {}", path.display(), f.algorithm))?;
    let k = Keypair::from_seed_alg(alg, seed)?;
    if k.address().to_text() != f.address {
        return Err(format!("{}: seed does not match address", path.display()));
    }
    Ok(k)
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GenesisValidatorEntry {
    pub signing_key: String,
    pub withdrawal: String,
    pub stake: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Allocation {
    pub address: String,
    pub amount: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Genesis {
    pub network: String,
    pub validators: Vec<GenesisValidatorEntry>,
    pub allocations: Vec<Allocation>,
}

impl Genesis {
    pub fn ledger(&self) -> Result<Ledger, String> {
        let mut vals = Vec::new();
        for v in &self.validators {
            vals.push(GenesisValidator {
                signing_key: PublicKey {
                    alg: ALG_ML_DSA_65,
                    bytes: hex::decode(&v.signing_key).map_err(|e| e.to_string())?,
                },
                withdrawal: Address::from_text(&v.withdrawal)?,
                stake: v.stake,
            });
        }
        let allocs = self
            .allocations
            .iter()
            .map(|a| Ok((Address::from_text(&a.address)?, a.amount)))
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Ledger::genesis(vals, &allocs))
    }

    /// Network ID = hash of the network name and the genesis state.
    pub fn network_id(&self) -> Result<Hash, String> {
        let root = self.ledger()?.state_root();
        Ok(Enc::new("pqchain/network-id").bytes(self.network.as_bytes()).bytes(&root).hash())
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct NodeConfig {
    pub name: String,
    /// Paths are relative to the config file's directory.
    pub key: String,
    pub genesis: String,
    pub data_dir: String,
    pub listen: String,
    pub rpc: String,
    pub peers: Vec<String>,
}

// ───────────────────────────── storage ─────────────────────────────

/// Append-only log of accepted blocks and finality certificates.
/// Record: len u32 | kind u8 | checksum 4 | payload. A torn final record
/// (crash mid-write) is detected and truncated on startup.
pub struct Store {
    file: std::fs::File,
}

pub enum Record {
    Block(Block),
    Cert(FinalityCert),
}

impl Store {
    pub fn open(dir: &Path) -> Result<(Store, Vec<Record>), String> {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let path = dir.join("chain.log");
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).map_err(|e| e.to_string())?;
        let mut records = Vec::new();
        let mut pos = 0usize;
        while pos + 9 <= buf.len() {
            let len = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap()) as usize;
            let kind = buf[pos + 4];
            let sum = &buf[pos + 5..pos + 9];
            let Some(payload) = buf.get(pos + 9..pos + 9 + len) else { break };
            if &sha3_256(payload)[..4] != sum {
                break;
            }
            records.push(match kind {
                0 => Record::Block(Block::from_bytes(payload)?),
                1 => Record::Cert(FinalityCert::from_bytes(payload)?),
                _ => return Err("unknown record kind in chain.log".into()),
            });
            pos += 9 + len;
        }
        if pos != buf.len() {
            eprintln!("store: truncating {} bytes of incomplete data", buf.len() - pos);
            file.set_len(pos as u64).map_err(|e| e.to_string())?;
        }
        Ok((Store { file }, records))
    }

    fn append(&mut self, kind: u8, payload: &[u8]) {
        let mut rec = (payload.len() as u32).to_le_bytes().to_vec();
        rec.push(kind);
        rec.extend_from_slice(&sha3_256(payload)[..4]);
        rec.extend_from_slice(payload);
        if let Err(e) = self.file.write_all(&rec).and_then(|_| self.file.sync_data()) {
            eprintln!("store: write failed: {e}");
        }
    }
}

// ───────────────────────────── messages ─────────────────────────────

#[derive(Clone, Debug)]
pub enum Msg {
    Status { kerckhoffs: u64, atbash: u64 },
    Tx(Tx),
    Block(Block),
    Query { id: u64, chain: ChainId, height: u64 },
    Chits { id: u64, pref: Option<Hash> },
    Vote { chain: ChainId, height: u64, hash: Hash, voter: Address, sig: Signature },
    GetBlocks { chain: ChainId, from: u64 },
    Blocks(Vec<(Block, FinalityCert)>),
    WantBlock { chain: ChainId, height: u64, hash: Hash },
}

impl Wire for (Block, FinalityCert) {
    fn put(&self, w: &mut Writer) {
        self.0.put(w);
        self.1.put(w);
    }
    fn get(r: &mut Reader) -> DecodeResult<Self> {
        Ok((Block::get(r)?, FinalityCert::get(r)?))
    }
}

impl Wire for Msg {
    fn put(&self, w: &mut Writer) {
        match self {
            Msg::Status { kerckhoffs, atbash } => {
                w.u8(0);
                w.u64(*kerckhoffs);
                w.u64(*atbash);
            }
            Msg::Tx(t) => {
                w.u8(1);
                t.put(w);
            }
            Msg::Block(b) => {
                w.u8(2);
                b.put(w);
            }
            Msg::Query { id, chain, height } => {
                w.u8(3);
                w.u64(*id);
                chain.put(w);
                w.u64(*height);
            }
            Msg::Chits { id, pref } => {
                w.u8(4);
                w.u64(*id);
                match pref {
                    None => w.u8(0),
                    Some(h) => {
                        w.u8(1);
                        w.fixed(h);
                    }
                }
            }
            Msg::Vote { chain, height, hash, voter, sig } => {
                w.u8(5);
                chain.put(w);
                w.u64(*height);
                w.fixed(hash);
                voter.put(w);
                sig.put(w);
            }
            Msg::GetBlocks { chain, from } => {
                w.u8(6);
                chain.put(w);
                w.u64(*from);
            }
            Msg::Blocks(v) => {
                w.u8(7);
                w.list(v);
            }
            Msg::WantBlock { chain, height, hash } => {
                w.u8(8);
                chain.put(w);
                w.u64(*height);
                w.fixed(hash);
            }
        }
    }
    fn get(r: &mut Reader) -> DecodeResult<Self> {
        Ok(match r.u8()? {
            0 => Msg::Status { kerckhoffs: r.u64()?, atbash: r.u64()? },
            1 => Msg::Tx(Tx::get(r)?),
            2 => Msg::Block(Block::get(r)?),
            3 => Msg::Query { id: r.u64()?, chain: ChainId::get(r)?, height: r.u64()? },
            4 => {
                let id = r.u64()?;
                let pref = match r.u8()? {
                    0 => None,
                    1 => Some(r.hash()?),
                    _ => return Err("bad chits flag".into()),
                };
                Msg::Chits { id, pref }
            }
            5 => Msg::Vote {
                chain: ChainId::get(r)?,
                height: r.u64()?,
                hash: r.hash()?,
                voter: Address::get(r)?,
                sig: Signature::get(r)?,
            },
            6 => Msg::GetBlocks { chain: ChainId::get(r)?, from: r.u64()? },
            7 => Msg::Blocks(r.list()?),
            8 => Msg::WantBlock { chain: ChainId::get(r)?, height: r.u64()?, hash: r.hash()? },
            _ => return Err("unknown message type".into()),
        })
    }
}

// ───────────────────────────── engine ─────────────────────────────

struct Quorum {
    pref: Hash,
    counts: BTreeMap<Hash, u64>,
    last: Option<Hash>,
    conf: u32,
}

struct Poll {
    chain: ChainId,
    height: u64,
    deadline: Instant,
    pending: BTreeMap<Address, usize>,
    votes: BTreeMap<Hash, usize>,
}

type PeerTx = (u64, mpsc::UnboundedSender<Vec<u8>>);

pub struct Engine {
    pub name: String,
    key: Keypair,
    pub me: Address,
    pub ledger: Ledger,
    store: Store,
    accepted: BTreeMap<(ChainId, u64), (Block, Option<FinalityCert>)>,
    mempool: Vec<Tx>,
    cands: BTreeMap<ChainId, Vec<Block>>,
    orphans: Vec<Block>,
    quorum: BTreeMap<ChainId, Quorum>,
    polls: BTreeMap<u64, Poll>,
    next_poll: u64,
    votes: BTreeMap<(ChainId, u64), Vec<(Hash, Address, Signature)>>,
    wanted: BTreeSet<Hash>,
    wait_since: BTreeMap<ChainId, Instant>,
    proposed: BTreeSet<(ChainId, u64, u32)>,
    pub peers: BTreeMap<Address, PeerTx>,
    peer_tips: BTreeMap<Address, (u64, u64)>,
    last_status: Instant,
    last_sync_req: BTreeMap<ChainId, Instant>,
    params: Params,
}

impl Engine {
    pub fn new(name: String, key: Keypair, genesis: Ledger, store: Store, records: Vec<Record>) -> Result<Self, String> {
        let now = Instant::now();
        let mut e = Engine {
            name,
            me: key.address(),
            key,
            ledger: genesis,
            store,
            accepted: BTreeMap::new(),
            mempool: Vec::new(),
            cands: BTreeMap::new(),
            orphans: Vec::new(),
            quorum: BTreeMap::new(),
            polls: BTreeMap::new(),
            next_poll: 1,
            votes: BTreeMap::new(),
            wanted: BTreeSet::new(),
            wait_since: CHAINS.iter().map(|c| (*c, now)).collect(),
            proposed: BTreeSet::new(),
            peers: BTreeMap::new(),
            peer_tips: BTreeMap::new(),
            last_status: now,
            last_sync_req: BTreeMap::new(),
            params: testnet_params(),
        };
        // Replay the log: rebuild state exactly as it was accepted.
        let n = records.len();
        for r in records {
            match r {
                Record::Block(b) => {
                    e.ledger.apply_block(&b).map_err(|err| format!("replay failed: {err}"))?;
                    e.accepted.insert((b.header().chain, b.header().height), (b, None));
                }
                Record::Cert(c) => {
                    if let Some(entry) = e.accepted.get_mut(&(c.chain, c.height)) {
                        entry.1 = Some(c);
                    }
                }
            }
        }
        if n > 0 {
            e.log(format!(
                "replayed {n} records from disk: kerckhoffs #{} atbash #{} state {}",
                e.ledger.tip(ChainId::Kerckhoffs).0,
                e.ledger.tip(ChainId::Atbash).0,
                short(&e.ledger.state_root())
            ));
        }
        Ok(e)
    }

    fn log(&self, s: String) {
        println!("[{}] {s}", self.name);
    }

    fn send(&self, to: &Address, m: &Msg) {
        if let Some((_, tx)) = self.peers.get(to) {
            let _ = tx.send(m.to_bytes());
        }
    }

    fn broadcast(&self, m: &Msg, except: Option<Address>) {
        let bytes = m.to_bytes();
        for (a, (_, tx)) in &self.peers {
            if Some(*a) != except {
                let _ = tx.send(bytes.clone());
            }
        }
    }

    pub fn is_active_validator(&self) -> bool {
        self.ledger.validators.get(&self.me).is_some_and(|v| v.weight() > 0)
    }

    pub fn on_connect(&mut self, peer: Address) {
        self.log(format!("connected to {peer} (ML-KEM-768 + X25519, ML-DSA-65 authenticated)"));
        self.send(&peer, &self.status_msg());
    }

    fn status_msg(&self) -> Msg {
        Msg::Status {
            kerckhoffs: self.ledger.tip(ChainId::Kerckhoffs).0,
            atbash: self.ledger.tip(ChainId::Atbash).0,
        }
    }

    // ── transactions ──

    pub fn submit_tx(&mut self, tx: Tx, from: Option<Address>) -> Result<Hash, String> {
        let id = tx.id();
        if self.mempool.iter().any(|t| t.id() == id) {
            return Ok(id);
        }
        if self.mempool.len() >= MAX_MEMPOOL {
            return Err("mempool full".into());
        }
        let mut l = self.ledger.clone();
        for t in &self.mempool {
            let _ = t.apply(&mut l);
        }
        tx.apply(&mut l)?;
        self.mempool.push(tx.clone());
        self.broadcast(&Msg::Tx(tx), from);
        Ok(id)
    }

    fn revalidate_mempool(&mut self) {
        let mut l = self.ledger.clone();
        self.mempool.retain(|t| t.apply(&mut l).is_ok());
    }

    // ── blocks ──

    fn add_block(&mut self, b: Block, from: Option<Address>) {
        let (c, h) = (b.header().chain, b.header().height);
        let tip = self.ledger.tip(c).0;
        let hash = b.hash();
        if h <= tip
            || self.cands.get(&c).is_some_and(|v| v.iter().any(|x| x.hash() == hash))
            || self.orphans.iter().any(|x| x.hash() == hash)
        {
            return;
        }
        if h == tip + 1 {
            match self.ledger.clone().apply_block(&b) {
                Ok(()) => {
                    self.quorum.entry(c).or_insert(Quorum {
                        pref: hash,
                        counts: BTreeMap::new(),
                        last: None,
                        conf: 0,
                    });
                    self.cands.entry(c).or_default().push(b.clone());
                    self.broadcast(&Msg::Block(b), from);
                    self.check_vote_finality(c, h);
                    return;
                }
                Err(e) if !e.contains("retry later") && !e.contains("missing or already spent") => {
                    self.log(format!("rejected {} #{h} {}: {e}", c.name(), short(&hash)));
                    return;
                }
                Err(_) => {}
            }
        }
        if self.orphans.len() >= MAX_ORPHANS {
            self.orphans.remove(0);
        }
        self.orphans.push(b);
    }

    fn retry_orphans(&mut self) {
        let orphans = std::mem::take(&mut self.orphans);
        for b in orphans {
            self.add_block(b, None);
        }
    }

    fn accept(&mut self, b: Block, cert: Option<FinalityCert>, how: &str) {
        let (c, h, hash) = (b.header().chain, b.header().height, b.hash());
        if let Err(e) = self.ledger.apply_block(&b) {
            self.log(format!("BUG: decided block {} #{h} failed to apply: {e}", c.name()));
            return;
        }
        self.store.append(0, &b.to_bytes());
        let n = b.body.len();
        let anchor = b.header().anchor;
        self.accepted.insert((c, h), (b, None));
        self.cands.remove(&c);
        self.quorum.remove(&c);
        self.polls.retain(|_, p| p.chain != c);
        self.wait_since.insert(c, Instant::now());
        self.revalidate_mempool();
        self.log(format!(
            "accepted {} #{h} {} ({n} txs) via {how}; state {}",
            c.name(),
            short(&hash),
            short(&self.ledger.state_root())
        ));

        // Validators sign the accepted block for the finality certificate.
        let signer = self
            .ledger
            .validators_at(anchor)
            .and_then(|s| s.get(&self.me))
            .is_some_and(|v| !v.slashed);
        if signer {
            let sig = self.key.sign(ctx::VOTE, &vote_msg(c, h, &hash));
            self.votes.entry((c, h)).or_default().push((hash, self.me, sig.clone()));
            self.broadcast(&Msg::Vote { chain: c, height: h, hash, voter: self.me, sig }, None);
        }
        match cert {
            Some(cert) => self.set_cert(c, h, cert),
            None => self.try_cert(c, h),
        }
        // Forget votes for old heights.
        self.votes.retain(|(vc, vh), _| *vc != c || *vh + 64 > h);
        self.retry_orphans();
    }

    fn set_cert(&mut self, c: ChainId, h: u64, cert: FinalityCert) {
        if let Some(entry) = self.accepted.get_mut(&(c, h)) {
            if entry.1.is_none() {
                self.store.append(1, &cert.to_bytes());
                entry.1 = Some(cert);
            }
        }
    }

    /// Build a certificate from collected votes if > 2/3 of stake signed.
    fn cert_from_votes(&self, c: ChainId, h: u64, b: &Block) -> Option<FinalityCert> {
        let hash = b.hash();
        let votes = self.votes.get(&(c, h))?;
        let mut cert = FinalityCert::new(c, h, hash);
        cert.votes = votes
            .iter()
            .filter(|(vh, _, _)| *vh == hash)
            .map(|(_, a, s)| (*a, s.clone()))
            .collect();
        let set = self.ledger.validators_at(b.header().anchor)?;
        LightClient::from_validators(set).verify(&cert).ok()?;
        Some(cert)
    }

    fn try_cert(&mut self, c: ChainId, h: u64) {
        let Some((b, None)) = self.accepted.get(&(c, h)) else { return };
        if let Some(cert) = self.cert_from_votes(c, h, b) {
            self.set_cert(c, h, cert);
        }
    }

    /// Accept a candidate as soon as a valid > 2/3 certificate exists for it.
    /// This is how full nodes (which do not vote) follow the chain.
    fn check_vote_finality(&mut self, c: ChainId, h: u64) {
        let Some(cands) = self.cands.get(&c) else { return };
        let found = cands.iter().find_map(|b| self.cert_from_votes(c, h, b).map(|cert| (b.clone(), cert)));
        if let Some((b, cert)) = found {
            self.accept(b, Some(cert), "finality certificate");
        }
    }

    fn on_vote(&mut self, from: Address, c: ChainId, h: u64, hash: Hash, voter: Address, sig: Signature) {
        let tip = self.ledger.tip(c).0;
        if h + 64 <= tip || h > tip + 8 {
            return;
        }
        if self.accepted.get(&(c, h)).is_some_and(|e| e.1.is_some()) {
            return;
        }
        let list = self.votes.entry((c, h)).or_default();
        if list.iter().any(|(_, a, _)| *a == voter) {
            return;
        }
        let Some(v) = self.ledger.validators.get(&voter) else { return };
        if !v.signing_key.verify(ctx::VOTE, &vote_msg(c, h, &hash), &sig) {
            return;
        }
        list.push((hash, voter, sig.clone()));
        self.broadcast(&Msg::Vote { chain: c, height: h, hash, voter, sig }, Some(from));
        if h <= tip {
            self.try_cert(c, h);
        } else {
            let known = self.cands.get(&c).is_some_and(|v| v.iter().any(|b| b.hash() == hash));
            if !known && self.wanted.insert(hash) {
                self.send(&from, &Msg::WantBlock { chain: c, height: h, hash });
            }
            self.check_vote_finality(c, h);
        }
    }

    // ── consensus polls ──

    fn start_poll(&mut self, c: ChainId) {
        let Some(q) = self.quorum.get(&c) else { return };
        if self.polls.values().any(|p| p.chain == c) {
            return;
        }
        let Some(set) = self.ledger.validators_at(self.ledger.current_anchor()) else { return };
        let active: Vec<(Address, u64)> =
            set.values().filter(|v| v.weight() > 0).map(|v| (v.node_id, v.weight())).collect();
        let total: u64 = active.iter().map(|(_, w)| w).sum();
        if total == 0 {
            return;
        }
        let mut sample: BTreeMap<Address, usize> = BTreeMap::new();
        for _ in 0..self.params.k {
            let mut r = rand::random_range(0..total);
            for (a, w) in &active {
                if r < *w {
                    *sample.entry(*a).or_default() += 1;
                    break;
                }
                r -= w;
            }
        }
        let id = self.next_poll;
        self.next_poll += 1;
        let height = self.ledger.tip(c).0 + 1;
        let mut poll = Poll {
            chain: c,
            height,
            deadline: Instant::now() + POLL_TIMEOUT,
            pending: BTreeMap::new(),
            votes: BTreeMap::new(),
        };
        for (a, m) in sample {
            if a == self.me {
                *poll.votes.entry(q.pref).or_default() += m;
            } else if self.peers.contains_key(&a) {
                poll.pending.insert(a, m);
                self.send(&a, &Msg::Query { id, chain: c, height });
            } // unreachable validators abstain
        }
        let done = poll.pending.is_empty();
        self.polls.insert(id, poll);
        if done {
            self.finish_poll(id);
        }
    }

    fn on_chits(&mut self, from: Address, id: u64, pref: Option<Hash>) {
        let Some(p) = self.polls.get_mut(&id) else { return };
        let Some(m) = p.pending.remove(&from) else { return };
        if let Some(h) = pref {
            *p.votes.entry(h).or_default() += m;
        }
        if p.pending.is_empty() {
            self.finish_poll(id);
        }
    }

    fn finish_poll(&mut self, id: u64) {
        let Some(p) = self.polls.remove(&id) else { return };
        let c = p.chain;
        if p.height != self.ledger.tip(c).0 + 1 {
            return;
        }
        let Some((best, n)) = p.votes.iter().max_by_key(|(_, n)| **n).map(|(h, n)| (*h, *n)) else {
            if let Some(q) = self.quorum.get_mut(&c) {
                q.conf = 0;
            }
            return;
        };
        let known = self.cands.get(&c).is_some_and(|v| v.iter().any(|b| b.hash() == best));
        let Some(q) = self.quorum.get_mut(&c) else { return };
        if n < self.params.alpha || !known {
            q.conf = 0;
            return;
        }
        *q.counts.entry(best).or_default() += 1;
        if q.counts[&best] > q.counts.get(&q.pref).copied().unwrap_or(0) {
            q.pref = best;
        }
        if q.last == Some(best) {
            q.conf += 1;
        } else {
            q.last = Some(best);
            q.conf = 1;
        }
        if q.conf >= self.params.beta {
            let pref = q.pref;
            if let Some(b) = self.cands.get(&c).and_then(|v| v.iter().find(|b| b.hash() == pref)).cloned() {
                self.accept(b, None, "sampled quorum");
            }
        }
    }

    // ── proposing ──

    fn maybe_propose(&mut self) {
        if !self.is_active_validator() {
            return;
        }
        let now = Instant::now();
        for c in CHAINS {
            if self.cands.get(&c).is_some_and(|v| !v.is_empty()) {
                continue;
            }
            let txs: Vec<Tx> = self.mempool.iter().filter(|t| t.chain() == c).cloned().collect();
            if txs.is_empty() {
                self.wait_since.insert(c, now);
                continue;
            }
            let waited = now - self.wait_since[&c];
            let round = (waited.as_millis() / ROUND_TIME.as_millis()) as u32;
            let (h, parent) = self.ledger.tip(c);
            let anchor = self.ledger.current_anchor();
            if self.ledger.scheduled_proposer(c, h + 1, &parent, round, anchor) != Some(self.me) {
                continue;
            }
            if !self.proposed.insert((c, h + 1, round)) {
                continue;
            }
            let mut l = self.ledger.clone();
            let picked: Vec<Tx> =
                txs.into_iter().filter(|t| t.apply(&mut l).is_ok()).take(MAX_BLOCK_TXS).collect();
            if picked.is_empty() {
                continue;
            }
            let body = match c {
                ChainId::Kerckhoffs => Body::Kerckhoffs(
                    picked.into_iter().filter_map(|t| if let Tx::Kerckhoffs(t) = t { Some(t) } else { None }).collect(),
                ),
                ChainId::Atbash => Body::Atbash(
                    picked.into_iter().filter_map(|t| if let Tx::Atbash(t) = t { Some(t) } else { None }).collect(),
                ),
            };
            let b = propose_round(&self.ledger, &self.key, body, unix_now(), round);
            self.log(format!("proposing {} #{} {} (round {round}, {} txs)", c.name(), h + 1, short(&b.hash()), b.body.len()));
            self.add_block(b, None);
        }
        self.proposed.retain(|(c, h, _)| *h > self.ledger.tip(*c).0);
    }

    // ── sync ──

    fn on_status(&mut self, from: Address, k: u64, a: u64) {
        self.peer_tips.insert(from, (k, a));
        let now = Instant::now();
        for (c, theirs) in [(ChainId::Kerckhoffs, k), (ChainId::Atbash, a)] {
            let mine = self.ledger.tip(c).0;
            let recent = self.last_sync_req.get(&c).is_some_and(|t| now - *t < Duration::from_millis(500));
            if theirs > mine && !recent {
                self.last_sync_req.insert(c, now);
                self.send(&from, &Msg::GetBlocks { chain: c, from: mine + 1 });
            }
        }
    }

    fn on_get_blocks(&self, from: Address, c: ChainId, start: u64) {
        let mut out = Vec::new();
        for h in start..start + SYNC_BATCH {
            match self.accepted.get(&(c, h)) {
                Some((b, Some(cert))) => out.push((b.clone(), cert.clone())),
                _ => break,
            }
        }
        if !out.is_empty() {
            self.send(&from, &Msg::Blocks(out));
        }
    }

    fn on_blocks(&mut self, list: Vec<(Block, FinalityCert)>) {
        for (b, cert) in list {
            let (c, h) = (b.header().chain, b.header().height);
            let tip = self.ledger.tip(c).0;
            if h <= tip {
                continue;
            }
            if h != tip + 1 || cert.chain != c || cert.height != h || cert.block != b.hash() {
                break;
            }
            let Some(set) = self.ledger.validators_at(b.header().anchor) else { break };
            if b.header().anchor > self.ledger.current_anchor() {
                break; // need Kerckhoffs blocks first
            }
            if LightClient::from_validators(set).verify(&cert).is_err() {
                self.log(format!("sync: bad certificate for {} #{h}", c.name()));
                break;
            }
            if self.ledger.clone().apply_block(&b).is_err() {
                break; // cross-chain dependency not yet synced; retried later
            }
            self.accept(b, Some(cert), "sync");
        }
    }

    // ── dispatch ──

    pub fn on_msg(&mut self, from: Address, m: Msg) {
        match m {
            Msg::Status { kerckhoffs, atbash } => self.on_status(from, kerckhoffs, atbash),
            Msg::Tx(t) => {
                let _ = self.submit_tx(t, Some(from));
            }
            Msg::Block(b) => self.add_block(b, Some(from)),
            Msg::Query { id, chain, height } => {
                let tip = self.ledger.tip(chain).0;
                let pref = if height <= tip {
                    self.accepted.get(&(chain, height)).map(|e| e.0.hash())
                } else if height == tip + 1 {
                    self.quorum.get(&chain).map(|q| q.pref)
                } else {
                    None
                };
                self.send(&from, &Msg::Chits { id, pref });
            }
            Msg::Chits { id, pref } => self.on_chits(from, id, pref),
            Msg::Vote { chain, height, hash, voter, sig } => self.on_vote(from, chain, height, hash, voter, sig),
            Msg::GetBlocks { chain, from: start } => self.on_get_blocks(from, chain, start),
            Msg::Blocks(list) => self.on_blocks(list),
            Msg::WantBlock { chain, height, hash } => {
                let b = self
                    .cands
                    .get(&chain)
                    .and_then(|v| v.iter().find(|b| b.hash() == hash))
                    .or_else(|| self.accepted.get(&(chain, height)).map(|e| &e.0).filter(|b| b.hash() == hash))
                    .cloned();
                if let Some(b) = b {
                    self.send(&from, &Msg::Block(b));
                }
            }
        }
    }

    pub fn tick(&mut self) {
        let now = Instant::now();
        let expired: Vec<u64> = self.polls.iter().filter(|(_, p)| p.deadline <= now).map(|(id, _)| *id).collect();
        for id in expired {
            self.finish_poll(id);
        }
        for c in CHAINS {
            if self.cands.get(&c).is_some_and(|v| !v.is_empty()) && self.is_active_validator() {
                self.start_poll(c);
            }
        }
        self.maybe_propose();
        if now - self.last_status >= STATUS_EVERY {
            self.last_status = now;
            self.broadcast(&self.status_msg(), None);
            self.retry_orphans();
        }
    }

    // ── RPC views ──

    pub fn status_json(&self) -> serde_json::Value {
        let chain = |c: ChainId| {
            let (h, hash) = self.ledger.tip(c);
            let certified = self.accepted.get(&(c, h)).is_some_and(|e| e.1.is_some());
            serde_json::json!({ "height": h, "hash": hex::encode(hash), "certified": certified || h == 0 })
        };
        serde_json::json!({
            "node": self.name,
            "address": self.me.to_text(),
            "validator": self.is_active_validator(),
            "peers": self.peers.keys().map(|a| a.to_text()).collect::<Vec<_>>(),
            "kerckhoffs": chain(ChainId::Kerckhoffs),
            "atbash": chain(ChainId::Atbash),
            "mempool": self.mempool.len(),
            "state_root": hex::encode(self.ledger.state_root()),
            "total_stake": self.ledger.total_weight(),
            "burned": self.ledger.burned,
        })
    }

    pub fn block_json(&self, c: ChainId, h: u64) -> Option<serde_json::Value> {
        let (b, cert) = self.accepted.get(&(c, h))?;
        let hd = b.header();
        Some(serde_json::json!({
            "chain": chain_slug(c), "height": h, "hash": hex::encode(b.hash()),
            "parent": hex::encode(hd.parent), "proposer": hd.proposer.to_text(),
            "round": hd.round, "anchor": hd.anchor, "timestamp": hd.timestamp,
            "txs": b.body.tx_ids().iter().map(hex::encode).collect::<Vec<_>>(),
            "certificate": cert.as_ref().map(|c| serde_json::json!({
                "votes": c.votes.len(), "bytes": c.size_bytes() })),
        }))
    }
}

// ───────────────────────────── async runtime ─────────────────────────────

pub type Shared = Arc<Mutex<Engine>>;
static CONN_ID: AtomicU64 = AtomicU64::new(1);

async fn run_session(engine: Shared, sess: transport::Session) {
    let peer = sess.peer;
    let conn = CONN_ID.fetch_add(1, Ordering::Relaxed);
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    {
        let mut e = engine.lock().unwrap();
        if peer == e.me {
            return;
        }
        e.peers.insert(peer, (conn, tx));
        e.on_connect(peer);
    }
    let mut writer = sess.writer;
    let wtask = tokio::spawn(async move {
        while let Some(b) = rx.recv().await {
            if writer.send(&b).await.is_err() {
                break;
            }
        }
    });
    let mut reader = sess.reader;
    loop {
        let Ok(bytes) = reader.recv().await else { break };
        match Msg::from_bytes(&bytes) {
            Ok(m) => engine.lock().unwrap().on_msg(peer, m),
            Err(err) => {
                eprintln!("bad message from {peer}: {err}");
                break;
            }
        }
    }
    wtask.abort();
    let mut e = engine.lock().unwrap();
    if e.peers.get(&peer).map(|p| p.0) == Some(conn) {
        e.peers.remove(&peer);
        e.log(format!("disconnected from {peer}"));
    }
}

fn resolve(base: &Path, p: &str) -> PathBuf {
    let p = Path::new(p);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

pub async fn run(config_path: &Path) -> Result<(), String> {
    let base = config_path.parent().unwrap_or(Path::new(".")).to_path_buf();
    let cfg: NodeConfig = serde_json::from_str(
        &std::fs::read_to_string(config_path).map_err(|e| format!("{}: {e}", config_path.display()))?,
    )
    .map_err(|e| e.to_string())?;
    let key_path = resolve(&base, &cfg.key);
    let genesis: Genesis = serde_json::from_str(
        &std::fs::read_to_string(resolve(&base, &cfg.genesis)).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let network_id = genesis.network_id()?;
    let (store, records) = Store::open(&resolve(&base, &cfg.data_dir))?;
    let engine: Shared = Arc::new(Mutex::new(Engine::new(
        cfg.name.clone(),
        load_key(&key_path)?,
        genesis.ledger()?,
        store,
        records,
    )?));
    let key = Arc::new(load_key(&key_path)?);
    println!(
        "[{}] node {} starting · network {} · p2p {} · rpc {}",
        cfg.name,
        key.address(),
        short(&network_id),
        cfg.listen,
        cfg.rpc
    );

    // Inbound connections.
    let listener = TcpListener::bind(&cfg.listen).await.map_err(|e| format!("{}: {e}", cfg.listen))?;
    {
        let (engine, key) = (engine.clone(), key.clone());
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = listener.accept().await else { continue };
                let (engine, key) = (engine.clone(), key.clone());
                tokio::spawn(async move {
                    let hs = tokio::time::timeout(Duration::from_secs(10), transport::accept(s, &key, &network_id)).await;
                    match hs {
                        Ok(Ok(sess)) => run_session(engine, sess).await,
                        Ok(Err(e)) => eprintln!("inbound handshake failed: {e}"),
                        Err(_) => eprintln!("inbound handshake timed out"),
                    }
                });
            }
        });
    }

    // Outbound connections to configured peers, with reconnect.
    for addr in cfg.peers.clone() {
        let (engine, key) = (engine.clone(), key.clone());
        tokio::spawn(async move {
            loop {
                if let Ok(Ok(s)) = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
                    let _ = s.set_nodelay(true);
                    match tokio::time::timeout(Duration::from_secs(10), transport::connect(s, &key, &network_id, None)).await {
                        Ok(Ok(sess)) => run_session(engine.clone(), sess).await,
                        Ok(Err(e)) => eprintln!("handshake with {addr} failed: {e}"),
                        Err(_) => eprintln!("handshake with {addr} timed out"),
                    }
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }

    // Protocol clock.
    {
        let engine = engine.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(TICK);
            loop {
                iv.tick().await;
                engine.lock().unwrap().tick();
            }
        });
    }

    crate::rpc::serve(&cfg.rpc, engine).await
}
