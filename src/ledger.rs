//! Ledger: the primary network's Atbash Chain (UTXO assets) and Kerckhoffs
//! Chain (staking, validators, slashing, zone registry), plus zones
//! (application chains validated by a subset of primary validators).
//!
//! Cross-chain value moves two ways:
//! * Atbash <-> Kerckhoffs: "atomic memory" (both validated by everyone).
//! * Anything involving a zone: relay messages, proven by the source block's
//!   finality certificate plus a Merkle inclusion proof.

use crate::consensus::{FinalityCert, LightClient};
use crate::hamming::{self, BlobCommitment};
use crate::playfair::{self, BridgeMsg, Counterparty, PlayfairKind};
use crate::feistel::{self, Action, FeistelState, FeistelTx, Receipt, BASE_FEE, MAX_FUEL};
use crate::crypto::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub type ValidatorSet = BTreeMap<Address, Validator>;

pub type AssetId = Hash;
pub const NATIVE: AssetId = [0u8; 32];

pub const TX_FEE: u64 = 1;
pub const MIN_VALIDATOR_STAKE: u64 = 2_000;
pub const MIN_DELEGATION: u64 = 25;
pub const MAX_DELEGATION_FACTOR: u64 = 5;
/// Kerckhoffs blocks between a validator's exit request and the release of
/// its stake. During this window the validator can still be slashed.
pub const UNBONDING_BLOCKS: u64 = 10;
/// Fee (burned) for registering a zone.
pub const ZONE_FEE: u64 = 100;
pub const MAX_ZONE_MEMBERS: usize = 64;
/// New native tokens issued per accepted block (any chain), shared by that
/// chain's validators in proportion to stake (own + delegated).
pub const BLOCK_REWARD: u64 = 1_000;
/// Commission a validator keeps from its delegators' share (basis points).
pub const DELEGATION_FEE_BPS: u64 = 1_000; // 10%

static EMPTY_UTXOS: BTreeMap<OutPoint, TxOut> = BTreeMap::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChainId {
    Kerckhoffs,
    Atbash,
    /// Smart-contract chain (WebAssembly, account-based).
    Feistel,
    /// Data-availability chain (erasure-coded blobs).
    Hamming,
    /// Bridge chain (light clients of other PQ-Chain networks).
    Playfair,
    /// Application chain registered on the Kerckhoffs Chain.
    Zone(u32),
}

impl ChainId {
    /// Stable numeric code used in hashes and on the wire.
    pub fn code(self) -> u64 {
        match self {
            ChainId::Kerckhoffs => 0,
            ChainId::Atbash => 1,
            ChainId::Feistel => 2,
            ChainId::Hamming => 3,
            ChainId::Playfair => 4,
            // Codes 3-15 are reserved for future primary chains (Hamming, Playfair).
            ChainId::Zone(n) => 16 + n as u64,
        }
    }
    pub fn name(self) -> String {
        match self {
            ChainId::Kerckhoffs => "Kerckhoffs Chain".into(),
            ChainId::Atbash => "Atbash Chain".into(),
            ChainId::Feistel => "Feistel Chain".into(),
            ChainId::Hamming => "Hamming Chain".into(),
            ChainId::Playfair => "Playfair Chain".into(),
            ChainId::Zone(n) => format!("Zone {n}"),
        }
    }
    pub fn is_zone(self) -> bool {
        matches!(self, ChainId::Zone(_))
    }
    /// Signature context for transactions on this chain (domain separation:
    /// a signature for one chain is never valid on another).
    pub fn tx_context(self) -> Vec<u8> {
        match self {
            ChainId::Kerckhoffs => ctx::KERCKHOFFS_TX.to_vec(),
            ChainId::Atbash => ctx::ATBASH_TX.to_vec(),
            ChainId::Feistel => ctx::FEISTEL_TX.to_vec(),
            ChainId::Hamming => ctx::HAMMING_TX.to_vec(),
            ChainId::Playfair => ctx::PLAYFAIR_TX.to_vec(),
            ChainId::Zone(n) => format!("pqchain/v2/zone/{n}/tx").into_bytes(),
        }
    }
}

/// Transfers involving a zone travel as relay messages, not atomic memory.
pub fn needs_relay(src: ChainId, dest: ChainId) -> bool {
    src.is_zone() || dest.is_zone()
}

// ───────────────────────────── transactions ─────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct OutPoint {
    pub txid: Hash,
    pub index: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    pub owner: Address,
    pub asset: AssetId,
    pub amount: u64,
}

impl TxOut {
    pub fn native(owner: Address, amount: u64) -> Self {
        TxOut { owner, asset: NATIVE, amount }
    }
    fn encode(&self, e: &mut Enc) {
        e.bytes(&self.owner.0).bytes(&self.asset).u64(self.amount);
    }
}

/// Where an input comes from: this chain's UTXO set, atomic memory (funds
/// exported between the primary chains), or a proven relay message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Local,
    Atomic,
    Relay,
}

/// A cross-chain transfer emitted by a block (an exported output whose
/// route involves a zone).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayMsg {
    pub src: ChainId,
    pub dest: ChainId,
    pub txid: Hash,
    pub index: u32,
    pub out: TxOut,
}

impl RelayMsg {
    pub fn hash(&self) -> Hash {
        let mut e = Enc::new("pqchain/relay-msg");
        e.u64(self.src.code()).u64(self.dest.code()).bytes(&self.txid).u64(self.index as u64);
        self.out.encode(&mut e);
        e.hash()
    }
    pub fn outpoint(&self) -> OutPoint {
        OutPoint { txid: self.txid, index: self.index }
    }
}

/// Self-contained proof that a relay message was emitted by a finalized
/// block on its source chain: the block header, its finality certificate,
/// and a Merkle path from the message to the header's `msg_root`.
#[derive(Clone, Debug)]
pub struct RelayIn {
    pub msg: RelayMsg,
    pub header: BlockHeader,
    pub cert: FinalityCert,
    pub leaf: u32,
    pub branch: Vec<Hash>,
}

#[derive(Clone, Debug)]
pub struct TxIn {
    pub prev: OutPoint,
    pub source: Source,
    pub pubkey: PublicKey,
    pub sig: Signature,
}

/// The value-moving part shared by every transaction on every chain.
#[derive(Clone, Debug, Default)]
pub struct Transfer {
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    /// Outputs sent to another chain (atomic memory or relay message).
    pub export_to: Option<ChainId>,
    pub exported: Vec<TxOut>,
    /// Proofs for inputs with `Source::Relay`.
    pub relay_in: Vec<RelayIn>,
}

impl Transfer {
    /// Signatures are excluded from the txid, so txids are not malleable.
    pub(crate) fn encode(&self, e: &mut Enc) {
        e.u64(self.inputs.len() as u64);
        for i in &self.inputs {
            e.bytes(&i.prev.txid)
                .u64(i.prev.index as u64)
                .u8(i.source as u8)
                .u8(i.pubkey.alg)
                .bytes(&i.pubkey.bytes);
        }
        e.u64(self.outputs.len() as u64);
        for o in &self.outputs {
            o.encode(e);
        }
        e.u64(self.export_to.map_or(u64::MAX, |c| c.code()));
        e.u64(self.exported.len() as u64);
        for o in &self.exported {
            o.encode(e);
        }
        // Commit to which messages are claimed; proofs themselves are not
        // part of the txid (a proof can be refreshed without re-signing).
        e.u64(self.relay_in.len() as u64);
        for r in &self.relay_in {
            e.bytes(&r.msg.hash());
        }
    }

    /// Start an unsigned transfer spending `spends` with the given keys.
    pub fn spend(spends: &[(OutPoint, Source, &Keypair)], outputs: Vec<TxOut>) -> Self {
        Transfer {
            inputs: spends
                .iter()
                .map(|(prev, source, k)| TxIn {
                    prev: *prev,
                    source: *source,
                    pubkey: k.public.clone(),
                    sig: Signature::empty(),
                })
                .collect(),
            outputs,
            export_to: None,
            exported: Vec::new(),
            relay_in: Vec::new(),
        }
    }

    fn sign_all(&mut self, context: &[u8], txid: &Hash, keys: &[&Keypair]) {
        assert_eq!(keys.len(), self.inputs.len(), "one key per input");
        for (inp, k) in self.inputs.iter_mut().zip(keys) {
            inp.sig = k.sign(context, txid);
        }
    }

    fn n_outpoints(&self) -> u32 {
        (self.outputs.len() + self.exported.len()) as u32
    }
}

#[derive(Clone, Debug)]
pub struct AssetDef {
    pub name: String,
    pub supply: u64,
}

/// Atbash Chain transaction: transfers, exports, and new-asset creation.
#[derive(Clone, Debug)]
pub struct AtbashTx {
    pub base: Transfer,
    pub create_asset: Option<AssetDef>,
}

impl AtbashTx {
    pub fn id(&self) -> Hash {
        let mut e = Enc::new("pqchain/atbash-tx");
        self.base.encode(&mut e);
        match &self.create_asset {
            None => e.u8(0),
            Some(a) => e.u8(1).bytes(a.name.as_bytes()).u64(a.supply),
        };
        e.hash()
    }

    /// Asset ID is derived from the first spent outpoint, which can only be
    /// spent once, so asset IDs are globally unique.
    pub fn new_asset_id(&self) -> Option<AssetId> {
        self.create_asset.as_ref()?;
        let first = self.base.inputs.first()?;
        Some(Enc::new("pqchain/asset").bytes(&first.prev.txid).u64(first.prev.index as u64).hash())
    }

    /// Sign for the Atbash Chain.
    pub fn sign(self, keys: &[&Keypair]) -> Self {
        self.sign_for(ChainId::Atbash, keys)
    }

    /// Sign for a specific UTXO chain (Atbash or a zone).
    pub fn sign_for(mut self, chain: ChainId, keys: &[&Keypair]) -> Self {
        let id = self.id();
        self.base.sign_all(&chain.tx_context(), &id, keys);
        self
    }
}

/// Hamming Chain transaction: posts a blob (possibly empty, which makes it a
/// plain transfer) and pays a per-byte fee. Carries the blob's commitment so
/// the id can be computed and checked without the data; validators verify
/// the commitment against the data.
#[derive(Clone, Debug)]
pub struct BlobTx {
    pub base: Transfer,
    pub namespace: [u8; 8],
    pub commitment: BlobCommitment,
    pub data: Vec<u8>,
}

impl BlobTx {
    /// Hash of everything except the blob (payment and namespace).
    pub fn prefix_hash(&self) -> Hash {
        let mut e = Enc::new("pqchain/hamming-prefix");
        self.base.encode(&mut e);
        e.bytes(&self.namespace);
        e.hash()
    }
    pub fn id(&self) -> Hash {
        hamming::tx_id(&self.prefix_hash(), &self.commitment)
    }
    pub fn new(base: Transfer, namespace: [u8; 8], data: Vec<u8>) -> Self {
        BlobTx { base, namespace, commitment: hamming::commit(&data), data }
    }
    pub fn sign(mut self, keys: &[&Keypair]) -> Self {
        let id = self.id();
        self.base.sign_all(ctx::HAMMING_TX, &id, keys);
        self
    }
}

/// Playfair Chain transaction (bridges).
#[derive(Clone, Debug)]
pub struct PlayfairTx {
    pub base: Transfer,
    pub kind: PlayfairKind,
}

impl PlayfairTx {
    pub fn id(&self) -> Hash {
        let mut e = Enc::new("pqchain/playfair-tx");
        self.base.encode(&mut e);
        self.kind.encode(&mut e);
        e.hash()
    }
    pub fn sign(mut self, keys: &[&Keypair]) -> Self {
        let id = self.id();
        self.base.sign_all(ctx::PLAYFAIR_TX, &id, keys);
        self
    }
    /// Unsigned, input-less transaction (Update and Receive are proven, not paid).
    pub fn proven(kind: PlayfairKind) -> Self {
        PlayfairTx { base: Transfer::default(), kind }
    }
}

/// A signed block header: what a proposer commits to.
#[derive(Clone, Debug)]
pub struct SignedHeader {
    pub header: BlockHeader,
    pub sig: Signature,
}

#[derive(Clone, Debug)]
pub enum KerckhoffsKind {
    /// Plain transfer / import from atomic memory.
    Transfer,
    /// Become a Tier-1 validator. `signing_key` is the hot ML-DSA block key;
    /// `withdrawal` should be a cold (offline) address.
    AddValidator { signing_key: PublicKey, withdrawal: Address, stake: u64 },
    /// Tier-3 delegator: lend stake to a validator.
    AddDelegator { node: Address, stake: u64, reward: Address },
    /// Proof that a validator signed two different blocks at the same height.
    Slash { a: Box<SignedHeader>, b: Box<SignedHeader> },
    /// Validator leaves the set. Must be signed by the key behind the
    /// validator's cold withdrawal address (typically SLH-DSA). Stake is
    /// released to that address after `UNBONDING_BLOCKS`.
    Exit { node: Address, authority: PublicKey, sig: Signature },
    /// Register a zone validated by the listed primary validators.
    CreateZone { name: String, members: Vec<Address> },
    /// Pay out accumulated staking rewards to `authority`'s address. `nonce`
    /// must equal the address's claim count, so a claim cannot be replayed.
    ClaimRewards { authority: PublicKey, nonce: u64, sig: Signature },
}

#[derive(Clone, Debug)]
pub struct KerckhoffsTx {
    pub base: Transfer,
    pub kind: KerckhoffsKind,
}

impl KerckhoffsTx {
    pub fn id(&self) -> Hash {
        let mut e = Enc::new("pqchain/kerckhoffs-tx");
        self.base.encode(&mut e);
        match &self.kind {
            KerckhoffsKind::Transfer => e.u8(0),
            KerckhoffsKind::AddValidator { signing_key, withdrawal, stake } => e
                .u8(1)
                .u8(signing_key.alg)
                .bytes(&signing_key.bytes)
                .bytes(&withdrawal.0)
                .u64(*stake),
            KerckhoffsKind::AddDelegator { node, stake, reward } => {
                e.u8(2).bytes(&node.0).u64(*stake).bytes(&reward.0)
            }
            KerckhoffsKind::Slash { a, b } => e
                .u8(3)
                .bytes(&a.header.hash())
                .bytes(&a.sig.bytes)
                .bytes(&b.header.hash())
                .bytes(&b.sig.bytes),
            // The exit signature itself is excluded so it can sign the txid.
            KerckhoffsKind::Exit { node, authority, .. } => {
                e.u8(4).bytes(&node.0).u8(authority.alg).bytes(&authority.bytes)
            }
            KerckhoffsKind::CreateZone { name, members } => {
                e.u8(5).bytes(name.as_bytes()).u64(members.len() as u64);
                for m in members {
                    e.bytes(&m.0);
                }
                &mut e
            }
            KerckhoffsKind::ClaimRewards { authority, nonce, .. } => {
                e.u8(6).u8(authority.alg).bytes(&authority.bytes).u64(*nonce)
            }
        };
        e.hash()
    }

    /// Build a reward claim signed by the address owner's key.
    pub fn claim_rewards(key: &Keypair, nonce: u64) -> Self {
        let mut tx = KerckhoffsTx {
            base: Transfer::default(),
            kind: KerckhoffsKind::ClaimRewards { authority: key.public.clone(), nonce, sig: Signature::empty() },
        };
        let id = tx.id();
        if let KerckhoffsKind::ClaimRewards { sig, .. } = &mut tx.kind {
            *sig = key.sign(ctx::CLAIM, &id);
        }
        tx
    }

    pub fn sign(mut self, keys: &[&Keypair]) -> Self {
        let id = self.id();
        self.base.sign_all(ctx::KERCKHOFFS_TX, &id, keys);
        self
    }

    /// Build a validator exit signed by the withdrawal (cold) key.
    pub fn exit(node: Address, withdrawal_key: &Keypair) -> Self {
        let mut tx = KerckhoffsTx {
            base: Transfer::default(),
            kind: KerckhoffsKind::Exit {
                node,
                authority: withdrawal_key.public.clone(),
                sig: Signature::empty(),
            },
        };
        let id = tx.id();
        if let KerckhoffsKind::Exit { sig, .. } = &mut tx.kind {
            *sig = withdrawal_key.sign(ctx::EXIT, &id);
        }
        tx
    }
}

// ───────────────────────────── blocks ─────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub chain: ChainId,
    pub height: u64,
    pub parent: Hash,
    pub tx_root: Hash,
    pub proposer: Address,
    pub timestamp: u64,
    /// Proposal round: if the scheduled proposer is offline, the proposer for
    /// round 1, 2, ... takes over after a timeout.
    pub round: u32,
    /// Kerckhoffs Chain height whose validator set governs this block. Makes
    /// validity independent of the order in which chains are accepted.
    pub anchor: u64,
    /// Kerckhoffs blocks: hash of the active validator set after this block
    /// (lets other networks' light clients follow validator changes).
    /// Other chains: all zeros.
    pub set_root: Hash,
    /// Merkle root of the relay messages this block emits.
    pub msg_root: Hash,
}

impl BlockHeader {
    pub fn hash(&self) -> Hash {
        Enc::new("pqchain/block-header")
            .u64(self.chain.code())
            .u64(self.height)
            .bytes(&self.parent)
            .bytes(&self.tx_root)
            .bytes(&self.proposer.0)
            .u64(self.timestamp)
            .u64(self.round as u64)
            .u64(self.anchor)
            .bytes(&self.msg_root)
            .bytes(&self.set_root)
            .hash()
    }
}

/// Block body. `Atbash` is the UTXO body used by the Atbash Chain and by zones.
#[derive(Clone, Debug)]
pub enum Body {
    Atbash(Vec<AtbashTx>),
    Kerckhoffs(Vec<KerckhoffsTx>),
    Feistel(Vec<FeistelTx>),
    Hamming(Vec<BlobTx>),
    Playfair(Vec<PlayfairTx>),
}

impl Body {
    pub fn tx_ids(&self) -> Vec<Hash> {
        match self {
            Body::Atbash(t) => t.iter().map(AtbashTx::id).collect(),
            Body::Kerckhoffs(t) => t.iter().map(KerckhoffsTx::id).collect(),
            Body::Feistel(t) => t.iter().map(FeistelTx::id).collect(),
            Body::Hamming(t) => t.iter().map(BlobTx::id).collect(),
            Body::Playfair(t) => t.iter().map(PlayfairTx::id).collect(),
        }
    }
    pub fn len(&self) -> usize {
        match self {
            Body::Atbash(t) => t.len(),
            Body::Kerckhoffs(t) => t.len(),
            Body::Feistel(t) => t.len(),
            Body::Hamming(t) => t.len(),
            Body::Playfair(t) => t.len(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Clone, Debug)]
pub struct Block {
    pub signed: SignedHeader,
    pub body: Body,
}

impl Block {
    pub fn hash(&self) -> Hash {
        self.signed.header.hash()
    }
    pub fn header(&self) -> &BlockHeader {
        &self.signed.header
    }

    /// Relay messages emitted by this block, in order.
    pub fn messages(&self) -> Vec<RelayMsg> {
        body_messages(self.signed.header.chain, &self.body)
    }
}

pub fn body_messages(src: ChainId, body: &Body) -> Vec<RelayMsg> {
    let mut msgs = Vec::new();
    if let Body::Atbash(txs) = body {
        for tx in txs {
            let Some(dest) = tx.base.export_to else { continue };
            if !needs_relay(src, dest) {
                continue;
            }
            let txid = tx.id();
            for (j, out) in tx.base.exported.iter().enumerate() {
                let index = (tx.base.outputs.len() + j) as u32;
                msgs.push(RelayMsg { src, dest, txid, index, out: out.clone() });
            }
        }
    }
    msgs
}

pub fn msg_root(msgs: &[RelayMsg]) -> Hash {
    merkle_root(&msgs.iter().map(RelayMsg::hash).collect::<Vec<_>>())
}

/// A registered zone. Membership is fixed at creation in v2.
#[derive(Clone, Debug)]
pub struct Zone {
    pub id: u32,
    pub name: String,
    pub members: Vec<Address>,
    pub created_at: u64,
}

// ───────────────────────────── state ─────────────────────────────

#[derive(Clone, Debug)]
pub struct Validator {
    pub node_id: Address,
    pub signing_key: PublicKey,
    pub withdrawal: Address,
    pub stake: u64,
    pub delegated: u64,
    pub slashed: bool,
    /// Kerckhoffs height at which an exiting validator's stake is released.
    pub exit_at: Option<u64>,
}

impl Validator {
    /// Voting / proposing weight. Slashed and exiting validators have none.
    pub fn weight(&self) -> u64 {
        if self.slashed || self.exit_at.is_some() {
            0
        } else {
            self.stake.saturating_add(self.delegated)
        }
    }
}

/// Per-validator shares of one block's reward, proportional to weight.
/// Rounds down, so the sum never exceeds `BLOCK_REWARD` (proved with Kani).
pub(crate) fn reward_shares(weights: &[u64]) -> Vec<u128> {
    let total: u128 = weights.iter().map(|w| *w as u128).sum();
    if total == 0 {
        return vec![0; weights.len()];
    }
    weights.iter().map(|w| BLOCK_REWARD as u128 * *w as u128 / total).collect()
}

/// Split a validator's share between itself (own stake + commission) and its
/// delegators (pro rata). Requires `stake <= weight`. Never pays out more than
/// `share` (proved with Kani).
pub(crate) fn split_validator_reward(share: u128, stake: u64, weight: u64, delegations: &[u64]) -> (u128, Vec<u128>) {
    if weight == 0 {
        return (0, vec![0; delegations.len()]);
    }
    let own = share * stake as u128 / weight as u128;
    let to_delegators = share - own;
    let fee = to_delegators * DELEGATION_FEE_BPS as u128 / 10_000;
    let pool = to_delegators - fee;
    let dsum: u128 = delegations.iter().map(|d| *d as u128).sum();
    let parts = delegations.iter().map(|d| if dsum == 0 { 0 } else { pool * *d as u128 / dsum }).collect();
    (own + fee, parts)
}

#[derive(Clone, Debug)]
pub struct Delegation {
    pub node: Address,
    pub stake: u64,
    pub reward: Address,
}

/// Full replicated state of the primary network. Every node (validator,
/// full node) holds its own copy and re-executes every block.
#[derive(Clone, Debug, Default)]
pub struct Ledger {
    pub atbash_utxos: BTreeMap<OutPoint, TxOut>,
    pub kerckhoffs_utxos: BTreeMap<OutPoint, TxOut>,
    pub hamming_utxos: BTreeMap<OutPoint, TxOut>,
    pub playfair_utxos: BTreeMap<OutPoint, TxOut>,
    /// This network's id (from genesis); bridge messages are addressed by it.
    pub network_id: Hash,
    /// Light clients of other networks, by network id.
    pub counterparties: BTreeMap<Hash, Counterparty>,
    /// Native tokens escrowed for each counterparty network.
    pub escrowed: BTreeMap<Hash, u64>,
    /// Bridge messages already received: (source network, message hash).
    pub bridge_received: BTreeSet<(Hash, Hash)>,
    /// (destination chain, outpoint) -> output waiting to be imported.
    pub atomic: BTreeMap<(ChainId, OutPoint), TxOut>,
    pub validators: ValidatorSet,
    /// Snapshot of the validator set after each Kerckhoffs block (shared, cheap to clone).
    pub validator_history: BTreeMap<u64, Arc<ValidatorSet>>,
    pub delegations: Vec<Delegation>,
    pub burned: u64,
    pub tips: BTreeMap<ChainId, (u64, Hash)>,
    /// Anchor of the last accepted block on each chain (must not go backwards).
    pub anchors: BTreeMap<ChainId, u64>,
    pub zones: BTreeMap<u32, Zone>,
    pub zone_utxos: BTreeMap<u32, BTreeMap<OutPoint, TxOut>>,
    /// Relay messages already claimed: (source chain, outpoint).
    pub relay_consumed: BTreeSet<(ChainId, OutPoint)>,
    /// Unclaimed staking rewards per address.
    pub rewards: BTreeMap<Address, u64>,
    /// Number of reward claims made per address (replay protection).
    pub claim_nonces: BTreeMap<Address, u64>,
    /// Total native tokens issued as rewards.
    pub minted: u64,
    pub feistel: FeistelState,
    /// Recent Feistel receipts by txid. Derived data, not part of the state root.
    pub receipts: BTreeMap<Hash, Receipt>,
}

pub struct GenesisValidator {
    pub signing_key: PublicKey,
    pub withdrawal: Address,
    pub stake: u64,
}

impl Ledger {
    pub fn genesis(validators: Vec<GenesisValidator>, x_allocs: &[(Address, u64)]) -> Self {
        let mut l = Ledger::default();
        let gid = Enc::new("pqchain/genesis/v0").hash();
        for (i, (owner, amount)) in x_allocs.iter().enumerate() {
            l.atbash_utxos.insert(OutPoint { txid: gid, index: i as u32 }, TxOut::native(*owner, *amount));
        }
        for gv in validators {
            let node_id = gv.signing_key.address();
            l.validators.insert(
                node_id,
                Validator {
                    node_id,
                    signing_key: gv.signing_key,
                    withdrawal: gv.withdrawal,
                    stake: gv.stake,
                    delegated: 0,
                    slashed: false,
                    exit_at: None,
                },
            );
        }
        for c in [ChainId::Kerckhoffs, ChainId::Atbash, ChainId::Feistel, ChainId::Hamming, ChainId::Playfair] {
            l.tips.insert(c, (0, Enc::new("pqchain/genesis-block").u64(c.code()).hash()));
            l.anchors.insert(c, 0);
        }
        l.validator_history.insert(0, Arc::new(l.validators.clone()));
        l
    }

    /// Tip of a chain; (0, zero hash) for a chain this ledger does not know.
    pub fn tip(&self, chain: ChainId) -> (u64, Hash) {
        self.tips.get(&chain).copied().unwrap_or((0, [0; 32]))
    }

    /// Every chain this ledger tracks: the two primary chains plus zones.
    pub fn chains(&self) -> Vec<ChainId> {
        let mut v = vec![ChainId::Kerckhoffs, ChainId::Atbash, ChainId::Feistel, ChainId::Hamming, ChainId::Playfair];
        v.extend(self.zones.keys().map(|n| ChainId::Zone(*n)));
        v
    }

    pub fn knows(&self, chain: ChainId) -> bool {
        self.tips.contains_key(&chain)
    }

    /// Validators of `chain` as of a Kerckhoffs height: all primary
    /// validators for the primary chains, the members for a zone.
    pub fn chain_validators(&self, chain: ChainId, anchor: u64) -> Option<ValidatorSet> {
        let set = self.validators_at(anchor)?;
        match chain {
            ChainId::Kerckhoffs | ChainId::Atbash | ChainId::Feistel | ChainId::Hamming | ChainId::Playfair => {
                Some(set.clone())
            }
            ChainId::Zone(n) => {
                let z = self.zones.get(&n)?;
                if z.created_at > anchor {
                    return None;
                }
                Some(set.iter().filter(|(a, _)| z.members.contains(a)).map(|(a, v)| (*a, v.clone())).collect())
            }
        }
    }

    pub fn total_weight(&self) -> u64 {
        self.validators.values().map(Validator::weight).sum()
    }

    /// Validator set as of a Kerckhoffs height.
    pub fn validators_at(&self, anchor: u64) -> Option<&ValidatorSet> {
        self.validator_history.range(..=anchor).next_back().map(|(_, v)| &**v)
    }

    /// The anchor an honest proposer uses now: the local Kerckhoffs tip.
    pub fn current_anchor(&self) -> u64 {
        self.tip(ChainId::Kerckhoffs).0
    }

    /// Balance of `owner` for `asset` on a chain.
    pub fn balance(&self, chain: ChainId, owner: &Address, asset: &AssetId) -> u64 {
        self.utxos(chain)
            .values()
            .filter(|o| &o.owner == owner && &o.asset == asset)
            .map(|o| o.amount)
            .sum()
    }

    /// Spendable outpoints for an owner (wallet helper).
    pub fn utxos_of(&self, chain: ChainId, owner: &Address) -> Vec<(OutPoint, TxOut)> {
        self.utxos(chain)
            .iter()
            .filter(|(_, o)| &o.owner == owner)
            .map(|(p, o)| (*p, o.clone()))
            .collect()
    }

    pub fn atomic_of(&self, dest: ChainId, owner: &Address) -> Vec<(OutPoint, TxOut)> {
        self.atomic
            .iter()
            .filter(|((c, _), o)| *c == dest && &o.owner == owner)
            .map(|((_, p), o)| (*p, o.clone()))
            .collect()
    }

    fn utxos(&self, chain: ChainId) -> &BTreeMap<OutPoint, TxOut> {
        match chain {
            ChainId::Kerckhoffs => &self.kerckhoffs_utxos,
            ChainId::Atbash => &self.atbash_utxos,
            ChainId::Zone(n) => self.zone_utxos.get(&n).unwrap_or(&EMPTY_UTXOS),
            ChainId::Feistel => &EMPTY_UTXOS, // account-based
            ChainId::Hamming => &self.hamming_utxos,
            ChainId::Playfair => &self.playfair_utxos,
        }
    }
    fn utxos_mut(&mut self, chain: ChainId) -> &mut BTreeMap<OutPoint, TxOut> {
        match chain {
            ChainId::Kerckhoffs => &mut self.kerckhoffs_utxos,
            ChainId::Hamming => &mut self.hamming_utxos,
            ChainId::Playfair => &mut self.playfair_utxos,
            ChainId::Atbash => &mut self.atbash_utxos,
            ChainId::Zone(n) => self.zone_utxos.entry(n).or_default(),
            ChainId::Feistel => unreachable!("the Feistel Chain is account-based (apply_utxo rejects it)"),
        }
    }

    /// Check a relay proof for delivery to `dest`. Depends only on the
    /// proof and the validator registry, not on the source chain's state.
    pub fn verify_relay(&self, dest: ChainId, ri: &RelayIn) -> Result<(), String> {
        let (m, h) = (&ri.msg, &ri.header);
        if m.dest != dest {
            return Err("relay message is addressed to another chain".into());
        }
        if m.src == dest || !needs_relay(m.src, m.dest) {
            return Err("not a relay route".into());
        }
        if h.chain != m.src {
            return Err("proof header is from the wrong chain".into());
        }
        if ri.cert.chain != h.chain || ri.cert.height != h.height || ri.cert.block != h.hash() {
            return Err("finality certificate does not match the header".into());
        }
        if h.anchor > self.current_anchor() {
            return Err("relay proof anchor is ahead of the local Kerckhoffs tip (retry later)".into());
        }
        let set = self.chain_validators(h.chain, h.anchor).ok_or("source chain unknown at proof anchor")?;
        LightClient::from_validators(&set).verify(&ri.cert).map_err(|e| format!("relay certificate: {e}"))?;
        if !merkle_verify(&m.hash(), ri.leaf, &ri.branch, &h.msg_root) {
            return Err("relay message is not included in the source block".into());
        }
        Ok(())
    }

    /// Deterministic, stake-weighted leader schedule for (height, round),
    /// computed over the validator set at `anchor`.
    pub fn scheduled_proposer(
        &self,
        chain: ChainId,
        height: u64,
        parent: &Hash,
        round: u32,
        anchor: u64,
    ) -> Option<Address> {
        let set = self.chain_validators(chain, anchor)?;
        let total: u64 = set.values().map(Validator::weight).sum();
        if total == 0 {
            return None;
        }
        let seed = Enc::new("pqchain/leader")
            .u64(chain.code())
            .u64(height)
            .bytes(parent)
            .u64(round as u64)
            .hash();
        let mut r = u64::from_le_bytes(seed[..8].try_into().unwrap()) % total;
        for v in set.values().filter(|v| !v.slashed) {
            if r < v.weight() {
                return Some(v.node_id);
            }
            r -= v.weight();
        }
        None
    }

    /// Remove and authenticate inputs. Returns per-asset input totals.
    /// Callers work on a clone, so partial mutation on error is harmless.
    fn spend_inputs(
        &mut self,
        chain: ChainId,
        t: &Transfer,
        txid: &Hash,
        context: &[u8],
    ) -> Result<BTreeMap<AssetId, u128>, String> {
        let mut totals = BTreeMap::new();
        let relay_inputs = t.inputs.iter().filter(|i| i.source == Source::Relay).count();
        if relay_inputs != t.relay_in.len() {
            return Err("every relay proof must back exactly one relay input".into());
        }
        for inp in &t.inputs {
            let out = match inp.source {
                Source::Local => self.utxos_mut(chain).remove(&inp.prev),
                Source::Atomic => self.atomic.remove(&(chain, inp.prev)),
                Source::Relay => {
                    let ri = t
                        .relay_in
                        .iter()
                        .find(|r| r.msg.outpoint() == inp.prev)
                        .ok_or("relay input without a matching proof")?;
                    self.verify_relay(chain, ri)?;
                    if !self.relay_consumed.insert((ri.msg.src, inp.prev)) {
                        return Err("relay message already claimed (double-spend)".into());
                    }
                    Some(ri.msg.out.clone())
                }
            }
            .ok_or("input missing or already spent (double-spend)")?;
            if inp.pubkey.address() != out.owner {
                return Err("public key does not match the output's owner".into());
            }
            if !inp.pubkey.verify(context, txid, &inp.sig) {
                return Err("invalid transaction signature".into());
            }
            *totals.entry(out.asset).or_insert(0u128) += out.amount as u128;
        }
        Ok(totals)
    }

    fn create_outputs(
        &mut self,
        chain: ChainId,
        t: &Transfer,
        txid: &Hash,
    ) -> Result<BTreeMap<AssetId, u128>, String> {
        let mut totals = BTreeMap::new();
        match (t.export_to, t.exported.is_empty()) {
            (None, true) => {}
            (Some(dest), false) if dest != chain => {
                if matches!(
                    (chain, dest),
                    (ChainId::Kerckhoffs, ChainId::Zone(_)) | (ChainId::Zone(_), ChainId::Kerckhoffs)
                ) {
                    return Err("zones exchange value with the Atbash Chain and other zones, not Kerckhoffs".into());
                }
                if dest == ChainId::Feistel && chain != ChainId::Atbash {
                    return Err("the Feistel Chain is funded from the Atbash Chain only".into());
                }
                let atbash_only = |c: ChainId| matches!(c, ChainId::Hamming | ChainId::Playfair);
                if (atbash_only(chain) && dest != ChainId::Atbash) || (atbash_only(dest) && chain != ChainId::Atbash) {
                    return Err("the Hamming and Playfair Chains exchange value with the Atbash Chain only".into());
                }
                if !self.knows(dest) {
                    return Err("export to an unknown chain".into());
                }
            }
            _ => return Err("bad export: needs a different destination chain and outputs".into()),
        }
        for (i, o) in t.outputs.iter().chain(&t.exported).enumerate() {
            if o.amount == 0 {
                return Err("zero-value output".into());
            }
            let op = OutPoint { txid: *txid, index: i as u32 };
            if i < t.outputs.len() {
                self.utxos_mut(chain).insert(op, o.clone());
            } else {
                let dest = t.export_to.unwrap();
                if !needs_relay(chain, dest) {
                    self.atomic.insert((dest, op), o.clone());
                } // else: carried by a relay message committed in the block's msg_root
            }
            *totals.entry(o.asset).or_insert(0u128) += o.amount as u128;
        }
        Ok(totals)
    }

    pub fn apply_atbash(&mut self, tx: &AtbashTx) -> Result<(), String> {
        self.apply_utxo(ChainId::Atbash, tx)
    }

    /// Apply a Feistel (smart-contract) transaction. A valid transaction whose
    /// execution fails is still included: its effects are rolled back, but it
    /// consumes its nonce and pays for the fuel it used.
    pub fn apply_feistel(&mut self, tx: &FeistelTx) -> Result<Receipt, String> {
        self.atomically(|l| l.apply_feistel_inner(tx))
    }

    fn apply_feistel_inner(&mut self, tx: &FeistelTx) -> Result<Receipt, String> {
        let id = tx.id();
        let sender = tx.sender();
        if !tx.from.verify(ctx::FEISTEL_TX, &id, &tx.sig) {
            return Err("invalid transaction signature".into());
        }
        if tx.nonce != self.feistel.nonce(&sender) {
            return Err("bad nonce (stale or future)".into());
        }
        if tx.max_fuel > MAX_FUEL {
            return Err(format!("max_fuel above the {MAX_FUEL} limit"));
        }
        let max_fee = tx.max_fee();
        let receipt = if let Action::Import { outpoints } = &tx.action {
            let unique: BTreeSet<_> = outpoints.iter().collect();
            if outpoints.is_empty() || outpoints.len() > 256 || unique.len() != outpoints.len() {
                return Err("import needs 1-256 distinct outpoints".into());
            }
            let mut total = 0u64;
            for p in outpoints {
                let o = self.atomic.get(&(ChainId::Feistel, *p)).ok_or("import: no such export")?;
                if o.owner != sender || o.asset != NATIVE {
                    return Err("import: export belongs to someone else or is not native".into());
                }
                total += o.amount;
            }
            if total < BASE_FEE {
                return Err("import smaller than the fee".into());
            }
            for p in outpoints {
                self.atomic.remove(&(ChainId::Feistel, *p));
            }
            self.feistel.credit_pub(sender, total);
            *self.feistel.nonces.entry(sender).or_default() += 1;
            Receipt { ok: true, ..Default::default() }
        } else {
            let value = match &tx.action {
                Action::Transfer { amount, .. } | Action::Export { amount } => *amount,
                Action::Call { value, .. } => *value,
                _ => 0,
            };
            if self.feistel.balance(&sender) < max_fee.saturating_add(value) {
                return Err("insufficient balance for value + max fee".into());
            }
            *self.feistel.nonces.entry(sender).or_default() += 1;
            if let Action::Export { amount } = &tx.action {
                self.feistel.debit_pub(&sender, *amount)?;
                let op = OutPoint { txid: id, index: 0 };
                self.atomic.insert((ChainId::Atbash, op), TxOut::native(sender, *amount));
                Receipt { ok: true, ..Default::default() }
            } else {
                let mut scratch = self.feistel.clone();
                match feistel::execute(&mut scratch, tx, sender) {
                    Ok((output, logs, fuel_used, contract)) => {
                        self.feistel = scratch;
                        Receipt { ok: true, fuel_used, output, logs, contract, ..Default::default() }
                    }
                    Err((e, fuel_used)) => {
                        Receipt { ok: false, fuel_used: fuel_used.min(tx.max_fuel), error: Some(e), ..Default::default() }
                    }
                }
            }
        };
        let fee = feistel::fee_for_fuel(receipt.fuel_used);
        self.feistel.debit_pub(&sender, fee)?;
        self.burned += fee;
        let receipt = Receipt { fee, ..receipt };
        if self.receipts.len() >= 10_000 {
            self.receipts.pop_first();
        }
        self.receipts.insert(id, receipt.clone());
        Ok(receipt)
    }

    /// Apply a Playfair (bridge) transaction.
    pub fn apply_playfair(&mut self, tx: &PlayfairTx) -> Result<(), String> {
        self.atomically(|l| l.apply_playfair_inner(tx))
    }

    fn apply_playfair_inner(&mut self, tx: &PlayfairTx) -> Result<(), String> {
        let id = tx.id();
        let ins = self.spend_inputs(ChainId::Playfair, &tx.base, &id, ctx::PLAYFAIR_TX)?;
        let outs = self.create_outputs(ChainId::Playfair, &tx.base, &id)?;
        let get = |m: &BTreeMap<AssetId, u128>, a: &AssetId| m.get(a).copied().unwrap_or(0);
        // Which non-native asset (if any) this kind moves out, and how much native it locks.
        let (moved, native_locked, fee) = match &tx.kind {
            PlayfairKind::Transfer => (None, 0, TX_FEE),
            PlayfairKind::Register { .. } => (None, 0, playfair::REGISTER_FEE),
            PlayfairKind::Update { .. } | PlayfairKind::Receive { .. } => (None, 0, 0),
            PlayfairKind::Send { origin, amount, .. } if *origin == self.network_id => (None, *amount, TX_FEE),
            PlayfairKind::Send { origin, amount, .. } => (Some((playfair::wrapped_asset(origin), *amount)), 0, TX_FEE),
        };
        for asset in ins.keys().chain(outs.keys()).filter(|a| **a != NATIVE) {
            let (i, o) = (get(&ins, asset), get(&outs, asset));
            match moved {
                Some((w, amount)) if w == *asset => {
                    if i != o + amount as u128 {
                        return Err("wrapped inputs must equal outputs + amount sent".into());
                    }
                }
                _ if i != o => return Err("asset amounts not conserved".into()),
                _ => {}
            }
        }
        if let Some((w, amount)) = moved {
            if get(&ins, &w) != get(&outs, &w) + amount as u128 {
                return Err("wrapped inputs must equal outputs + amount sent".into());
            }
        }
        let (n_in, n_out) = (get(&ins, &NATIVE), get(&outs, &NATIVE));
        if n_in < n_out + native_locked as u128 + fee as u128 {
            return Err("native inputs do not cover outputs + amount + fee".into());
        }
        self.burned += (n_in - n_out - native_locked as u128) as u64;

        match &tx.kind {
            PlayfairKind::Transfer => {}
            PlayfairKind::Register { network_id, name, k_height, validators } => {
                if *network_id == self.network_id || self.counterparties.contains_key(network_id) {
                    return Err("network is this network or already registered".into());
                }
                if name.is_empty() || name.len() > 32 {
                    return Err("counterparty name must be 1-32 bytes".into());
                }
                playfair::validate_set(validators)?;
                let sets = BTreeMap::from([(*k_height, validators.clone())]);
                self.counterparties.insert(*network_id, Counterparty { name: name.clone(), sets, tip: *k_height });
            }
            PlayfairKind::Update { network_id, header, cert, validators } => {
                let cp = self.counterparties.get_mut(network_id).ok_or("unknown counterparty")?;
                playfair::check_update(cp, header, cert, validators)?;
                cp.sets.insert(header.height, validators.clone());
                cp.tip = header.height;
                while cp.sets.len() > playfair::KEEP_SETS {
                    cp.sets.pop_first();
                }
            }
            PlayfairKind::Send { dest_network, recipient, origin, amount } => {
                if *amount == 0 || *recipient == Address([0; 32]) {
                    return Err("send needs a positive amount and a recipient".into());
                }
                if !self.counterparties.contains_key(dest_network) {
                    return Err("unknown destination network".into());
                }
                if *origin == self.network_id {
                    *self.escrowed.entry(*dest_network).or_default() += amount;
                } else if origin != dest_network {
                    return Err("wrapped tokens can only return to their origin network".into());
                }
            }
            PlayfairKind::Receive { proof } => {
                let m = &proof.msg;
                let cp = self.counterparties.get(&m.src_network).ok_or("unknown source network")?;
                playfair::check_proof(cp, &self.network_id, proof)?;
                if !self.bridge_received.insert((m.src_network, m.hash())) {
                    return Err("bridge message already received (double-spend)".into());
                }
                let asset = if m.origin == self.network_id {
                    let e = self.escrowed.get_mut(&m.src_network).filter(|e| **e >= m.amount);
                    *e.ok_or("escrow for this network cannot cover the release")? -= m.amount;
                    NATIVE
                } else if m.origin == m.src_network {
                    playfair::wrapped_asset(&m.origin)
                } else {
                    return Err("multi-hop transfers are not supported".into());
                };
                let op = OutPoint { txid: id, index: tx.base.n_outpoints() };
                self.playfair_utxos.insert(op, TxOut { owner: m.recipient, asset, amount: m.amount });
            }
        }
        Ok(())
    }

    /// Apply a Hamming blob transaction.
    pub fn apply_blob(&mut self, tx: &BlobTx) -> Result<(), String> {
        self.atomically(|l| l.apply_blob_inner(tx))
    }

    fn apply_blob_inner(&mut self, tx: &BlobTx) -> Result<(), String> {
        if tx.data.len() > hamming::MAX_BLOB {
            return Err(format!("blob larger than {} bytes", hamming::MAX_BLOB));
        }
        if tx.base.inputs.is_empty() {
            return Err("transaction has no inputs".into());
        }
        if hamming::commit(&tx.data) != tx.commitment {
            return Err("blob commitment does not match the data (bad encoding)".into());
        }
        let id = tx.id();
        let ins = self.spend_inputs(ChainId::Hamming, &tx.base, &id, ctx::HAMMING_TX)?;
        let outs = self.create_outputs(ChainId::Hamming, &tx.base, &id)?;
        if ins.keys().chain(outs.keys()).any(|a| *a != NATIVE) {
            return Err("only the native token lives on the Hamming Chain".into());
        }
        let n_in = ins.get(&NATIVE).copied().unwrap_or(0);
        let n_out = outs.get(&NATIVE).copied().unwrap_or(0);
        if n_in < n_out + hamming::blob_fee(tx.data.len()) as u128 {
            return Err("inputs do not cover outputs + blob fee".into());
        }
        self.burned += (n_in - n_out) as u64;
        Ok(())
    }

    /// Apply a UTXO transaction on the Atbash Chain or a zone.
    pub fn apply_utxo(&mut self, chain: ChainId, tx: &AtbashTx) -> Result<(), String> {
        self.atomically(|l| l.apply_utxo_inner(chain, tx))
    }

    fn apply_utxo_inner(&mut self, chain: ChainId, tx: &AtbashTx) -> Result<(), String> {
        if !matches!(chain, ChainId::Atbash | ChainId::Zone(_)) || !self.knows(chain) {
            return Err(format!("{} does not take UTXO transactions", chain.name()));
        }
        let id = tx.id();
        if tx.base.inputs.is_empty() {
            return Err("transaction has no inputs".into());
        }
        let ins = self.spend_inputs(chain, &tx.base, &id, &chain.tx_context())?;
        let outs = self.create_outputs(chain, &tx.base, &id)?;
        let new_asset = tx.new_asset_id();
        let get = |m: &BTreeMap<AssetId, u128>, a: &AssetId| m.get(a).copied().unwrap_or(0);

        let (n_in, n_out) = (get(&ins, &NATIVE), get(&outs, &NATIVE));
        if n_in < n_out + TX_FEE as u128 {
            return Err("native inputs do not cover outputs + fee".into());
        }
        for asset in ins.keys().chain(outs.keys()).filter(|a| **a != NATIVE) {
            let (i, o) = (get(&ins, asset), get(&outs, asset));
            if Some(*asset) == new_asset {
                if i != 0 || o != tx.create_asset.as_ref().unwrap().supply as u128 {
                    return Err("new asset outputs must equal declared supply".into());
                }
            } else if i != o {
                return Err("asset amounts not conserved".into());
            }
        }
        self.burned += (n_in - n_out) as u64;
        Ok(())
    }

    pub fn apply_kerckhoffs(&mut self, tx: &KerckhoffsTx) -> Result<(), String> {
        self.atomically(|l| l.apply_kerckhoffs_inner(tx))
    }

    /// Run `f` so that it either fully succeeds or leaves the ledger untouched.
    /// (Block application gets the same guarantee once per block instead.)
    fn atomically<T>(&mut self, f: impl FnOnce(&mut Ledger) -> Result<T, String>) -> Result<T, String> {
        let mut next = self.clone();
        let out = f(&mut next)?;
        *self = next;
        Ok(out)
    }

    fn apply_kerckhoffs_inner(&mut self, tx: &KerckhoffsTx) -> Result<(), String> {
        let id = tx.id();
        let ins = self.spend_inputs(ChainId::Kerckhoffs, &tx.base, &id, ctx::KERCKHOFFS_TX)?;
        let outs = self.create_outputs(ChainId::Kerckhoffs, &tx.base, &id)?;
        if ins.keys().chain(outs.keys()).any(|a| *a != NATIVE) {
            return Err("only the native token lives on the Kerckhoffs Chain".into());
        }
        let n_in = ins.get(&NATIVE).copied().unwrap_or(0);
        let n_out = outs.get(&NATIVE).copied().unwrap_or(0);
        let (stake, fee) = match &tx.kind {
            // Reporting misbehaviour is free; an exit is authorized by its signature.
            KerckhoffsKind::Slash { .. } | KerckhoffsKind::Exit { .. } => (0, 0),
            KerckhoffsKind::CreateZone { .. } => (0, ZONE_FEE),
            KerckhoffsKind::ClaimRewards { .. } => (0, 0),
            KerckhoffsKind::AddValidator { stake, .. } | KerckhoffsKind::AddDelegator { stake, .. } => (*stake, TX_FEE),
            KerckhoffsKind::Transfer => (0, TX_FEE),
        };
        if n_in < n_out + stake as u128 + fee as u128 {
            return Err("inputs do not cover outputs + stake + fee".into());
        }
        self.burned += (n_in - n_out - stake as u128) as u64;

        match &tx.kind {
            KerckhoffsKind::Transfer => {}
            KerckhoffsKind::AddValidator { signing_key, withdrawal, stake } => {
                if *stake < MIN_VALIDATOR_STAKE {
                    return Err(format!("validator stake below minimum {MIN_VALIDATOR_STAKE}"));
                }
                if signing_key.alg != ALG_ML_DSA_65 {
                    return Err("validator block-signing keys must be ML-DSA-65 (fast hot key)".into());
                }
                let node_id = signing_key.address();
                if self.validators.contains_key(&node_id) {
                    return Err("validator already registered".into());
                }
                self.validators.insert(
                    node_id,
                    Validator {
                        node_id,
                        signing_key: signing_key.clone(),
                        withdrawal: *withdrawal,
                        stake: *stake,
                        delegated: 0,
                        slashed: false,
                        exit_at: None,
                    },
                );
            }
            KerckhoffsKind::AddDelegator { node, stake, reward } => {
                if *stake < MIN_DELEGATION {
                    return Err(format!("delegation below minimum {MIN_DELEGATION}"));
                }
                let v = self.validators.get_mut(node).ok_or("unknown validator")?;
                if v.slashed || v.exit_at.is_some() {
                    return Err("validator is slashed or exiting".into());
                }
                if v.delegated + stake > v.stake * MAX_DELEGATION_FACTOR {
                    return Err(format!("delegation cap ({MAX_DELEGATION_FACTOR}x own stake) exceeded"));
                }
                v.delegated += stake;
                self.delegations.push(Delegation { node: *node, stake: *stake, reward: *reward });
            }
            KerckhoffsKind::Slash { a, b } => {
                let node = self.check_equivocation(a, b)?;
                let v = self.validators.get_mut(&node).unwrap();
                v.slashed = true;
                self.burned += v.stake;
                // Delegators are not punished: their stake is refunded.
                let mut idx = tx.base.n_outpoints();
                let (refund, keep): (Vec<_>, Vec<_>) =
                    self.delegations.drain(..).partition(|d| d.node == node);
                self.delegations = keep;
                for d in refund {
                    self.kerckhoffs_utxos.insert(OutPoint { txid: id, index: idx }, TxOut::native(d.reward, d.stake));
                    idx += 1;
                }
                v.delegated = 0;
            }
            KerckhoffsKind::Exit { node, authority, sig } => {
                let release = self.tip(ChainId::Kerckhoffs).0 + 1 + UNBONDING_BLOCKS;
                let v = self.validators.get_mut(node).ok_or("unknown validator")?;
                if v.slashed || v.exit_at.is_some() {
                    return Err("validator is already slashed or exiting".into());
                }
                if authority.address() != v.withdrawal {
                    return Err("exit must be signed by the validator's withdrawal key".into());
                }
                if !authority.verify(ctx::EXIT, &id, sig) {
                    return Err("invalid exit signature".into());
                }
                v.exit_at = Some(release);
            }
            KerckhoffsKind::CreateZone { name, members } => {
                if name.is_empty() || name.len() > 32 {
                    return Err("zone name must be 1-32 bytes".into());
                }
                if members.is_empty() || members.len() > MAX_ZONE_MEMBERS {
                    return Err(format!("a zone needs 1-{MAX_ZONE_MEMBERS} members"));
                }
                let distinct: BTreeSet<_> = members.iter().collect();
                if distinct.len() != members.len() {
                    return Err("duplicate zone member".into());
                }
                for m in members {
                    if !self.validators.get(m).is_some_and(|v| v.weight() > 0) {
                        return Err(format!("zone member {m} is not an active primary validator"));
                    }
                }
                let id = self.zones.keys().next_back().map_or(0, |n| n + 1);
                let created_at = self.tip(ChainId::Kerckhoffs).0 + 1;
                let chain = ChainId::Zone(id);
                self.zones.insert(id, Zone { id, name: name.clone(), members: members.clone(), created_at });
                self.tips.insert(chain, (0, Enc::new("pqchain/genesis-block").u64(chain.code()).hash()));
                self.anchors.insert(chain, created_at);
            }
            KerckhoffsKind::ClaimRewards { authority, nonce, sig } => {
                let owner = authority.address();
                if *nonce != self.claim_nonces.get(&owner).copied().unwrap_or(0) {
                    return Err("stale or future claim nonce".into());
                }
                if !authority.verify(ctx::CLAIM, &id, sig) {
                    return Err("invalid claim signature".into());
                }
                let amount = self.rewards.remove(&owner).filter(|a| *a > 0).ok_or("no rewards to claim")?;
                *self.claim_nonces.entry(owner).or_default() += 1;
                let op = OutPoint { txid: id, index: tx.base.n_outpoints() };
                self.kerckhoffs_utxos.insert(op, TxOut::native(owner, amount));
            }
        }
        Ok(())
    }

    /// Issue `BLOCK_REWARD` for a block on `chain`, split across the chain's
    /// validators (as of `anchor`) by weight. Each validator's share is split
    /// between its own stake (paid to its withdrawal address) and its
    /// delegators, minus the validator's commission. Rounding dust is not issued.
    fn distribute_rewards(&mut self, chain: ChainId, anchor: u64) {
        let Some(set) = self.chain_validators(chain, anchor) else { return };
        let active: Vec<&Validator> = set.values().filter(|v| v.weight() > 0).collect();
        let shares = reward_shares(&active.iter().map(|v| v.weight()).collect::<Vec<_>>());
        let mut credits: Vec<(Address, u64)> = Vec::new();
        for (v, share) in active.into_iter().zip(shares) {
            let ds: Vec<&Delegation> = self.delegations.iter().filter(|d| d.node == v.node_id).collect();
            let stakes: Vec<u64> = ds.iter().map(|d| d.stake).collect();
            let (mine, parts) = split_validator_reward(share, v.stake.min(v.weight()), v.weight(), &stakes);
            credits.push((v.withdrawal, mine as u64));
            for (d, amt) in ds.into_iter().zip(parts) {
                credits.push((d.reward, amt as u64));
            }
        }
        for (a, amt) in credits.into_iter().filter(|(_, a)| *a > 0) {
            *self.rewards.entry(a).or_default() += amt;
            self.minted += amt;
        }
    }

    /// Release stake of validators whose unbonding period ended at `height`.
    fn release_unbonded(&mut self, height: u64) {
        let done: Vec<Address> = self
            .validators
            .values()
            .filter(|v| !v.slashed && v.exit_at.is_some_and(|h| h <= height))
            .map(|v| v.node_id)
            .collect();
        for node in done {
            let v = self.validators.remove(&node).unwrap();
            let txid = Enc::new("pqchain/unbond").bytes(&node.0).u64(height).hash();
            self.kerckhoffs_utxos.insert(OutPoint { txid, index: 0 }, TxOut::native(v.withdrawal, v.stake));
            let (refund, keep): (Vec<_>, Vec<_>) = self.delegations.drain(..).partition(|d| d.node == node);
            self.delegations = keep;
            for (i, d) in refund.into_iter().enumerate() {
                self.kerckhoffs_utxos
                    .insert(OutPoint { txid, index: 1 + i as u32 }, TxOut::native(d.reward, d.stake));
            }
        }
    }

    /// Two validly signed, different headers from the same proposer for the
    /// same chain and height = provable equivocation.
    pub fn check_equivocation(&self, a: &SignedHeader, b: &SignedHeader) -> Result<Address, String> {
        let (ha, hb) = (&a.header, &b.header);
        if ha.chain != hb.chain
            || ha.height != hb.height
            || ha.round != hb.round
            || ha.proposer != hb.proposer
        {
            return Err("headers are not for the same slot/proposer".into());
        }
        if ha.hash() == hb.hash() {
            return Err("headers are identical".into());
        }
        let v = self.validators.get(&ha.proposer).ok_or("unknown validator")?;
        if v.slashed {
            return Err("validator already slashed".into());
        }
        for s in [a, b] {
            if !v.signing_key.verify(ctx::BLOCK, &s.header.hash(), &s.sig) {
                return Err("evidence signature invalid".into());
            }
        }
        Ok(ha.proposer)
    }

    /// Fully validate and apply a block. On error, `self` is unchanged.
    pub fn apply_block(&mut self, b: &Block) -> Result<(), String> {
        let mut next = self.clone();
        next.apply_block_inner(b)?;
        *self = next;
        Ok(())
    }

    fn apply_block_inner(&mut self, b: &Block) -> Result<(), String> {
        let h = b.header();
        let (tip_h, tip_hash) = self.tip(h.chain);
        if h.height != tip_h + 1 || h.parent != tip_hash {
            return Err("block does not extend the current tip".into());
        }
        let k_tip = self.tip(ChainId::Kerckhoffs).0;
        match h.chain {
            ChainId::Kerckhoffs if h.anchor != k_tip => {
                return Err("Kerckhoffs block must anchor to its parent height".into())
            }
            ChainId::Atbash | ChainId::Feistel | ChainId::Hamming | ChainId::Playfair | ChainId::Zone(_)
                if h.anchor > k_tip =>
            {
                return Err("anchor is ahead of the local Kerckhoffs tip (retry later)".into())
            }
            ChainId::Atbash | ChainId::Feistel | ChainId::Hamming | ChainId::Playfair | ChainId::Zone(_)
                if h.anchor < self.anchors.get(&h.chain).copied().unwrap_or(0) =>
            {
                return Err("anchor went backwards".into())
            }
            _ => {}
        }
        if !self.knows(h.chain) {
            return Err("unknown chain (retry later)".into());
        }
        let set = self.chain_validators(h.chain, h.anchor).ok_or("no validator set at anchor")?;
        let v = set
            .get(&h.proposer)
            .filter(|v| !v.slashed)
            .ok_or("proposer is not an active validator")?;
        // A validator slashed since the anchor may not propose either.
        if self.validators.get(&h.proposer).is_none_or(|v| v.slashed) {
            return Err("proposer is not an active validator".into());
        }
        if self.scheduled_proposer(h.chain, h.height, &h.parent, h.round, h.anchor)
            != Some(h.proposer)
        {
            return Err("proposer is not scheduled for this slot".into());
        }
        if !v.signing_key.verify(ctx::BLOCK, &h.hash(), &b.signed.sig) {
            return Err("invalid block signature".into());
        }
        if merkle_root(&b.body.tx_ids()) != h.tx_root {
            return Err("tx root mismatch".into());
        }
        if header_msg_root(&self.network_id, h.chain, &b.body) != h.msg_root {
            return Err("relay message root mismatch".into());
        }
        match (&b.body, h.chain) {
            (Body::Atbash(txs), ChainId::Atbash | ChainId::Zone(_)) => {
                for (i, t) in txs.iter().enumerate() {
                    self.apply_utxo_inner(h.chain, t).map_err(|e| format!("tx {i}: {e}"))?;
                }
            }
            (Body::Kerckhoffs(txs), ChainId::Kerckhoffs) => {
                for (i, t) in txs.iter().enumerate() {
                    self.apply_kerckhoffs_inner(t).map_err(|e| format!("tx {i}: {e}"))?;
                }
            }
            (Body::Feistel(txs), ChainId::Feistel) => {
                for (i, t) in txs.iter().enumerate() {
                    self.apply_feistel_inner(t).map_err(|e| format!("tx {i}: {e}"))?;
                }
            }
            (Body::Hamming(txs), ChainId::Hamming) => {
                if txs.iter().map(|t| t.data.len()).sum::<usize>() > hamming::MAX_BLOCK_DATA {
                    return Err("block carries too much blob data".into());
                }
                for (i, t) in txs.iter().enumerate() {
                    self.apply_blob_inner(t).map_err(|e| format!("tx {i}: {e}"))?;
                }
            }
            (Body::Playfair(txs), ChainId::Playfair) => {
                for (i, t) in txs.iter().enumerate() {
                    self.apply_playfair_inner(t).map_err(|e| format!("tx {i}: {e}"))?;
                }
            }
            _ => return Err("body does not match chain".into()),
        }
        self.distribute_rewards(h.chain, h.anchor);
        self.tips.insert(h.chain, (h.height, h.hash()));
        self.anchors.insert(h.chain, h.anchor);
        if h.chain == ChainId::Kerckhoffs {
            self.release_unbonded(h.height);
            if set_hash(&self.validators) != h.set_root {
                return Err("validator set root mismatch".into());
            }
            self.validator_history.insert(h.height, Arc::new(self.validators.clone()));
        } else if h.set_root != [0; 32] {
            return Err("only Kerckhoffs blocks carry a validator set root".into());
        }
        Ok(())
    }

    /// Every native token currently held anywhere in the state: UTXOs on all
    /// chains, atomic memory, Feistel accounts and contracts, bonded stake,
    /// delegations and unclaimed rewards. Relay messages in flight (exported
    /// from or to a zone but not yet claimed) are not counted.
    ///
    /// Invariant: `native_held() + burned == genesis supply + minted`.
    pub fn native_held(&self) -> u128 {
        let native = |m: &BTreeMap<OutPoint, TxOut>| -> u128 {
            m.values().filter(|o| o.asset == NATIVE).map(|o| o.amount as u128).sum()
        };
        native(&self.atbash_utxos)
            + native(&self.kerckhoffs_utxos)
            + native(&self.hamming_utxos)
            + native(&self.playfair_utxos)
            + self.escrowed.values().map(|e| *e as u128).sum::<u128>()
            + self.zone_utxos.values().map(native).sum::<u128>()
            + self.atomic.values().filter(|o| o.asset == NATIVE).map(|o| o.amount as u128).sum::<u128>()
            + self.feistel.balances.values().map(|b| *b as u128).sum::<u128>()
            + self.validators.values().filter(|v| !v.slashed).map(|v| v.stake as u128).sum::<u128>()
            + self.delegations.iter().map(|d| d.stake as u128).sum::<u128>()
            + self.rewards.values().map(|r| *r as u128).sum::<u128>()
    }

    /// Commitment to the entire state; replicas must agree on this.
    pub fn state_root(&self) -> Hash {
        let mut e = Enc::new("pqchain/state");
        e.bytes(&self.network_id);
        for (n, cp) in &self.counterparties {
            e.bytes(n).bytes(cp.name.as_bytes()).u64(cp.tip).u64(cp.sets.len() as u64);
            for (h, s) in &cp.sets {
                e.u64(*h).bytes(&playfair::bridge_set_hash(s));
            }
        }
        for (n, amt) in &self.escrowed {
            e.bytes(n).u64(*amt);
        }
        e.u64(self.bridge_received.len() as u64);
        for (n, m) in &self.bridge_received {
            e.bytes(n).bytes(m);
        }
        for (c, m) in [(0u8, &self.atbash_utxos), (1, &self.kerckhoffs_utxos), (3, &self.hamming_utxos), (4, &self.playfair_utxos)] {
            e.u8(c).u64(m.len() as u64);
            for (p, o) in m {
                e.bytes(&p.txid).u64(p.index as u64);
                o.encode(&mut e);
            }
        }
        e.u64(self.atomic.len() as u64);
        for ((c, p), o) in &self.atomic {
            e.u64(c.code()).bytes(&p.txid).u64(p.index as u64);
            o.encode(&mut e);
        }
        for z in self.zones.values() {
            e.u64(z.id as u64).bytes(z.name.as_bytes()).u64(z.created_at);
            for m in &z.members {
                e.bytes(&m.0);
            }
        }
        for (n, m) in self.zone_utxos.iter().filter(|(_, m)| !m.is_empty()) {
            e.u64(*n as u64).u64(m.len() as u64);
            for (p, o) in m {
                e.bytes(&p.txid).u64(p.index as u64);
                o.encode(&mut e);
            }
        }
        e.u64(self.relay_consumed.len() as u64);
        for (c, p) in &self.relay_consumed {
            e.u64(c.code()).bytes(&p.txid).u64(p.index as u64);
        }
        for v in self.validators.values() {
            e.bytes(&v.node_id.0).u64(v.stake).u64(v.delegated).u8(v.slashed as u8).u64(v.exit_at.unwrap_or(0));
        }
        for (c, (h, hash)) in &self.tips {
            e.u64(c.code()).u64(*h).bytes(hash).u64(self.anchors.get(c).copied().unwrap_or(0));
        }
        e.u64(self.burned).u64(self.minted);
        self.feistel.encode(&mut e);
        for (a, r) in &self.rewards {
            e.bytes(&a.0).u64(*r);
        }
        for (a, n) in &self.claim_nonces {
            e.bytes(&a.0).u64(*n);
        }
        e.hash()
    }
}

/// Build and sign a round-0 block as the given proposer.
pub fn propose(ledger: &Ledger, key: &Keypair, body: Body, timestamp: u64) -> Block {
    propose_round(ledger, key, body, timestamp, 0)
}

/// Build and sign a block for a specific proposal round.
pub fn propose_round(ledger: &Ledger, key: &Keypair, body: Body, timestamp: u64, round: u32) -> Block {
    let chain = match body {
        Body::Atbash(_) => ChainId::Atbash,
        Body::Kerckhoffs(_) => ChainId::Kerckhoffs,
        Body::Feistel(_) => ChainId::Feistel,
        Body::Hamming(_) => ChainId::Hamming,
        Body::Playfair(_) => ChainId::Playfair,
    };
    propose_on(ledger, key, chain, body, timestamp, round)
}

/// Hash of the active validators (weight > 0): (node id, signing key, weight)
/// in node-id order. The same function is used by bridge light clients.
pub fn set_hash_entries<'a>(entries: impl Iterator<Item = (Address, &'a PublicKey, u64)>) -> Hash {
    let mut e = Enc::new("pqchain/validator-set");
    for (a, k, w) in entries {
        e.bytes(&a.0).u8(k.alg).bytes(&k.bytes).u64(w);
    }
    e.hash()
}

pub fn set_hash(set: &ValidatorSet) -> Hash {
    set_hash_entries(set.values().filter(|v| v.weight() > 0).map(|v| (v.node_id, &v.signing_key, v.weight())))
}

/// Validator-set root a Kerckhoffs block at `height` with `body` will produce.
fn next_set_root(ledger: &Ledger, body: &Body, height: u64) -> Hash {
    let mut l = ledger.clone();
    if let Body::Kerckhoffs(txs) = body {
        for t in txs {
            let _ = l.apply_kerckhoffs_inner(t);
        }
    }
    l.release_unbonded(height);
    set_hash(&l.validators)
}

/// Message root committed in a block header (relay messages; bridge
/// messages on the Playfair Chain).
pub fn header_msg_root(network_id: &Hash, chain: ChainId, body: &Body) -> Hash {
    match body {
        Body::Playfair(_) => merkle_root(&bridge_messages(network_id, body).iter().map(BridgeMsg::hash).collect::<Vec<_>>()),
        _ => msg_root(&body_messages(chain, body)),
    }
}

/// Bridge messages emitted by a Playfair block, in order.
pub fn bridge_messages(network_id: &Hash, body: &Body) -> Vec<BridgeMsg> {
    let Body::Playfair(txs) = body else { return Vec::new() };
    txs.iter()
        .filter_map(|t| match &t.kind {
            PlayfairKind::Send { dest_network, recipient, origin, amount } => Some(BridgeMsg {
                src_network: *network_id,
                dest_network: *dest_network,
                txid: t.id(),
                recipient: *recipient,
                origin: *origin,
                amount: *amount,
            }),
            _ => None,
        })
        .collect()
}

/// Build and sign a block for any chain (zones use an Atbash-style body).
pub fn propose_on(ledger: &Ledger, key: &Keypair, chain: ChainId, body: Body, timestamp: u64, round: u32) -> Block {
    let (h, parent) = ledger.tip(chain);
    let header = BlockHeader {
        chain,
        height: h + 1,
        parent,
        tx_root: merkle_root(&body.tx_ids()),
        proposer: key.address(),
        timestamp,
        round,
        anchor: ledger.current_anchor(),
        msg_root: header_msg_root(&ledger.network_id, chain, &body),
        set_root: if chain == ChainId::Kerckhoffs { next_set_root(ledger, &body, h + 1) } else { [0; 32] },
    };
    let sig = key.sign(ctx::BLOCK, &header.hash());
    Block { signed: SignedHeader { header, sig }, body }
}

#[cfg(test)]
mod reward_math_tests {
    use super::*;

    /// Complements the bounded Kani proofs: random values over the full u64 range.
    #[test]
    fn reward_math_never_pays_more_than_issued_full_range() {
        for i in 0..200_000u64 {
            let r = |k: u64| -> u64 {
                let h = crate::crypto::Enc::new("t").u64(i).u64(k).hash();
                let v = u64::from_le_bytes(h[..8].try_into().unwrap());
                v >> (h[8] % 64) // mix of magnitudes, including huge ones
            };
            let w = [r(0), r(1), r(2)];
            let shares = reward_shares(&w);
            assert!(shares.iter().sum::<u128>() <= BLOCK_REWARD as u128);
            let (stake, delegated) = (r(3), r(4));
            let weight = stake.saturating_add(delegated);
            let (mine, parts) = split_validator_reward(shares[0], stake.min(weight), weight, &[r(5), r(6)]);
            assert!(mine + parts.iter().sum::<u128>() <= shares[0]);
        }
    }
}
