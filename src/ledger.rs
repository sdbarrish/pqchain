//! Ledger for the primary network: Atbash Chain (UTXO assets) and Kerckhoffs Chain
//! (platform: staking, validators, slashing), linked by
//! "atomic memory" for cross-chain export/import.

use crate::crypto::*;
use std::collections::BTreeMap;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChainId {
    Kerckhoffs,
    Atbash,
}

impl ChainId {
    pub fn tag(self) -> u8 {
        match self {
            ChainId::Kerckhoffs => 0,
            ChainId::Atbash => 1,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            ChainId::Kerckhoffs => "Kerckhoffs Chain",
            ChainId::Atbash => "Atbash Chain",
        }
    }
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

/// Where an input comes from: this chain's UTXO set, or atomic memory
/// (funds exported to this chain by another chain).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Local,
    Atomic,
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
    /// Outputs sent to another chain via atomic memory.
    pub export_to: Option<ChainId>,
    pub exported: Vec<TxOut>,
}

impl Transfer {
    /// Signatures are excluded from the txid, so txids are not malleable.
    fn encode(&self, e: &mut Enc) {
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
        e.u8(self.export_to.map_or(255, |c| c.tag()));
        e.u64(self.exported.len() as u64);
        for o in &self.exported {
            o.encode(e);
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

    pub fn sign(mut self, keys: &[&Keypair]) -> Self {
        let id = self.id();
        self.base.sign_all(ctx::ATBASH_TX, &id, keys);
        self
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
        };
        e.hash()
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
}

impl BlockHeader {
    pub fn hash(&self) -> Hash {
        Enc::new("pqchain/block-header")
            .u8(self.chain.tag())
            .u64(self.height)
            .bytes(&self.parent)
            .bytes(&self.tx_root)
            .bytes(&self.proposer.0)
            .u64(self.timestamp)
            .u64(self.round as u64)
            .u64(self.anchor)
            .hash()
    }
}

#[derive(Clone, Debug)]
pub enum Body {
    Atbash(Vec<AtbashTx>),
    Kerckhoffs(Vec<KerckhoffsTx>),
}

impl Body {
    pub fn tx_ids(&self) -> Vec<Hash> {
        match self {
            Body::Atbash(t) => t.iter().map(AtbashTx::id).collect(),
            Body::Kerckhoffs(t) => t.iter().map(KerckhoffsTx::id).collect(),
        }
    }
    pub fn len(&self) -> usize {
        match self {
            Body::Atbash(t) => t.len(),
            Body::Kerckhoffs(t) => t.len(),
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
            self.stake + self.delegated
        }
    }
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
        for c in [ChainId::Kerckhoffs, ChainId::Atbash] {
            l.tips.insert(c, (0, Enc::new("pqchain/genesis-block").u8(c.tag()).hash()));
            l.anchors.insert(c, 0);
        }
        l.validator_history.insert(0, Arc::new(l.validators.clone()));
        l
    }

    pub fn tip(&self, chain: ChainId) -> (u64, Hash) {
        self.tips[&chain]
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
        }
    }
    fn utxos_mut(&mut self, chain: ChainId) -> &mut BTreeMap<OutPoint, TxOut> {
        match chain {
            ChainId::Kerckhoffs => &mut self.kerckhoffs_utxos,
            ChainId::Atbash => &mut self.atbash_utxos,
        }
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
        let set = self.validators_at(anchor)?;
        let total: u64 = set.values().map(Validator::weight).sum();
        if total == 0 {
            return None;
        }
        let seed = Enc::new("pqchain/leader")
            .u8(chain.tag())
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
        for inp in &t.inputs {
            let out = match inp.source {
                Source::Local => self.utxos_mut(chain).remove(&inp.prev),
                Source::Atomic => self.atomic.remove(&(chain, inp.prev)),
            }
            .ok_or("input missing or already spent (double-spend)")?;
            if inp.pubkey.address() != out.owner {
                return Err("public key does not match the output's owner".into());
            }
            if !inp.pubkey.verify(context, txid, &inp.sig) {
                return Err("invalid ML-DSA signature".into());
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
            (Some(dest), false) if dest != chain => {}
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
                self.atomic.insert((t.export_to.unwrap(), op), o.clone());
            }
            *totals.entry(o.asset).or_insert(0u128) += o.amount as u128;
        }
        Ok(totals)
    }

    pub fn apply_atbash(&mut self, tx: &AtbashTx) -> Result<(), String> {
        let id = tx.id();
        if tx.base.inputs.is_empty() {
            return Err("transaction has no inputs".into());
        }
        let ins = self.spend_inputs(ChainId::Atbash, &tx.base, &id, ctx::ATBASH_TX)?;
        let outs = self.create_outputs(ChainId::Atbash, &tx.base, &id)?;
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
        }
        Ok(())
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
            ChainId::Atbash if h.anchor > k_tip => {
                return Err("anchor is ahead of the local Kerckhoffs tip (retry later)".into())
            }
            ChainId::Atbash if h.anchor < self.anchors[&ChainId::Atbash] => {
                return Err("anchor went backwards".into())
            }
            _ => {}
        }
        let set = self.validators_at(h.anchor).ok_or("no validator set at anchor")?;
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
        match (&b.body, h.chain) {
            (Body::Atbash(txs), ChainId::Atbash) => {
                for (i, t) in txs.iter().enumerate() {
                    self.apply_atbash(t).map_err(|e| format!("tx {i}: {e}"))?;
                }
            }
            (Body::Kerckhoffs(txs), ChainId::Kerckhoffs) => {
                for (i, t) in txs.iter().enumerate() {
                    self.apply_kerckhoffs(t).map_err(|e| format!("tx {i}: {e}"))?;
                }
            }
            _ => return Err("body does not match chain".into()),
        }
        self.tips.insert(h.chain, (h.height, h.hash()));
        self.anchors.insert(h.chain, h.anchor);
        if h.chain == ChainId::Kerckhoffs {
            self.release_unbonded(h.height);
            self.validator_history.insert(h.height, Arc::new(self.validators.clone()));
        }
        Ok(())
    }

    /// Commitment to the entire state; replicas must agree on this.
    pub fn state_root(&self) -> Hash {
        let mut e = Enc::new("pqchain/state");
        for (c, m) in [(0u8, &self.atbash_utxos), (1, &self.kerckhoffs_utxos)] {
            e.u8(c).u64(m.len() as u64);
            for (p, o) in m {
                e.bytes(&p.txid).u64(p.index as u64);
                o.encode(&mut e);
            }
        }
        e.u64(self.atomic.len() as u64);
        for ((c, p), o) in &self.atomic {
            e.u8(c.tag()).bytes(&p.txid).u64(p.index as u64);
            o.encode(&mut e);
        }
        for v in self.validators.values() {
            e.bytes(&v.node_id.0).u64(v.stake).u64(v.delegated).u8(v.slashed as u8).u64(v.exit_at.unwrap_or(0));
        }
        for (c, (h, hash)) in &self.tips {
            e.u8(c.tag()).u64(*h).bytes(hash).u64(self.anchors[c]);
        }
        e.u64(self.burned);
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
    };
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
    };
    let sig = key.sign(ctx::BLOCK, &header.hash());
    Block { signed: SignedHeader { header, sig }, body }
}
