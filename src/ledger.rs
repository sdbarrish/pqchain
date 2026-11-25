//! Ledger for the primary network: Prism Chain (UTXO assets) and Keystone Chain
//! (platform: staking, validators, slashing), linked by
//! "atomic memory" for cross-chain export/import.

use crate::crypto::*;
use std::collections::BTreeMap;

pub type AssetId = Hash;
pub const NATIVE: AssetId = [0u8; 32];

pub const TX_FEE: u64 = 1;
pub const MIN_VALIDATOR_STAKE: u64 = 2_000;
pub const MIN_DELEGATION: u64 = 25;
pub const MAX_DELEGATION_FACTOR: u64 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChainId {
    Keystone,
    Prism,
}

impl ChainId {
    pub fn tag(self) -> u8 {
        match self {
            ChainId::Keystone => 0,
            ChainId::Prism => 1,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            ChainId::Keystone => "Keystone Chain",
            ChainId::Prism => "Prism Chain",
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

/// Prism Chain transaction: transfers, exports, and new-asset creation.
#[derive(Clone, Debug)]
pub struct PrismTx {
    pub base: Transfer,
    pub create_asset: Option<AssetDef>,
}

impl PrismTx {
    pub fn id(&self) -> Hash {
        let mut e = Enc::new("pqchain/prism-tx");
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
        self.base.sign_all(ctx::PRISM_TX, &id, keys);
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
pub enum KeystoneKind {
    /// Plain transfer / import from atomic memory.
    Transfer,
    /// Become a Tier-1 validator. `signing_key` is the hot ML-DSA block key;
    /// `withdrawal` should be a cold (offline) address.
    AddValidator { signing_key: PublicKey, withdrawal: Address, stake: u64 },
    /// Tier-3 delegator: lend stake to a validator.
    AddDelegator { node: Address, stake: u64, reward: Address },
    /// Proof that a validator signed two different blocks at the same height.
    Slash { a: Box<SignedHeader>, b: Box<SignedHeader> },
}

#[derive(Clone, Debug)]
pub struct KeystoneTx {
    pub base: Transfer,
    pub kind: KeystoneKind,
}

impl KeystoneTx {
    pub fn id(&self) -> Hash {
        let mut e = Enc::new("pqchain/keystone-tx");
        self.base.encode(&mut e);
        match &self.kind {
            KeystoneKind::Transfer => e.u8(0),
            KeystoneKind::AddValidator { signing_key, withdrawal, stake } => e
                .u8(1)
                .u8(signing_key.alg)
                .bytes(&signing_key.bytes)
                .bytes(&withdrawal.0)
                .u64(*stake),
            KeystoneKind::AddDelegator { node, stake, reward } => {
                e.u8(2).bytes(&node.0).u64(*stake).bytes(&reward.0)
            }
            KeystoneKind::Slash { a, b } => e
                .u8(3)
                .bytes(&a.header.hash())
                .bytes(&a.sig.bytes)
                .bytes(&b.header.hash())
                .bytes(&b.sig.bytes),
        };
        e.hash()
    }

    pub fn sign(mut self, keys: &[&Keypair]) -> Self {
        let id = self.id();
        self.base.sign_all(ctx::KEYSTONE_TX, &id, keys);
        self
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
            .hash()
    }
}

#[derive(Clone, Debug)]
pub enum Body {
    Prism(Vec<PrismTx>),
    Keystone(Vec<KeystoneTx>),
}

impl Body {
    pub fn tx_ids(&self) -> Vec<Hash> {
        match self {
            Body::Prism(t) => t.iter().map(PrismTx::id).collect(),
            Body::Keystone(t) => t.iter().map(KeystoneTx::id).collect(),
        }
    }
    pub fn len(&self) -> usize {
        match self {
            Body::Prism(t) => t.len(),
            Body::Keystone(t) => t.len(),
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
}

impl Validator {
    pub fn weight(&self) -> u64 {
        if self.slashed {
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
    pub prism_utxos: BTreeMap<OutPoint, TxOut>,
    pub keystone_utxos: BTreeMap<OutPoint, TxOut>,
    /// (destination chain, outpoint) -> output waiting to be imported.
    pub atomic: BTreeMap<(ChainId, OutPoint), TxOut>,
    pub validators: BTreeMap<Address, Validator>,
    pub delegations: Vec<Delegation>,
    pub burned: u64,
    pub tips: BTreeMap<ChainId, (u64, Hash)>,
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
            l.prism_utxos.insert(OutPoint { txid: gid, index: i as u32 }, TxOut::native(*owner, *amount));
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
                },
            );
        }
        for c in [ChainId::Keystone, ChainId::Prism] {
            l.tips.insert(c, (0, Enc::new("pqchain/genesis-block").u8(c.tag()).hash()));
        }
        l
    }

    pub fn tip(&self, chain: ChainId) -> (u64, Hash) {
        self.tips[&chain]
    }

    pub fn total_weight(&self) -> u64 {
        self.validators.values().map(Validator::weight).sum()
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
            ChainId::Keystone => &self.keystone_utxos,
            ChainId::Prism => &self.prism_utxos,
        }
    }
    fn utxos_mut(&mut self, chain: ChainId) -> &mut BTreeMap<OutPoint, TxOut> {
        match chain {
            ChainId::Keystone => &mut self.keystone_utxos,
            ChainId::Prism => &mut self.prism_utxos,
        }
    }

    /// Deterministic, stake-weighted leader schedule.
    pub fn scheduled_proposer(&self, chain: ChainId, height: u64, parent: &Hash) -> Option<Address> {
        let total = self.total_weight();
        if total == 0 {
            return None;
        }
        let seed = Enc::new("pqchain/leader").u8(chain.tag()).u64(height).bytes(parent).hash();
        let mut r = u64::from_le_bytes(seed[..8].try_into().unwrap()) % total;
        for v in self.validators.values().filter(|v| !v.slashed) {
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

    pub fn apply_prism(&mut self, tx: &PrismTx) -> Result<(), String> {
        let id = tx.id();
        if tx.base.inputs.is_empty() {
            return Err("transaction has no inputs".into());
        }
        let ins = self.spend_inputs(ChainId::Prism, &tx.base, &id, ctx::PRISM_TX)?;
        let outs = self.create_outputs(ChainId::Prism, &tx.base, &id)?;
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

    pub fn apply_keystone(&mut self, tx: &KeystoneTx) -> Result<(), String> {
        let id = tx.id();
        let ins = self.spend_inputs(ChainId::Keystone, &tx.base, &id, ctx::KEYSTONE_TX)?;
        let outs = self.create_outputs(ChainId::Keystone, &tx.base, &id)?;
        if ins.keys().chain(outs.keys()).any(|a| *a != NATIVE) {
            return Err("only the native token lives on the Keystone Chain".into());
        }
        let n_in = ins.get(&NATIVE).copied().unwrap_or(0);
        let n_out = outs.get(&NATIVE).copied().unwrap_or(0);
        let (stake, fee) = match &tx.kind {
            KeystoneKind::Slash { .. } => (0, 0), // reporting misbehaviour is free
            KeystoneKind::AddValidator { stake, .. } | KeystoneKind::AddDelegator { stake, .. } => (*stake, TX_FEE),
            KeystoneKind::Transfer => (0, TX_FEE),
        };
        if n_in < n_out + stake as u128 + fee as u128 {
            return Err("inputs do not cover outputs + stake + fee".into());
        }
        self.burned += (n_in - n_out - stake as u128) as u64;

        match &tx.kind {
            KeystoneKind::Transfer => {}
            KeystoneKind::AddValidator { signing_key, withdrawal, stake } => {
                if *stake < MIN_VALIDATOR_STAKE {
                    return Err(format!("validator stake below minimum {MIN_VALIDATOR_STAKE}"));
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
                    },
                );
            }
            KeystoneKind::AddDelegator { node, stake, reward } => {
                if *stake < MIN_DELEGATION {
                    return Err(format!("delegation below minimum {MIN_DELEGATION}"));
                }
                let v = self.validators.get_mut(node).ok_or("unknown validator")?;
                if v.slashed {
                    return Err("validator is slashed".into());
                }
                if v.delegated + stake > v.stake * MAX_DELEGATION_FACTOR {
                    return Err(format!("delegation cap ({MAX_DELEGATION_FACTOR}x own stake) exceeded"));
                }
                v.delegated += stake;
                self.delegations.push(Delegation { node: *node, stake: *stake, reward: *reward });
            }
            KeystoneKind::Slash { a, b } => {
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
                    self.keystone_utxos.insert(OutPoint { txid: id, index: idx }, TxOut::native(d.reward, d.stake));
                    idx += 1;
                }
                v.delegated = 0;
            }
        }
        Ok(())
    }

    /// Two validly signed, different headers from the same proposer for the
    /// same chain and height = provable equivocation.
    pub fn check_equivocation(&self, a: &SignedHeader, b: &SignedHeader) -> Result<Address, String> {
        let (ha, hb) = (&a.header, &b.header);
        if ha.chain != hb.chain || ha.height != hb.height || ha.proposer != hb.proposer {
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
        let v = self
            .validators
            .get(&h.proposer)
            .filter(|v| !v.slashed)
            .ok_or("proposer is not an active validator")?;
        if self.scheduled_proposer(h.chain, h.height, &h.parent) != Some(h.proposer) {
            return Err("proposer is not scheduled for this slot".into());
        }
        if !v.signing_key.verify(ctx::BLOCK, &h.hash(), &b.signed.sig) {
            return Err("invalid block signature".into());
        }
        if merkle_root(&b.body.tx_ids()) != h.tx_root {
            return Err("tx root mismatch".into());
        }
        match (&b.body, h.chain) {
            (Body::Prism(txs), ChainId::Prism) => {
                for (i, t) in txs.iter().enumerate() {
                    self.apply_prism(t).map_err(|e| format!("tx {i}: {e}"))?;
                }
            }
            (Body::Keystone(txs), ChainId::Keystone) => {
                for (i, t) in txs.iter().enumerate() {
                    self.apply_keystone(t).map_err(|e| format!("tx {i}: {e}"))?;
                }
            }
            _ => return Err("body does not match chain".into()),
        }
        self.tips.insert(h.chain, (h.height, h.hash()));
        Ok(())
    }

    /// Commitment to the entire state; replicas must agree on this.
    pub fn state_root(&self) -> Hash {
        let mut e = Enc::new("pqchain/state");
        for (c, m) in [(0u8, &self.prism_utxos), (1, &self.keystone_utxos)] {
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
            e.bytes(&v.node_id.0).u64(v.stake).u64(v.delegated).u8(v.slashed as u8);
        }
        for (c, (h, hash)) in &self.tips {
            e.u8(c.tag()).u64(*h).bytes(hash);
        }
        e.u64(self.burned);
        e.hash()
    }
}

/// Build and sign a block as the given proposer.
pub fn propose(ledger: &Ledger, key: &Keypair, body: Body, timestamp: u64) -> Block {
    let chain = match body {
        Body::Prism(_) => ChainId::Prism,
        Body::Keystone(_) => ChainId::Keystone,
    };
    let (h, parent) = ledger.tip(chain);
    let header = BlockHeader {
        chain,
        height: h + 1,
        parent,
        tx_root: merkle_root(&body.tx_ids()),
        proposer: key.address(),
        timestamp,
    };
    let sig = key.sign(ctx::BLOCK, &header.hash());
    Block { signed: SignedHeader { header, sig }, body }
}
