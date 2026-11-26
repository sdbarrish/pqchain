//! Playfair Chain: trust-minimized bridges between PQ-Chain networks.
//!
//! Each network's Playfair Chain runs an on-chain light client of each
//! registered counterparty network:
//!
//! * **Tracking.** `Update` submits the counterparty's next Kerckhoffs block
//!   header with its finality certificate. It is accepted only if signed by
//!   > 2/3 of the validator set already tracked, and the new validator list
//!   must hash to the header's `set_root`. So the tracked set can only change
//!   the way the counterparty's own validators approved.
//! * **Sending.** `Send` escrows native tokens (or burns wrapped tokens that
//!   are going home) and emits a bridge message committed in the block
//!   header's `msg_root`.
//! * **Receiving.** `Receive` proves a message with the source Playfair
//!   block header, its finality certificate (checked against the tracked
//!   validator set at the header's anchor) and a Merkle path. It mints
//!   wrapped tokens, or releases escrow when tokens return home. Each message
//!   can be received once.
//!
//! Escrow is accounted per counterparty, so a compromised counterparty can
//! at most release what was sent to it. Hops through a third network are not
//! supported: wrapped tokens can only go back to their origin.
//!
//! All checks are hash- and ML-DSA-based: post-quantum end to end.

use crate::consensus::{FinalityCert, LightClient};
use crate::crypto::*;
use crate::ledger::{set_hash_entries, BlockHeader, ChainId, Validator, ValidatorSet};
use std::collections::BTreeMap;

pub const REGISTER_FEE: u64 = 100;
pub const MAX_BRIDGE_VALIDATORS: usize = 128;
/// Tracked validator sets kept per counterparty (older ones are pruned).
pub const KEEP_SETS: usize = 256;

/// A counterparty validator as tracked by the bridge: signing key and weight.
pub type BridgeValidators = Vec<(PublicKey, u64)>;

#[derive(Clone, Debug)]
pub struct Counterparty {
    pub name: String,
    /// Tracked validator sets by the counterparty's Kerckhoffs height.
    pub sets: BTreeMap<u64, BridgeValidators>,
    /// Latest tracked Kerckhoffs height.
    pub tip: u64,
}

impl Counterparty {
    pub fn set_at(&self, anchor: u64) -> Option<&BridgeValidators> {
        self.sets.range(..=anchor).next_back().map(|(_, s)| s)
    }
}

/// Canonical form: weights > 0, sorted by node id, no duplicates.
pub fn validate_set(v: &BridgeValidators) -> Result<(), String> {
    if v.is_empty() || v.len() > MAX_BRIDGE_VALIDATORS {
        return Err(format!("a validator set needs 1-{MAX_BRIDGE_VALIDATORS} entries"));
    }
    let ids: Vec<Address> = v.iter().map(|(k, _)| k.address()).collect();
    if ids.windows(2).any(|w| w[0] >= w[1]) || v.iter().any(|(k, w)| *w == 0 || k.alg != ALG_ML_DSA_65) {
        return Err("validator set must be sorted by node id, unique, ML-DSA keys, positive weights".into());
    }
    Ok(())
}

pub fn bridge_set_hash(v: &BridgeValidators) -> Hash {
    set_hash_entries(v.iter().map(|(k, w)| (k.address(), k, *w)))
}

/// Canonical bridge form of a ledger validator set (active validators only).
pub fn from_ledger_set(set: &ValidatorSet) -> BridgeValidators {
    set.values().filter(|v| v.weight() > 0).map(|v| (v.signing_key.clone(), v.weight())).collect()
}

fn to_validator_set(v: &BridgeValidators) -> ValidatorSet {
    v.iter()
        .map(|(k, w)| {
            let id = k.address();
            let val = Validator {
                node_id: id,
                signing_key: k.clone(),
                withdrawal: id,
                stake: *w,
                delegated: 0,
                slashed: false,
                exit_at: None,
            };
            (id, val)
        })
        .collect()
}

/// Asset id of tokens that originate on `origin_network`, as wrapped elsewhere.
pub fn wrapped_asset(origin_network: &Hash) -> Hash {
    Enc::new("pqchain/playfair/wrapped").bytes(origin_network).hash()
}

/// A cross-network transfer emitted by a `Send`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeMsg {
    pub src_network: Hash,
    pub dest_network: Hash,
    pub txid: Hash,
    pub recipient: Address,
    /// Network the tokens originally come from.
    pub origin: Hash,
    pub amount: u64,
}

impl BridgeMsg {
    pub fn hash(&self) -> Hash {
        Enc::new("pqchain/playfair/msg")
            .bytes(&self.src_network)
            .bytes(&self.dest_network)
            .bytes(&self.txid)
            .bytes(&self.recipient.0)
            .bytes(&self.origin)
            .u64(self.amount)
            .hash()
    }
}

/// Proof that a source-network Playfair block emitted a message.
#[derive(Clone, Debug)]
pub struct BridgeProof {
    pub msg: BridgeMsg,
    pub header: BlockHeader,
    pub cert: FinalityCert,
    pub leaf: u32,
    pub branch: Vec<Hash>,
}

#[derive(Clone, Debug)]
pub enum PlayfairKind {
    /// Plain transfer / import (funding from the Atbash Chain).
    Transfer,
    /// Start tracking a counterparty at a Kerckhoffs height with its set there.
    Register { network_id: Hash, name: String, k_height: u64, validators: BridgeValidators },
    /// Advance the tracked counterparty by one certified Kerckhoffs block.
    Update { network_id: Hash, header: BlockHeader, cert: FinalityCert, validators: BridgeValidators },
    /// Send tokens to `recipient` on `dest_network`.
    Send { dest_network: Hash, recipient: Address, origin: Hash, amount: u64 },
    /// Deliver a proven message from a counterparty.
    Receive { proof: Box<BridgeProof> },
}

impl PlayfairKind {
    pub(crate) fn encode(&self, e: &mut Enc) {
        match self {
            PlayfairKind::Transfer => {
                e.u8(0);
            }
            PlayfairKind::Register { network_id, name, k_height, validators } => {
                e.u8(1).bytes(network_id).bytes(name.as_bytes()).u64(*k_height).bytes(&bridge_set_hash(validators));
            }
            PlayfairKind::Update { network_id, header, validators, .. } => {
                e.u8(2).bytes(network_id).bytes(&header.hash()).bytes(&bridge_set_hash(validators));
            }
            PlayfairKind::Send { dest_network, recipient, origin, amount } => {
                e.u8(3).bytes(dest_network).bytes(&recipient.0).bytes(origin).u64(*amount);
            }
            PlayfairKind::Receive { proof } => {
                e.u8(4).bytes(&proof.msg.hash());
            }
        }
    }
}

/// Check a counterparty's Kerckhoffs header + certificate against the set we
/// already trust, and the new set against the header's `set_root`.
pub fn check_update(cp: &Counterparty, header: &BlockHeader, cert: &FinalityCert, next: &BridgeValidators) -> Result<(), String> {
    if header.chain != ChainId::Kerckhoffs || header.height != cp.tip + 1 {
        return Err(format!("expected the counterparty's Kerckhoffs block #{}", cp.tip + 1));
    }
    if cert.chain != header.chain || cert.height != header.height || cert.block != header.hash() {
        return Err("certificate does not match the header".into());
    }
    let trusted = cp.set_at(cp.tip).ok_or("no tracked validator set")?;
    LightClient::from_validators(&to_validator_set(trusted)).verify(cert).map_err(|e| format!("update certificate: {e}"))?;
    validate_set(next)?;
    if bridge_set_hash(next) != header.set_root {
        return Err("validator list does not match the certified set root".into());
    }
    Ok(())
}

/// Check a bridge message proof against the tracked counterparty.
pub fn check_proof(cp: &Counterparty, self_network: &Hash, p: &BridgeProof) -> Result<(), String> {
    let h = &p.header;
    if p.msg.dest_network != *self_network {
        return Err("message is addressed to another network".into());
    }
    if h.chain != ChainId::Playfair {
        return Err("proof header is not from a Playfair Chain".into());
    }
    if p.cert.chain != h.chain || p.cert.height != h.height || p.cert.block != h.hash() {
        return Err("certificate does not match the header".into());
    }
    if h.anchor > cp.tip {
        return Err("counterparty not synced to this block's anchor yet (retry later)".into());
    }
    let set = cp.set_at(h.anchor).ok_or("no tracked validator set at the proof's anchor")?;
    LightClient::from_validators(&to_validator_set(set)).verify(&p.cert).map_err(|e| format!("bridge certificate: {e}"))?;
    if !merkle_verify(&p.msg.hash(), p.leaf, &p.branch, &h.msg_root) {
        return Err("message is not included in the source block".into());
    }
    Ok(())
}
