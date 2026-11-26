//! PQ-Chain testnet v0: a post-quantum multi-chain prototype.
//!
//! * `crypto`    – ML-DSA-65 (FIPS 204, formally verified libcrux) + SHA3-256
//! * `ledger`    – Atbash Chain (UTXO assets) + Kerckhoffs Chain (staking/slashing) + atomic memory
//! * `consensus` – Sampled Quorum Consensus, finality certificates, light client
//! * `network`   – in-process validators / full nodes, wallet helpers
//!
//! PROTOTYPE: not audited, not for real value.
#![forbid(unsafe_code)]

pub mod codec;
pub mod consensus;
pub mod crypto;
pub mod feistel;
pub mod hamming;
pub mod ledger;
pub mod network;
pub mod node;
pub mod rpc;
pub mod snapshot;
pub mod transport;
pub mod wallet;

#[cfg(kani)]
mod proofs;
