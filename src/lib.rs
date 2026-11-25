//! PQ-Chain testnet v0: a post-quantum, Avalanche-style multi-chain prototype.
//!
//! * `crypto`    – ML-DSA-65 (FIPS 204, formally verified libcrux) + SHA3-256
//! * `ledger`    – X-Chain (UTXO assets) + P-Chain (staking/slashing) + atomic memory
//! * `consensus` – Snowball/Snowman voting, finality certificates, light client
//! * `network`   – in-process validators / full nodes, wallet helpers
//!
//! PROTOTYPE: not audited, not for real value.
#![forbid(unsafe_code)]

pub mod consensus;
pub mod crypto;
pub mod ledger;
pub mod network;
