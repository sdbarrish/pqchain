# PQ-Chain testnet v0

A post-quantum, Avalanche-style multi-chain blockchain prototype in Rust.

> **Prototype.** Not audited and not for real value.

## What works

| Area | Implementation |
|---|---|
| Signatures | ML-DSA-65 (NIST FIPS 204) from **libcrux**, which is formally verified. Algorithm ID byte on every key and signature. Domain-separated contexts per message type. |
| Hashing | SHA3-256 (FIPS 202). 256-bit addresses; Merkle roots; canonical length-prefixed encoding. |
| X-Chain | UTXO payments, user-created assets, exports to other chains |
| P-Chain | Validator registry, staking (min 2,000), delegation (min 25, cap 5x own stake), slashing for equivocation (stake burned, delegators refunded) |
| Cross-chain | Avalanche-style atomic memory: export on X, import on P, each output spendable once |
| Consensus | Snowball/Snowman: stake-weighted polls (k=20, alpha=14, beta=20). Deterministic stake-weighted leader schedule. |
| Node tiers | Tier-1 validators, full node (replays everything, no stake), light client (checks >2/3-stake finality certificates) |
| Safety | `#![forbid(unsafe_code)]`. Failed blocks leave state untouched. Non-malleable txids (signatures excluded). |

## Run

```bash
cargo run --release     # end-to-end demo: payments, double-spend attack, slashing, staking, 8 attack checks
cargo test --release    # protocol tests
```

## Layout

- `src/crypto.rs`: ML-DSA-65 keys, SHA3, Merkle, addresses
- `src/ledger.rs`: transactions, blocks, X/P-Chain state transition rules
- `src/consensus.rs`: Snowball, finality certificates, light client
- `src/network.rs`: in-process nodes, finalize flow, wallet helpers
- `src/main.rs`: demo scenario
- `tests/protocol.rs`: tests

## Roadmap

- **v1**: real P2P (ML-KEM-768 + X25519 hybrid transport), persistent storage (RocksDB), C-Chain (EVM with PQ account abstraction), sentry nodes, staking rewards and expiry, RPC
- **v2**: STARK-aggregated finality certificates (one ~100 KB proof instead of N × 3.3 KB signatures), subnets/L1s, SLH-DSA cold keys
- **v3**: D-Chain (hash-based data availability), B-Chain bridges, fuzzing, formal verification (Kani/Verus), external audits
