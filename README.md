# PQ-Chain testnet v0

A post-quantum, multi-chain blockchain prototype in Rust.

| Chain | Role |
|---|---|
| **Keystone Chain** | Staking, validator registry, delegation, slashing, governance |
| **Prism Chain** | UTXO payments and user-created assets |
| **Matrix Chain** *(planned)* | Smart contracts with post-quantum accounts |
| **Vault Chain** *(planned)* | Hash-based data availability for rollups |
| **Arc Chain** *(planned)* | Bridges to other networks |
| **Zones** *(planned)* | Sovereign application chains with their own validators |

> **Prototype.** Not audited and not for real value.

## What works

| Area | Implementation |
|---|---|
| Signatures | ML-DSA-65 (NIST FIPS 204) from **libcrux**, which is formally verified. Algorithm ID byte on every key and signature. Domain-separated contexts per message type. |
| Hashing | SHA3-256 (FIPS 202). 256-bit addresses; Merkle roots; canonical length-prefixed encoding. |
| Prism Chain | UTXO payments, user-created assets, exports to other chains |
| Keystone Chain | Validator registry, staking (min 2,000), delegation (min 25, cap 5x own stake), slashing for equivocation (stake burned, delegators refunded) |
| Cross-chain | Atomic memory: export on Prism, import on Keystone, each output spendable once |
| Consensus | Sampled Quorum Consensus: repeated stake-weighted random polls (k=20, alpha=14, beta=20). Deterministic stake-weighted leader schedule. |
| Node tiers | Tier-1 validators, full node (replays everything, no stake), light client (checks >2/3-stake finality certificates) |
| Safety | `#![forbid(unsafe_code)]`. Failed blocks leave state untouched. Non-malleable txids (signatures excluded). |

## Run

```bash
cargo run --release     # end-to-end demo: payments, double-spend attack, slashing, staking, 8 attack checks
cargo test --release    # protocol tests
```

## Layout

- `src/crypto.rs`: ML-DSA-65 keys, SHA3, Merkle, addresses
- `src/ledger.rs`: transactions, blocks, Prism/Keystone state transition rules
- `src/consensus.rs`: Sampled Quorum Consensus, finality certificates, light client
- `src/network.rs`: in-process nodes, finalize flow, wallet helpers
- `src/main.rs`: demo scenario
- `tests/protocol.rs`: tests

## Roadmap

- **v1**: real P2P (ML-KEM-768 + X25519 hybrid transport), persistent storage (RocksDB), Matrix Chain (EVM with PQ account abstraction), sentry nodes, staking rewards and expiry, RPC
- **v2**: STARK-aggregated finality certificates (one ~100 KB proof instead of N × 3.3 KB signatures), zones (app chains), relay messages between chains, SLH-DSA cold keys
- **v3**: Vault Chain (hash-based data availability), Arc Chain bridges, fuzzing, formal verification (Kani/Verus), external audits

## Credits

The consensus protocol follows the metastable, repeated-subsampling consensus family described in the public research paper *"Scalable and Probabilistic Leaderless BFT Consensus through Metastability"* (Rocket et al., 2019). This project is independent and not affiliated with any other blockchain network.
