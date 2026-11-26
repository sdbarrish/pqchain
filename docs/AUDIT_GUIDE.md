# Audit guide

For external reviewers of PQ-Chain. Read with [`PROTOCOL.md`](PROTOCOL.md) (the rules),
[`THREAT_MODEL.md`](THREAT_MODEL.md) (what must hold, under which assumptions) and
[`KNOWN_ISSUES.md`](KNOWN_ISSUES.md) (what we already know is weak).

## Scope

About 7,600 lines of Rust in `src/`, no `unsafe` (`#![forbid(unsafe_code)]`). Out of scope:
`src/demo.rs` (in-process simulation), `research/` (on another branch), and third-party crates (listed in
`Cargo.lock`; the cryptographic ones are libcrux ML-DSA/ML-KEM, `fips205`, `sha3`, `x25519-dalek`,
`chacha20poly1305`, `reed-solomon-erasure`, `wasmi`).

## Code map

| File | Lines | Responsibility | Review focus |
|---|---:|---|---|
| `src/ledger.rs` | ~1,700 | State, every transaction rule, block validity, rewards, supply invariant | **Highest priority.** Conservation, authorization, atomicity, anchor rules |
| `src/node.rs` | ~1,400 | Engine: mempool, proposing, sampled-quorum polls, votes, certificates, sync, discovery, storage, replay | Consensus logic, resource bounds, message handling |
| `src/codec.rs` | ~820 | Wire format for every type | Bounds, canonical encoding |
| `src/feistel.rs` | ~390 | WebAssembly execution, host API, fees | Sandbox limits, fuel accounting, rollback |
| `src/crypto.rs` | ~330 | Keys, signatures, hashing, Merkle trees | Algorithm checks, domain separation, Merkle proof semantics |
| `src/snapshot.rs` | ~330 | Snapshot encode/decode | Canonical decoding |
| `src/transport.rs` | ~250 | Hybrid handshake, encrypted framing | Transcript binding, nonce handling, limits |
| `src/consensus.rs` | ~220 | Snowball reference, finality certificates, light client | Certificate threshold, duplicate votes |
| `src/playfair.rs` | ~210 | Bridge light client and proof checks | Set tracking, proof validation |
| `src/hamming.rs` | ~160 | Erasure coding, commitments, sampling | Commitment binding, reconstruction checks |
| `src/rpc.rs`, `src/wallet.rs`, `src/main.rs` | ~1,240 | RPC server, wallet, CLI | Input handling (RPC is unauthenticated) |
| `src/proofs.rs` | small | Kani harnesses | |

## Where each critical rule is enforced

| Rule | Location |
|---|---|
| Input authorization (key ↔ owner, signature with chain context) | `Ledger::spend_inputs` |
| Per-asset conservation | `Ledger::apply_utxo_inner`, `apply_kerckhoffs_inner`, `apply_blob_inner`, `apply_playfair_inner` |
| Atomicity of transactions | `Ledger::atomically` (public `apply_*`) and `Ledger::apply_block` (clone per block) |
| Export routing rules | `Ledger::create_outputs` |
| Block validity, anchors, leader schedule, roots | `Ledger::apply_block_inner`, `Ledger::scheduled_proposer` |
| Validator-set root | `set_hash`, `next_set_root`, check in `apply_block_inner` |
| Slashing evidence | `Ledger::check_equivocation` |
| Exit and unbonding | `apply_kerckhoffs_inner` (Exit), `Ledger::release_unbonded` |
| Rewards | `Ledger::distribute_rewards`, `reward_shares`, `split_validator_reward` |
| Relay message verification | `Ledger::verify_relay` |
| Bridge update and proof checks | `playfair::check_update`, `playfair::check_proof` |
| Finality certificate threshold | `consensus::LightClient::verify` |
| Feistel validity, fees, rollback | `Ledger::apply_feistel_inner`, `feistel::execute`, `feistel::run` |
| Contract sandbox limits | `feistel::run` (`StoreLimits`, fuel), `feistel::engine` (floats off) |
| Blob commitment check | `Ledger::apply_blob_inner` → `hamming::commit` |
| Decoding bounds | `codec::Reader` (`MAX_BYTES`, `MAX_ITEMS`), `transport` frame limits |
| Supply invariant | `Ledger::native_held` |

## How to verify our claims

```bash
cargo test --release                                  # 47 tests: protocol, attacks, every chain
scripts/local-testnet.sh                              # 6 live nodes, full scenario, state agreement
scripts/bridge-testnet.sh                             # two live networks bridged end to end

cd fuzz                                               # needs nightly + cargo-fuzz
cargo +nightly fuzz run decode   -- -max_total_time=600
cargo +nightly fuzz run snapshot -- -max_total_time=600
cargo +nightly fuzz run supply   -- -max_total_time=600   # money conservation
cargo +nightly fuzz run wasm     -- -max_total_time=600   # contract sandbox and determinism
cargo +nightly fuzz run supply regressions/supply/*       # replay fixed crashes

cd .. && cargo kani --lib                             # 3 bounded proofs (needs Kani)
```

Fuzzing so far: about 37 million decoder inputs, ~73,000 signed operation sequences and ~24,000
generated contracts. Two bugs found and fixed (see `KNOWN_ISSUES.md`).

## Suggested review order

1. **Ledger conservation and authorization.** Every `apply_*` path, especially cross-chain ones (atomic
   memory, relay, bridge escrow/mint). Try to create or destroy native tokens or wrapped tokens.
2. **Block validity and consensus.** Anchor rules, leader schedule, certificate formation in `node.rs`,
   acceptance by certificate vs. by polls, and interaction between chains accepted in different orders.
3. **Bridge light client.** `check_update`, `check_proof`, escrow accounting, registration trust.
4. **Feistel sandbox.** Host functions (memory bounds, fuel charges), limits, rollback.
5. **Transport and decoding.** Handshake transcript binding, nonce reuse, resource exhaustion.
6. **Economics.** Reward split, fee charging, unbonding and slashing interactions.

## Open questions we would like answered

- Are the sampled-quorum parameters and anchor rules safe under adversarial scheduling? (C1, C3)
- Is per-counterparty escrow sufficient containment for bridge compromise, or is a rate limit needed?
- Are fuel prices adequate to prevent cheap resource exhaustion? (F1, F2)
- Is the hybrid handshake transcript complete (every negotiated value bound before keys are used)?
