# Known issues and limitations

Self-assessed by the development team before any external audit. Severities are our estimates for a
mainnet deployment holding real value: **High** = could lose funds or break safety, **Medium** = could
halt the network or degrade guarantees, **Low** = hardening or hygiene. None of these has been reviewed
by a third party.

## Consensus

| # | Issue | Severity |
|---|---|---|
| C1 | ~~Testnet consensus parameters unsafe~~ **Fixed.** Analysis showed `alpha = 12` lost safety to a 20% split-brain adversary. Defaults are now `alpha = 14, beta = 20`, configurable per network in genesis with `alpha >= 0.7 k` enforced. Remaining: the analysis is simulation-based (see `CONSENSUS_ANALYSIS.md`). | ~~High~~ Low |
| C2 | **Votes in polls (chits) are unsigned.** A validator can answer polls inconsistently with no evidence left behind. Only proposer equivocation is slashable; vote equivocation in certificates is not. | Medium |
| C3 | **Anchor staleness.** Non-Kerckhoffs blocks may use any anchor between the previous one and the local Kerckhoffs tip. A proposer can keep using an old anchor, delaying the effect of validator-set changes; an *exiting* (not slashed) validator remains schedulable under old anchors. | Medium |
| C4 | **Predictable leader schedule.** Anyone can compute upcoming proposers and target them with DoS. Rounds keep the chain live but slower. | Low |
| C5 | **No long-range attack protection.** There is no weak-subjectivity checkpointing; a node syncing from scratch trusts the certificates of historical validator sets, whose keys may later be compromised. | Medium |
| C6 | **Block timestamps are not validated.** They are informational only; nothing should depend on them. | Low |

## Denial of service

| # | Issue | Severity |
|---|---|---|
| D1 | ~~No per-peer rate limits~~ **Partly fixed.** Each connection has message (500/s, burst 2,000) and byte (16 MiB/s, burst 64 MiB) budgets; a peer exceeding them is disconnected and banned for 60 s. Remaining: bans are per identity, so an attacker can rotate keys (bounded by D2's per-IP handshake limit); budgets are not weighted by message cost (a vote costs an ML-DSA verification). | ~~Medium~~ Low |
| D2 | ~~Handshake cost unbounded~~ **Partly fixed.** At most 32 inbound handshakes run at once, and each IP may start 4 per second (burst 16); excess connections are dropped before any cryptography. Remaining: a distributed attacker with many IPs can still keep the 32 slots busy. | ~~Medium~~ Low |
| D3 | ~~RPC unlimited~~ **Partly fixed.** Per-IP budget of 50 requests/s (burst 100); contract queries, scans and submissions cost 10, shard fetches 2; excess requests get HTTP 429 (the wallet backs off and retries). Read-only queries are capped at 2M fuel. Remaining: RPC is still unauthenticated and scans are O(blocks); keep it on trusted interfaces. | ~~Medium~~ Low |
| D4 | **O(state) per transaction.** Atomic transaction application clones the ledger for each transaction (mempool, proposer, RPC submission). Throughput degrades as state grows. | Medium |
| D5 | **Discovery poisoning.** Peers can fill the 1,000-entry known-peer table with bogus addresses (dial attempts are bounded but there is no scoring or eviction). Eclipse resistance is not designed in. | Medium |
| D6 | **Low fees.** Fees are flat and tiny (no fee market or congestion pricing); spam is cheap. | Medium |

## Cross-chain and bridges

| # | Issue | Severity |
|---|---|---|
| B1 | ~~Registration accepted on a fee alone~~ **Fixed.** Registering a counterparty now needs approval signatures from more than 2/3 of this network's own validator stake over the exact (network id, name, height, validator-set hash). Remaining: the approving validators must verify the counterparty's set out of band; the first set is still a trust anchor, now vouched for by the validators. | ~~High~~ Low |
| B2 | **No update skipping.** Light clients must apply every Kerckhoffs header in order. A counterparty with many Kerckhoffs blocks is expensive to follow. | Low |
| B3 | **Set pruning.** Only the newest 256 tracked sets are kept; a proof anchored before the oldest kept set cannot be delivered. | Low |
| B4 | **Zones' safety equals their members' honesty.** A zone with few members can be taken over cheaply; relay messages from it are then forgeable. The Atbash Chain accepts relay messages from any zone. | Medium |
| B5 | **Hamming light clients take the validator set from one node** (`/validators`) instead of following Kerckhoffs certificates from genesis. | Medium |
| B6 | **No data-availability fraud proofs.** Correct encoding relies on validators re-encoding; nodes that only sample cannot prove a bad encoding. | Medium |
| B7 | **Blobs are never pruned.** Storage grows without bound. | Low |
| B8 | **Merkle proofs do not bind the leaf count.** With odd-sized levels a valid path can also verify at a "phantom" index. Callers bind indices separately (shard leaves include the index; consumption is keyed by message identity), but new uses must do the same. | Low |

## Execution (Feistel)

| # | Issue | Severity |
|---|---|---|
| F1 | **Fuel prices are not calibrated.** Host-call and storage costs are rough estimates; some operations may be under-priced relative to their real CPU and memory cost. | Medium |
| F2 | **Each call recompiles the module.** Compilation cost is not charged as fuel beyond the deployment fee. | Medium |
| F3 | **State is cloned per transaction** (see D4). | Medium |
| F4 | **No cross-contract calls, upgrades or contract destruction.** Feature gaps rather than bugs. | Low |

## Economics

| # | Issue | Severity |
|---|---|---|
| E1 | **Unbounded issuance.** 1,000 tokens per block on every chain with no cap or decay; issuance scales with block count, so transaction spam increases inflation. | Medium |
| E2 | **No uptime requirement.** Offline validators keep earning rewards. | Medium |
| E3 | **Rewards are not formally verified.** Kani could not finish the 128-bit arithmetic; covered by a 200,000-case full-range test and the supply fuzzer instead. | Low |

## Keys and operations

| # | Issue | Severity |
|---|---|---|
| K1 | ~~Keys stored as plaintext seed files~~ **Partly fixed.** Key files are now encrypted at rest (Argon2id, 64 MiB, 3 passes → ChaCha20-Poly1305, address bound as associated data) when `PQCHAIN_PASSPHRASE` is set; `wallet encrypt-key` converts old files; plaintext files still load with a warning. Remaining: the passphrase comes from an environment variable, keys are decrypted into process memory, and there is no HSM or key-ceremony tooling. | ~~High~~ Medium |
| K2 | **Block keys cannot be rotated** without exiting and re-registering the validator. | Low |
| K3 | **Randomness** for keys and hedged signing comes from `rand`'s OS-seeded CSPRNG; production should use a vetted hardware source. | Low |
| K4 | **Research code.** `research/stark-agg` (on branch `v2-stark-spike`) uses example-grade parameters and is not part of the node. | Info |

## Fixed during development (for the record)

| Issue | Found by | Fix |
|---|---|---|
| Rejected transactions left partial state changes in the mempool/proposer scratch state | `supply` fuzzer | All transaction application is atomic; regression test |
| Snapshot decoder accepted non-canonical encodings | `snapshot` fuzzer | Strictly increasing keys required |
| Contracts could grow memory toward 4 GiB | review during audit preparation | 16 MiB memory cap and instance limits; regression test |
| Validator weight could overflow on extreme values | Kani review | Saturating addition |
| Blocks proposed before peers connected were never delivered, stalling the chain (intermittent) | two-network script, after raising alpha | New peers receive pending candidates and mempool; candidates re-announced every second |
| Consensus setting `alpha = 12` of 20 allowed a 20% adversary to split honest validators | `examples/consensus_analysis.rs` | Defaults `alpha = 14, beta = 20`; `alpha >= 0.7 k` enforced; regression test |
