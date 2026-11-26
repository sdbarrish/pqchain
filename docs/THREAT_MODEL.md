# PQ-Chain threat model

Scope: the code on `main`. This document states what the system is designed to resist, under which
assumptions, and where the design stops. Concrete weaknesses are listed in
[`KNOWN_ISSUES.md`](KNOWN_ISSUES.md).

## 1. Assets

| Asset | Where |
|---|---|
| Native token balances | UTXO sets (Atbash, Kerckhoffs, Hamming, Playfair, zones), Feistel accounts, atomic memory, escrow |
| Bonded stake and delegations | Kerckhoffs Chain validator set |
| User-created and wrapped assets | UTXO sets |
| Contract state and balances | Feistel Chain |
| Availability of posted blobs | Hamming Chain |
| Finality (no conflicting accepted blocks) | all chains |
| Liveness (transactions eventually included) | all chains |
| Node availability | each node process |
| Private keys | key files on operators' and users' machines |

## 2. Adversaries

| Adversary | Capabilities assumed |
|---|---|
| **Quantum adversary** | A cryptographically relevant quantum computer: Shor's algorithm breaks RSA, ECDSA, EdDSA, X25519 and pairing-based schemes; Grover's algorithm halves symmetric/hash security. |
| **Network adversary** | Reads, delays, drops, reorders and injects packets; runs many nodes (Sybil); can partition the network for bounded periods. |
| **Byzantine validators** | Hold less than 1/3 of the stake of a chain's validator set (primary or zone) and deviate arbitrarily, colluding with each other. |
| **Malicious users** | Submit arbitrary transactions, contracts and blobs, and pay fees. |
| **Malicious counterparty network** | For a bridge: may be fully controlled by an attacker (all its validators). |
| **RPC clients** | Any party that can reach a node's RPC port. |

Out of scope: compromise of the machine running a node or wallet; side channels on the host; supply-chain
compromise of dependencies (mitigated only by `Cargo.lock` pinning); social engineering.

## 3. Trust assumptions

1. **Cryptography.** ML-DSA-65, SLH-DSA-SHAKE-128s, ML-KEM-768 and SHA3-256 meet their NIST security
   claims, including against quantum adversaries. The transport stays confidential if *either* ML-KEM-768
   or X25519 holds.
2. **Honest supermajority.** For each chain, validators holding more than 2/3 of that chain's stake at
   the relevant anchor follow the protocol. For a zone this applies to its members' stake only, so a zone
   is only as safe as its member set.
3. **Synchrony for liveness only.** Safety does not depend on timing; liveness needs messages to arrive
   within the poll timeout (400 ms) and round time (2 s) most of the time.
4. **Light-client checkpoints.** Bridges and Hamming light clients trust one initial validator set (a
   registration or a node's `/validators` reply). Everything after it is verified.
5. **Local storage is trusted.** `chain.log` and `snapshot.bin` are checksummed against accidental
   corruption, not against an attacker who can write to the node's disk.

## 4. Threats and mitigations

### 4.1 Cryptographic
| Threat | Mitigation |
|---|---|
| Quantum forgery of signatures | ML-DSA-65 (lattice) for hot keys; SLH-DSA (hash-only) for cold withdrawal keys |
| Quantum decryption of recorded traffic ("harvest now, decrypt later") | Hybrid ML-KEM-768 + X25519, fresh ephemeral keys per connection |
| Signature replay across chains, purposes or networks | Context strings per purpose and per chain; network id in the handshake; chain code in every header and vote |
| Transaction malleability | Txids exclude signatures; canonical encoding (fuzzed) |
| Downgrade to a weaker algorithm | Algorithm byte on every key and signature, checked against each other; block keys must be ML-DSA |

### 4.2 Consensus and finality
| Threat | Mitigation |
|---|---|
| Double-spend via conflicting blocks | Sampled-quorum consensus; certificates need > 2/3 stake; tested with 20% adversarial voters |
| Proposer equivocation | Two signed headers for the same slot are slashing evidence (stake burned) |
| Offline proposer stalls a chain | Proposer rounds every 2 s |
| Validator escapes slashing by leaving | 10-block unbonding during which stake remains slashable |
| Nodes disagree because chains are accepted in different orders | Each block carries an anchor; validity uses the validator set at that anchor |
| Syncing node fed a valid but unfinalized fork | Sync transfers only certified blocks |

### 4.3 Ledger and economics
| Threat | Mitigation |
|---|---|
| Creating money | Per-asset conservation on every transaction; supply invariant fuzzed over signed operation sequences |
| Partial effects from rejected transactions | Every transaction is all-or-nothing (bug found by fuzzing, fixed) |
| Theft | Each input needs a signature from the key that hashes to the output's owner |
| Stolen hot key withdraws stake | Exits and payouts require the cold withdrawal key |
| Reward claim replay | Per-address claim nonce |
| Reward over-issuance | Shares round down (tested over the full u64 range; reward split fuzzed via the supply invariant) |

### 4.4 Cross-chain and bridges
| Threat | Mitigation |
|---|---|
| Forged relay or bridge message | Source header + > 2/3 certificate of the source chain's set + Merkle inclusion proof |
| Double claim | Consumed-message sets |
| Inflated amount / wrong recipient / wrong destination | Fields are inside the Merkle leaf; destination checked |
| Counterparty rotates to a set it shouldn't | New sets only via headers certified by > 2/3 of the tracked set, matching `set_root` |
| Fully compromised counterparty drains the bridge | Escrow is per counterparty: it can release at most what was sent to it; it can mint unlimited wrapped tokens of *its own* origin, which are only worth what that network backs |
| Data withheld behind a published commitment | Rate-1/2 erasure coding, commitments re-checked by validators, random sampling (< 2^-s miss chance for s samples) |

### 4.5 Execution (Feistel)
| Threat | Mitigation |
|---|---|
| Infinite loops | Fuel metering; fee charged for fuel used |
| Memory exhaustion | 16 MiB memory cap, 1 memory, 1 table, bounded table size (found in review, fixed) |
| Non-determinism | Floating point disabled; deterministic interpreter; fuzzed for determinism |
| Failed calls corrupting state | Execution on a scratch copy; committed only on success |

### 4.6 Network and nodes
| Threat | Mitigation |
|---|---|
| Malformed messages crash nodes | Bounded, strict decoders; fuzzed (> 30 million inputs) |
| Oversized frames | 16 MiB frame and 16 KiB handshake limits |
| Impersonating a peer | ML-DSA mutual authentication over the transcript; identities pinned for discovered peers |
| Crash corrupts storage | Checksummed, fsync'd log; torn tail truncated; atomic snapshot writes |

## 5. Explicit non-goals (current version)

- Privacy: all balances, transfers and contract state are public.
- Denial-of-service resistance against well-resourced attackers (see `KNOWN_ISSUES.md`).
- Bridges to networks other than PQ-Chain.
- Production key management (HSMs, key ceremonies, rotation of block keys).
