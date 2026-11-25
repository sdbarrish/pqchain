# PQ-Chain testnet

A post-quantum, multi-chain blockchain prototype in Rust.

Each chain is named after a piece of cryptographic history:

| Chain | Role | Named after |
|---|---|---|
| **Kerckhoffs Chain** | Staking, validator registry, delegation, slashing, governance | Kerckhoffs's principle (1883): security must rest only in the keys, just as the network's security rests in validator keys |
| **Atbash Chain** | UTXO payments and user-created assets | Atbash, one of the oldest known ciphers, for the chain that carries the most basic use: moving value |
| **Feistel Chain** *(planned)* | Smart contracts with post-quantum accounts | Feistel networks, which build complex ciphers from simple, composable rounds, as contracts compose |
| **Hamming Chain** *(planned)* | Hash-based data availability for rollups | Hamming codes, the first error-correcting codes; data availability relies on erasure coding |
| **Playfair Chain** *(planned)* | Bridges to other networks | The Playfair cipher, which works on pairs of letters, as a bridge links pairs of chains |
| **Zones** | Application chains validated by a chosen subset of primary validators | |

> **Prototype.** Not audited and not for real value.

## What works

| Area | Implementation |
|---|---|
| Signatures | ML-DSA-65 (NIST FIPS 204) from **libcrux**, which is formally verified, for hot keys; SLH-DSA-SHAKE-128s (FIPS 205, hash-based) for cold keys such as validator withdrawal keys. Algorithm ID byte on every key and signature. Domain-separated contexts per message type. |
| Hashing | SHA3-256 (FIPS 202). 256-bit addresses; Merkle roots; canonical length-prefixed encoding. |
| Atbash Chain | UTXO payments, user-created assets, exports to other chains |
| Kerckhoffs Chain | Validator registry, staking (min 2,000), delegation (min 25, cap 5x own stake), slashing for equivocation (stake burned, delegators refunded) |
| Cross-chain | Atomic memory: export on Atbash, import on Kerckhoffs, each output spendable once |
| Consensus | Sampled Quorum Consensus: repeated stake-weighted random polls (k=20, alpha=14, beta=20). Deterministic stake-weighted leader schedule. |
| Node tiers | Tier-1 validators, full node (replays everything, no stake), light client (checks >2/3-stake finality certificates) |
| Safety | `#![forbid(unsafe_code)]`. Failed blocks leave state untouched. Non-malleable txids (signatures excluded). |

## Zones and relay messages (v2)

| Piece | Implementation |
|---|---|
| Registration | `CreateZone { name, members }` on the Kerckhoffs Chain (fee 100, burned). Members must be active primary validators. |
| Validation | Only members propose and vote on a zone. Its finality certificates need > 2/3 of the members' stake. Other nodes follow by certificate. |
| Relay messages | Exports into or out of a zone become messages committed in the block header's `msg_root`. |
| Claiming | The receiving chain checks the source block's certificate against the source chain's validator set, plus a Merkle proof from the message to `msg_root`. Each message can be claimed once. |
| Routes | Atbash ↔ zone and zone ↔ zone. The Kerckhoffs Chain only exchanges with the Atbash Chain, via atomic memory. |

```bash
pqchain wallet create-zone --key payer.key --name games --members <node1>,<node2>,<node3>
pqchain wallet export --key alice.key --amount 4000 --from atbash --to zone-0
pqchain wallet relay-import --key alice.key --chain zone-0
pqchain wallet send --key alice.key --to <bob> --amount 1500 --chain zone-0
```

## Run

```bash
cargo build --release
./target/release/pqchain demo            # v0 in-process demo (simulated network, attack checks)
scripts/local-testnet.sh                 # v1: real multi-process testnet, full end-to-end scenario
cargo test --release                     # protocol, codec and transport tests
```

### Run a local testnet by hand

```bash
pqchain testnet-init --dir testnet                       # keys, genesis, configs (4 validators + 1 full node)
pqchain node --config testnet/validator-0/config.json    # start each node (one terminal each, or in background)

pqchain wallet new --out alice.key
pqchain wallet send --key testnet/faucet.key --to <alice address> --amount 100000
pqchain wallet balance --key alice.key
pqchain wallet export --key alice.key --amount 20000 --from atbash --to kerckhoffs
pqchain wallet import --key alice.key --chain kerckhoffs
pqchain wallet stake --key alice.key --node-key <new node>/node.key --amount 5000
pqchain wallet delegate --key alice.key --node <validator address> --amount 500
pqchain wallet create-asset --key alice.key --name QUBIT --supply 21000000
```

Wallets sign locally; only signed transactions are sent to a node (`--rpc http://127.0.0.1:8100`).

## v1 networking

| Piece | Implementation |
|---|---|
| Transport | Hybrid **ML-KEM-768 + X25519** key exchange, **ML-DSA-65** mutual authentication over the full transcript, ChaCha20-Poly1305 frames. Fresh ephemeral keys per connection (forward secrecy). Network ID derived from genesis. |
| Consensus over the network | Validators poll k=20 stake-weighted samples with `Query`/`Chits` messages (testnet alpha=12, beta=15). |
| Finality certificates | After accepting, validators broadcast signed votes; >2/3 of stake forms a certificate. Full nodes and catching-up nodes accept blocks by certificate. |
| Proposer fallback | Blocks carry a `round`; if the scheduled proposer is offline, the next round's proposer takes over after 2 s. |
| Cross-chain determinism | Every block carries an `anchor` (Kerckhoffs height) whose validator set governs it, so nodes agree regardless of the order they accept the two chains. |
| Storage | Append-only `chain.log` (blocks + certificates, checksummed, fsync'd). Torn writes are truncated; state is rebuilt by replay at startup. |
| Sync | Nodes exchange tips every second and fetch missing certified blocks in batches. |
| RPC | JSON over HTTP: `/status`, `/validators`, `/balance`, `/utxos`, `/atomic`, `/block`, `POST /tx`. |
| Hardening | Bounded decoding (no panics or huge allocations on hostile input), frame size limits, handshake timeouts, `#![forbid(unsafe_code)]`. |

## Layout

- `src/crypto.rs`: ML-DSA-65 keys, SHA3, Merkle, addresses
- `src/ledger.rs`: transactions, blocks, Atbash/Kerckhoffs state transition rules
- `src/consensus.rs`: Sampled Quorum Consensus, finality certificates, light client
- `src/network.rs`: in-process simulation, coin selection helpers
- `src/codec.rs`: binary wire format
- `src/transport.rs`: hybrid post-quantum encrypted transport
- `src/node.rs`: node engine (gossip, voting, certificates, sync, storage)
- `src/rpc.rs`: HTTP RPC
- `src/wallet.rs`: wallet transaction builders and RPC client
- `src/main.rs`, `src/demo.rs`: CLI and v0 demo
- `scripts/local-testnet.sh`: end-to-end multi-process test
- `tests/`: protocol, codec and transport tests

## Roadmap

- **v1 (done, milestone 1)**: real P2P with hybrid post-quantum transport, consensus over the network, finality certificates, persistent storage, sync, RPC, wallet CLI, multi-process testnet
- **v1 milestone 2**: Feistel Chain (smart contracts with PQ accounts), staking rewards and expiry, sentry nodes, peer discovery, state snapshots (no full replay), Docker images
- **v2 step 1 (done)**: SLH-DSA (FIPS 205, hash-based) cold keys; validator exit authorized by the cold withdrawal key, with a 10-block unbonding period during which misbehaviour is still slashable
- **v2 step 2 (done)**: zones (application chains validated by a subset of primary validators, registered on the Kerckhoffs Chain) and relay messages: cross-chain transfers proven by the source block's finality certificate plus a Merkle inclusion proof, claimable exactly once
- **v2 remaining**: STARK-aggregated finality certificates (one ~100 KB proof instead of N × 3.3 KB signatures), zones (app chains), relay messages between chains, SLH-DSA cold keys
- **v3**: Hamming Chain (hash-based data availability), Playfair Chain bridges, fuzzing, formal verification (Kani/Verus), external audits

## Credits

The consensus protocol follows the metastable, repeated-subsampling consensus family described in the public research paper *"Scalable and Probabilistic Leaderless BFT Consensus through Metastability"* (Rocket et al., 2019). This project is independent and not affiliated with any other blockchain network.
