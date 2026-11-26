# PQ-Chain testnet

A post-quantum, multi-chain blockchain prototype in Rust.

Each chain is named after a piece of cryptographic history:

| Chain | Role | Named after |
|---|---|---|
| **Kerckhoffs Chain** | Staking, validator registry, delegation, slashing, governance | Kerckhoffs's principle (1883): security must rest only in the keys, just as the network's security rests in validator keys |
| **Atbash Chain** | UTXO payments and user-created assets | Atbash, one of the oldest known ciphers, for the chain that carries the most basic use: moving value |
| **Feistel Chain** | WebAssembly smart contracts with post-quantum accounts | Feistel networks, which build complex ciphers from simple, composable rounds, as contracts compose |
| **Hamming Chain** | Hash-based data availability for rollups and zones | Hamming codes, the first error-correcting codes; data availability relies on erasure coding |
| **Playfair Chain** | Trust-minimized bridges to other PQ-Chain networks (on-chain light clients) | The Playfair cipher, which works on pairs of letters, as a bridge links pairs of chains |
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

## Feistel Chain (smart contracts)

| Piece | Implementation |
|---|---|
| Accounts | Address of an ML-DSA-65 or SLH-DSA key; each transaction is signed and nonce-protected. |
| Contracts | WebAssembly run by `wasmi` (deterministic interpreter) with fuel metering; floating point disabled. One exported function per method, optional `init` at deployment. |
| Host API | `storage_read/write`, `caller`, `self_address`, `value`, `balance`, `input`, `output`, `log`, `transfer`. |
| Fees | 1 + fuel used / 10,000, burned. A failed call is rolled back but pays for its fuel and uses its nonce. |
| Funding | Export from the Atbash Chain to `feistel`, then `feistel-import`. `feistel-export` sends funds back. |
| Examples | `contracts/counter.wat` and `contracts/tipjar.wat` (owner-only withdrawal). |

```bash
pqchain wallet export --key alice.key --amount 30000 --from atbash --to feistel
pqchain wallet feistel-import --key alice.key
pqchain wallet feistel-deploy --key alice.key --code contracts/counter.wat
pqchain wallet feistel-call --key alice.key --contract <address> --method increment
pqchain wallet feistel-query --contract <address> --method get
```

Not yet supported: contract-to-contract calls, contract upgrades, an EVM compatibility layer.

## Staking rewards, discovery, snapshots

- **Rewards:** each accepted block issues 1,000 native tokens, split across that chain's validators by stake. Delegators are paid pro rata minus a 10% commission. Claim with `wallet claim-rewards --key <withdrawal or reward key>` (replay-protected by a nonce).
- **Peer discovery:** nodes announce their address and gossip known peers. A node needs one bootstrap peer; identities are pinned in the handshake.
- **Snapshots:** every 20 log records the node writes a checksummed ledger snapshot. A restart loads it and re-executes only later records.

## Hamming Chain (data availability)

| Piece | Implementation |
|---|---|
| Blobs | Up to 128 KB each (2 MB per block), tagged with an 8-byte namespace. Fee: 1 + 1 per 256 bytes, burned. |
| Erasure coding | Reed–Solomon at rate 1/2: `k` data + `k` parity shards (`k` ≤ 64); any `k` shards rebuild the blob. |
| Commitment | Merkle root over the shards (hash-based, post-quantum; no KZG). Validators re-encode every blob, so a certified block has a correct encoding. |
| Light clients | Verify the block's finality certificate and the blob's inclusion in `tx_root`, then sample random shards with Merkle proofs. Withholding needs > half the shards, so `s` verified samples leave < 2^-s chance of unavailability. |
| Funding | Atbash Chain ↔ Hamming Chain via atomic memory. |

```bash
pqchain wallet export --key alice.key --amount 5000 --from atbash --to hamming
pqchain wallet import --key alice.key --chain hamming
pqchain wallet hamming-post --key alice.key --namespace rollup1 --file data.bin
pqchain wallet hamming-sample --height 2 --samples 20      # light-client availability check
pqchain wallet hamming-get --height 2 --out rebuilt.bin    # rebuild from a random half of the shards
```

Limits: the light client takes the validator set from one node as a checkpoint (a production client would follow Kerckhoffs Chain certificates from genesis); nodes keep all blobs (no pruning yet); there is no fraud-proof path for nodes that only sample.

## Playfair Chain (bridges)

Each network's Playfair Chain runs an **on-chain light client** of every registered counterparty network. Funds move on cryptographic proof, with no multisig custodian.

| Piece | Implementation |
|---|---|
| Validator-set commitments | Every Kerckhoffs block header carries `set_root`, the hash of the validator set the block produces; every node verifies it. |
| Tracking | `Update` applies the counterparty's next Kerckhoffs header. It is accepted only with a > 2/3 certificate from the set already tracked, and the new list must match `set_root`. |
| Send | Native tokens are escrowed per destination network; wrapped tokens going home are burned. The message is committed in the block's `msg_root`. |
| Receive | Source header + finality certificate (checked against the tracked set at the header's anchor) + Merkle path. Mints wrapped tokens or releases escrow; each message is received once. |
| Damage limits | Escrow is per counterparty, so a compromised network can release at most what was sent to it. No multi-hop: wrapped tokens only return to their origin. |
| Trust anchor | Registration (fee 100) records the counterparty's validator set at one height. Check the network id out of band, like a light-client checkpoint. |

```bash
pqchain wallet --rpc $A bridge-register --key payer.key --remote $B --name network-b
pqchain wallet --rpc $A bridge-sync --remote $B                     # relayer: light-client updates
pqchain wallet --rpc $A bridge-send --key alice.key --dest-network <B id> --recipient <bob> --amount 1000
pqchain wallet --rpc $B bridge-relay --remote $A                    # relayer: deliver with proofs
scripts/bridge-testnet.sh                                           # two live networks end to end
```

Not supported yet: bridges to non-PQ-Chain networks (Bitcoin, Ethereum), skipping light-client updates (every Kerckhoffs header is applied in order), and token types other than each network's native token.

## Hardening (v3)

**Fuzzing** (`cargo +nightly fuzz run <target>` in `fuzz/`, libFuzzer):

| Target | What must hold | Inputs tried |
|---|---|---|
| `decode` | Every wire decoder (messages, blocks, transactions, relay proofs, certificates) rejects garbage without panicking; anything accepted re-encodes to the exact input | ~16 million |
| `snapshot` | Same for snapshots | ~13 million |
| `supply` | Arbitrary sequences of correctly signed operations conserve money: held + burned = genesis + minted after every step | ~63,000 sequences |
| `wasm` | Generated WebAssembly contracts never panic the node, stay within fuel, and run deterministically | ~24,000 contracts |

Bugs found and fixed (crash inputs kept in `fuzz/regressions/`):
1. **Non-atomic transactions** (`supply`): a transaction rejected late in validation, such as a delegation over the cap, left inputs spent and fees burned in the scratch state the mempool and proposer use. Every `apply_*` is now all-or-nothing.
2. **Non-canonical snapshots** (`snapshot`): the decoder accepted out-of-order or duplicate keys. Keys must now strictly increase.

**Formal proofs** (`cargo kani`, bounded model checking, every input):
- the wire reader never panics or reads out of bounds
- chain codes are unique for every possible zone number
- fees never overflow, and a transaction never pays more than its declared maximum

Reward arithmetic is not formally proved: the solver could not finish symbolic 128-bit division even at 8-bit inputs. It is covered by a unit test sampling 200,000 cases over the full 64-bit range and by the `supply` fuzzer.

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
- **Core milestone 2 (done)**: staking rewards, peer discovery, state snapshots, Feistel smart-contract chain
- **v2 step 1 (done)**: SLH-DSA (FIPS 205, hash-based) cold keys; validator exit authorized by the cold withdrawal key, with a 10-block unbonding period during which misbehaviour is still slashable
- **v2 step 2 (done)**: zones (application chains validated by a subset of primary validators, registered on the Kerckhoffs Chain) and relay messages: cross-chain transfers proven by the source block's finality certificate plus a Merkle inclusion proof, claimable exactly once
- **v2 remaining**: STARK-aggregated finality certificates (one ~100 KB proof instead of N × 3.3 KB signatures), zones (app chains), relay messages between chains, SLH-DSA cold keys
- **v3 hardening (done)**: fuzzing (4 targets, 2 bugs fixed), Kani proofs, atomic transaction application
- **v3 Hamming Chain (done)**: erasure-coded blobs, hash-based commitments, light-client sampling
- **v3 Playfair Chain (done)**: on-chain light clients, escrow and wrapped tokens, validator-set roots in headers
- **Remaining before any real value**: external security audit, bridges to external networks, light-client update skipping, blob pruning

## Credits

The consensus protocol follows the metastable, repeated-subsampling consensus family described in the public research paper *"Scalable and Probabilistic Leaderless BFT Consensus through Metastability"* (Rocket et al., 2019). This project is independent and not affiliated with any other blockchain network.
