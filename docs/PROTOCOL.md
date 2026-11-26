# PQ-Chain protocol specification

Status: describes the code on `main` (testnet). Where this document and the code disagree, the code is
authoritative and the disagreement is a documentation bug. File references point to where each rule is
enforced.

## 1. Cryptography (`src/crypto.rs`)

| Use | Primitive | Standard |
|---|---|---|
| Hot signatures (blocks, votes, transactions, node identity) | ML-DSA-65, hedged signing | FIPS 204 (libcrux, formally verified implementation) |
| Cold signatures (validator withdrawal keys, optional accounts) | SLH-DSA-SHAKE-128s | FIPS 205 (`fips205` crate) |
| Hashing, addresses, Merkle trees | SHA3-256 | FIPS 202 |
| Key exchange (transport) | ML-KEM-768 + X25519 hybrid | FIPS 203 / RFC 7748 |
| Transport encryption | ChaCha20-Poly1305 | RFC 8439 |

- **Algorithm agility.** Every public key and signature carries an algorithm byte: `0x01` ML-DSA-65,
  `0x02` SLH-DSA-SHAKE-128s. A signature verifies only if its algorithm equals the key's. Unknown
  algorithms are rejected.
- **Addresses.** `address = SHA3-256(Enc("pqchain/address") | alg | pubkey)`, written `pq1` + hex.
- **Canonical hashing.** All hashes use `Enc`: a domain-tag string, then length-prefixed fields
  (u64 little-endian lengths). No two different structures share a domain tag.
- **Domain separation of signatures.** Every signature uses a FIPS 204/205 context string:

| Context | Signs |
|---|---|
| `pqchain/v0/block` | block header hash |
| `pqchain/v0/finality-vote` | `H("pqchain/vote", chain code, height, block hash)` |
| `pqchain/v0/atbash/tx`, `pqchain/v0/kerckhoffs/tx`, `pqchain/v3/hamming/tx`, `pqchain/v3/playfair/tx` | transaction id |
| `pqchain/v2/zone/{n}/tx` | transaction id on zone `n` |
| `pqchain/v3/feistel/tx` | Feistel transaction id |
| `pqchain/v2/validator-exit`, `pqchain/v3/claim-rewards` | transaction id of an exit / reward claim |
| `pqchain/v1/handshake/{initiator,responder}` | handshake transcript hash |

- **Merkle trees.** Leaves are `H("pqchain/merkle/leaf", x)`, nodes `H("pqchain/merkle/node", l, r)`.
  An odd node at any level is paired with itself. The empty tree's root is `H("pqchain/merkle/empty")`.
  Inclusion proofs are sibling paths; verification checks the index bit at each level.

## 2. Chains (`src/ledger.rs`, `ChainId`)

| Chain | Code | Model | Role | Exchanges value with |
|---|---|---|---|---|
| Kerckhoffs | 0 | UTXO | staking, validators, zones registry, rewards | Atbash (atomic memory) |
| Atbash | 1 | UTXO | payments, user-created assets | all other chains |
| Feistel | 2 | accounts | WebAssembly contracts | Atbash (atomic memory) |
| Hamming | 3 | UTXO | data availability (blobs) | Atbash (atomic memory) |
| Playfair | 4 | UTXO | bridges to other networks | Atbash (atomic memory), other networks |
| Zone *n* | 16 + *n* | UTXO | application chains | Atbash and zones (relay messages) |

Codes 5–15 are reserved. Chain codes appear in every header, vote and leader-schedule hash.

## 3. Wire encoding (`src/codec.rs`)

- Integers little-endian; byte strings and lists are `u32` length + items.
- Limits: byte string ≤ 1 MiB, list ≤ 100,000 items, frame ≤ 16 MiB, handshake frame ≤ 16 KiB.
- Decoding rejects trailing bytes. Every accepted encoding re-encodes to identical bytes (checked by the
  `decode` fuzzer). There is exactly one encoding per value.

## 4. Transactions

### 4.1 Transfers (all UTXO chains)
A `Transfer` has inputs, outputs, an optional export (destination chain + outputs) and relay proofs.
- Each input names an outpoint and a source: `Local` (this chain's UTXO set), `Atomic` (exported to this
  chain from another primary chain) or `Relay` (a proven relay message, §7).
- Each input's public key must hash to the spent output's owner, and its signature must verify over the
  transaction id with the chain's context.
- **The txid excludes signatures** (non-malleable), and excludes relay proofs (they can be refreshed).
  It commits to which relay messages are claimed.
- Outputs must be non-zero. Output `i` of txid `t` becomes outpoint `(t, i)`; exported outputs continue
  the numbering after local outputs.
- **Conservation:** per asset, inputs ≥ outputs + exports (+ fee, stake or amount sent where the kind
  says so). Non-native assets must balance exactly unless being created, sent or received as defined
  below. Native surplus is burned.
- **Atomicity:** applying a transaction either fully succeeds or leaves the state unchanged.

### 4.2 Atbash (`apply_utxo`)
Fee `TX_FEE = 1`. An optional `create_asset {name ≤ 64 B, supply}` mints a new asset whose id is
`H("pqchain/asset", first input outpoint)` (globally unique); outputs of that asset must equal `supply`.

### 4.3 Kerckhoffs (`apply_kerckhoffs`)
All amounts are native. Kinds:

| Kind | Rule |
|---|---|
| Transfer | fee 1 |
| AddValidator | stake ≥ 2,000 locked; block key must be ML-DSA-65; node id = address of that key, not yet registered |
| AddDelegator | stake ≥ 25; validator active (not slashed, not exiting); delegated ≤ 5 × own stake |
| Slash | two different, validly signed headers with the same chain, height, round and proposer. Free. Burns the validator's stake and refunds its delegators |
| Exit | signed (context `validator-exit`) by the key whose address is the validator's withdrawal address. Weight drops to 0 at once; stake and delegations are released `UNBONDING_BLOCKS = 10` Kerckhoffs blocks later and remain slashable until then |
| CreateZone | fee 100; 1–64 distinct members, each an active primary validator; name 1–32 B; zone id = next integer; membership is fixed |
| ClaimRewards | signed by the key whose address holds rewards; `nonce` must equal that address's claim count (replay protection); pays the full unclaimed balance as one output |

### 4.4 Feistel (`apply_feistel`, `src/feistel.rs`)
Transaction: sender public key (ML-DSA or SLH-DSA), nonce, `max_fuel ≤ 50,000,000`, action, signature.
- Valid iff signature verifies, nonce equals the sender's current nonce, and balance ≥
  `max_fee + value` where `max_fee = 1 + ⌈max_fuel / 10,000⌉`.
- `Import` consumes atomic-memory exports to Feistel owned by the sender (1–256 distinct outpoints),
  credits them, pays `BASE_FEE`.
- `Export` debits and creates an atomic-memory output to the sender's address on Atbash.
- `Transfer`, `Deploy`, `Call` execute on a scratch copy. On success the copy replaces the state; on
  failure it is discarded. **Either way** the nonce increments and the fee
  `1 + ⌈fuel_used / 10,000⌉` is charged and burned.
- Contract address: `H("pqchain/feistel/contract", creator, nonce)`. Deployment costs 50 fuel per code
  byte plus `init` execution if exported.
- Execution: `wasmi` with fuel metering, floating point disabled, at most 16 MiB linear memory, 1 memory,
  1 table (≤ 10,000 elements), 1 instance. Host API and limits are in `src/feistel.rs`. Cross-contract
  calls are not supported.

### 4.5 Hamming (`apply_blob`, `src/hamming.rs`)
A blob transaction has a transfer, an 8-byte namespace, a commitment and data (≤ 128 KiB; ≤ 2 MiB per
block). Fee: `1 + ⌈len / 256⌉`.
- Encoding: `k = clamp(⌈len/64⌉, 1, 64)` data shards of `⌈len/k⌉` bytes (zero-padded) plus `k`
  Reed–Solomon parity shards over GF(2⁸).
- Commitment: `{len, k, root}` with `root = MerkleRoot(H("pqchain/hamming/shard", i, shard_i))`.
- **Validity requires `commit(data) == commitment`.** Every validator re-encodes.
- Transaction id: `H("pqchain/hamming-tx", H("pqchain/hamming-prefix", transfer, namespace),
  H(commitment))`. It can be checked without the data.

### 4.6 Playfair (`apply_playfair`, `src/playfair.rs`)
| Kind | Rule |
|---|---|
| Transfer | fee 1 |
| Register | fee 100; counterparty network id ≠ own and not registered; name 1–32 B; validator list canonical (§8) |
| Update | header is the counterparty's Kerckhoffs block `tip + 1`; certificate matches the header and has > 2/3 of the tracked set at `tip`; new list canonical and hashes to the header's `set_root`. Free |
| Send | destination registered; amount > 0. If origin = own network: native escrowed for that destination. Otherwise origin must equal the destination (no multi-hop) and that many wrapped tokens are burned. Fee 1 |
| Receive | proof (§8) valid; message not yet received. If origin = own network: escrow for the source network is reduced (must cover the amount) and native is paid. If origin = source network: wrapped tokens `H("pqchain/playfair/wrapped", origin)` are minted. Otherwise rejected. Free |

## 5. Blocks (`apply_block`)

Header: chain, height, parent, tx_root, proposer, timestamp, round, anchor, msg_root, set_root.

A block is valid iff all of:
1. `height = tip + 1` and `parent = tip hash` for its chain; the chain is known.
2. **Anchor.** Kerckhoffs blocks: `anchor = parent height`. Other chains: `anchor ≤ local Kerckhoffs tip`
   (otherwise "retry later") and not lower than the chain's previous anchor.
3. The proposer is in the chain's validator set at `anchor` (zones: members only), is not slashed now,
   and equals the stake-weighted leader for `(chain, height, parent, round)` over that set.
4. The proposer's ML-DSA signature over the header hash verifies.
5. `tx_root` = Merkle root of transaction ids; `msg_root` = Merkle root of relay messages (bridge
   messages on Playfair); for Kerckhoffs blocks `set_root` = hash of the resulting active set, otherwise
   zero.
6. Every transaction is valid in order. Hamming blocks carry ≤ 2 MiB of blob data.

After the transactions: rewards are distributed (§9). On Kerckhoffs blocks, unbonded validators are
released and the validator set is snapshotted at that height.

**Leader schedule:** `seed = H("pqchain/leader", chain, height, parent, round)`; the validator whose
cumulative weight range contains `seed mod total_weight` (validators in node-id order) proposes.

**Validator set hash:** `H("pqchain/validator-set", for each active validator in node-id order:
node id, key alg, key, weight)`. Used for `set_root` and bridge tracking.

## 6. Consensus and finality (`src/consensus.rs`, `src/node.rs`)

- **Sampled quorum** (Snowball family). For an undecided height a validator repeatedly samples
  `k = 20` validators, weighted by stake with replacement, and asks for their preferred block. A poll
  succeeds if one block gets ≥ `alpha` votes. The preference follows the block with the most successful
  polls. The block is accepted after `beta` consecutive successful polls for it. Parameters come from the
  genesis file and are part of the network id; defaults `k = 20, alpha = 14, beta = 20`; `alpha < 0.7 k`
  is rejected (see `CONSENSUS_ANALYSIS.md`). Poll timeout 400 ms; unreachable validators abstain.
  Until a poll succeeds, conflicting candidates are ordered by hash (lowest preferred).
- **Proposer rounds.** If no candidate exists, the leader for round `r = ⌊waited / 2 s⌋` proposes.
  Honest validators propose at most once per (chain, height, round).
- **Finality certificates.** After accepting a block, each validator of that chain signs a vote. A
  certificate is a set of distinct votes from more than 2/3 of the chain's stake at the block's anchor.
  Nodes that do not vote (full nodes, syncing nodes) accept a block when they hold such a certificate.
- **Sync** transfers blocks only together with certificates.

## 7. Relay messages (zones)

An export from or to a zone creates a relay message `{src, dest, txid, index, output}` committed in the
source block's `msg_root`. It is claimed on the destination with `Source::Relay` and a proof: the
source header, its finality certificate (checked against the source chain's validator set at the
header's anchor, which must not exceed the local Kerckhoffs tip) and a Merkle path. A message is claimed
at most once (keyed by source chain and outpoint). The Kerckhoffs Chain never exchanges with zones.

## 8. Bridges (`src/playfair.rs`)

- Tracked set representation: list of (ML-DSA key, weight > 0) sorted by node id, unique, ≤ 128 entries.
- Bridge message: `{src_network, dest_network, txid, recipient, origin, amount}`, committed in the
  source Playfair block's `msg_root`.
- Proof check: destination is this network; header is a Playfair header; certificate matches the header;
  `anchor ≤ tracked tip` (else retry later); certificate has > 2/3 of the tracked set at `anchor`;
  Merkle path to `msg_root`.
- The newest 256 tracked sets are kept per counterparty.

## 9. Economics

| Item | Value |
|---|---|
| Fees | Atbash, Kerckhoffs, Playfair transfers: 1. Blobs: 1 + ⌈len/256⌉. Feistel: 1 + ⌈fuel/10,000⌉. Zone creation and bridge registration: 100. All fees are burned. |
| Issuance | 1,000 per accepted block on any chain, split across that chain's validators by weight (rounded down). |
| Delegation | A validator's share is split by own stake : delegated stake. The validator keeps 10% of the delegators' part as commission. Delegators are paid pro rata. |
| Invariant | `native held + burned = genesis supply + minted` (checked by the `supply` fuzzer). |

## 10. Transport and P2P (`src/transport.rs`, `src/node.rs`)

- Handshake: `I → R: "PQC1" | network id | X25519 eph | ML-KEM-768 encaps key`;
  `R → I: {X25519 eph | ML-KEM ct | R key} | sig_R(transcript)`; keys =
  `SHA3(transcript | X25519 ss | ML-KEM ss)` per direction; `I → R (encrypted): I key | sig_I(transcript)`.
- Frames: u32 length + ChaCha20-Poly1305 ciphertext; nonce = 64-bit per-direction counter.
- Network id = `H("pqchain/network-id", name, genesis state root)`. Peers on other networks are refused.
- Discovery: `Hello{listen}`, `Peers[(id, addr)]` (≤ 64 per message, ≤ 1,000 known). Dialed peers'
  identities are pinned.

## 11. Storage (`src/node.rs`, `src/snapshot.rs`)

- `chain.log`: records `len | kind | 4-byte SHA3 checksum | payload` (block or certificate), fsync per
  record. A torn final record is truncated at startup.
- `snapshot.bin` every 20 records: magic, state root, payload, SHA3 checksum; written to a temp file and
  renamed. Loaded only if its checksum and state root verify; keys must strictly increase. Snapshots are
  local and never accepted from peers.
