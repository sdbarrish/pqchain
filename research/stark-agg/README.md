# Spike: STARK-aggregated finality certificates

**Question:** can PQ-Chain replace "one ML-DSA-65 signature per vote" finality certificates with a single
post-quantum proof that ">2/3 of the validator set signed this block"? How big, how fast, and at what cost?

**Answer:** yes, and the trade-off is clear. The proof stays around 100–160 KB and verifies in about 3–5 ms
at any validator-set size. Proving takes about 42 ms per validator slot and several GB of RAM at 1,000
validators. It pays off above about 32 validators, so it fits the **light-client and relay-proof** path, not
consensus itself.

## What was built

A standalone crate (`research/stark-agg`) using [Winterfell](https://github.com/facebook/winterfell) 0.13.1, a
STARK prover and verifier. The circuit (AIR) and trace builder are Winterfell's Lamport threshold example,
used unchanged under its MIT license (see `LICENSE-winterfell`). New code is the benchmark harness and the
attack checks.

The proven statement: *at least `t` distinct keys from the set committed to by `pub_key_root` produced valid
Lamport+ signatures on `message`.* Everything is hash-based (Rescue hash inside the circuit, SHA3-256 for the
STARK commitments), so the scheme is post-quantum end to end.

Each run also checks that the verifier **rejects** a proof presented with a higher signer count or a different
message. Every run caught both.

## Results

Machine: 4 vCPU cloud container. Signers = ⌊2N/3⌋+1. "ML-DSA bytes" is PQ-Chain's current certificate size for the
same votes (40 + votes × 3,341 bytes).

### ~100-bit conjectured security (28 queries, blowup 8, 16-bit grinding)

| Validators | Signed | Prove | Verify | STARK proof | ML-DSA cert | Smaller by |
|---:|---:|---:|---:|---:|---:|---:|
| 3 | 3 | 0.24 s | 1 ms | 54 KB | 10 KB | 0.2× (worse) |
| 15 | 11 | 0.68 s | 2 ms | 62 KB | 37 KB | 0.6× (worse) |
| 31 | 21 | 1.4 s | 2 ms | 71 KB | 70 KB | 1.0× (break-even) |
| 63 | 43 | 3.0 s | 2 ms | 76 KB | 144 KB | 1.9× |
| 127 | 85 | 5.7 s | 3 ms | 83 KB | 284 KB | 3.4× |
| 255 | 171 | 10.9 s | 3 ms | 91 KB | 571 KB | 6.3× |
| 511 | 341 | 23.6 s | 3 ms | 98 KB | 1.14 MB | 11.7× |
| 1,023 | 683 | 43.3 s | 3 ms | 105 KB | 2.28 MB | **21.8×** |

Peak RAM at 1,023 validators: about 8.3 GB.

### ~128-bit conjectured security (40 queries, blowup 16, quadratic extension, 20-bit grinding)

| Validators | Signed | Prove | Verify | STARK proof | ML-DSA cert | Smaller by |
|---:|---:|---:|---:|---:|---:|---:|
| 15 | 11 | 1.2 s | 3 ms | 112 KB | 37 KB | 0.3× |
| 63 | 43 | 4.6 s | 4 ms | 136 KB | 144 KB | 1.1× |
| 255 | 171 | 17.9 s | 5 ms | 163 KB | 571 KB | 3.5× |

## Findings

1. **Size grows logarithmically, verification is flat.** From 3 to 1,023 validators the proof only doubles
   (54 → 105 KB), while ML-DSA certificates grow linearly (10 KB → 2.3 MB). Verification stays at 1–5 ms.
2. **Break-even is about 32 validators at 100-bit security, about 64 at 128-bit.** The testnet (4–6 validators) and
   small zones should keep ML-DSA certificates.
3. **Proving is the bottleneck.** It costs about 42 ms per validator slot on 4 cores and scales linearly; at
   1,023 validators it took 43 s and 8.3 GB. It must stay **off the consensus path**: blocks are finalized
   with ML-DSA votes as today, and a prover node compresses the certificate afterwards.
4. **Lamport signatures are one-time.** Each validator would need a fresh key per vote. A real design needs
   a many-time hash-based scheme (XMSS or a WOTS+ Merkle tree per epoch, as in Ethereum's "lean consensus"
   research). That adds a Merkle path per signer to the circuit, so expect proving cost to rise.
5. **Parameters are research-grade.** The circuit's Rescue parameters and f128 field come from an example.
   Production would use a reviewed algebraic hash (RPO / Poseidon2) and a reviewed parameter set, and get an audit.

## Recommended design (if adopted)

- **Keep ML-DSA votes for consensus.** No change to finality latency.
- **Add an optional "compressed certificate"** (STARK) that any node with enough CPU can produce after a
  block is final. Light clients and relay proofs accept either form; the receiver picks the smaller.
- **Use it where it pays off:** the primary network once it exceeds ~64 validators, and relay proofs from
  large zones. Today's relay proof (about 10 KB at 4 validators) should stay ML-DSA.
- **Give validators a second, hash-based "vote key"** (XMSS-style, many-time) registered on the Kerckhoffs
  Chain, used only to sign what the STARK aggregates.

## Next steps

1. Replace Lamport with a many-time hash-based scheme (XMSS / WOTS+ with an algebraic hash) and re-measure.
2. Recursion or folding so proving parallelizes across machines, bounding per-prover time.
3. Evaluate Plonky3 (faster fields such as BabyBear / Mersenne-31) against Winterfell on the same statement.
4. Wire an optional `CompressedCert` into the node, relay proofs and light client behind a feature flag.

## Reproduce

```bash
cd research/stark-agg
cargo run --release -- 3 7 15 31 63 127 255      # N + 1 must be a power of two
SECURITY=128 cargo run --release -- 15 63 255
```
