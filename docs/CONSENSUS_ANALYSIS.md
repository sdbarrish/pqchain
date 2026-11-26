# Consensus parameter analysis

PQ-Chain's sampled-quorum consensus has three parameters: sample size `k`, success threshold `alpha`,
and decision threshold `beta` (consecutive successful polls). This analysis chose the defaults and the
minimum `alpha` every network must use.

## Method

`examples/consensus_analysis.rs` (`cargo run --release --example consensus_analysis [trials]`) runs
many independent decisions between **two conflicting blocks with honest validators initially split
50/50**, the hardest starting point (it only arises when a proposer equivocates, which is slashable).
Each cell is `safety failures / liveness failures / mean rounds` over 300 trials; a liveness failure
means some honest validator had not decided after 2,000 rounds. Two adversaries:

- **Stall:** byzantine validators vote for whatever honest validators prefer least (attacks liveness).
- **SplitBrain:** byzantine validators tell each querier what it already prefers, pushing the two halves
  toward different decisions (attacks safety).

## Results

```
### adversary: Stall
trials per cell: 300; cell = safety failures / liveness failures / mean rounds
scenario                         k=20 alpha=12 beta=15     k=20 alpha=14 beta=20     k=20 alpha=15 beta=20     k=20 alpha=16 beta=20
4 val, all honest                           0 / 0 / 18                0 / 0 / 29                0 / 0 / 46               0 / 0 / 106
4 val, 1 offline (25%)                      0 / 0 / 34              0 / 26 / 971            0 / 300 / 2000            0 / 300 / 2000
10 val, 2 byzantine (20%)                   0 / 0 / 26               0 / 0 / 152              0 / 9 / 1005            0 / 300 / 2000
10 val, 3 byzantine (30%)                  0 / 3 / 144            0 / 300 / 2000            0 / 300 / 2000            0 / 300 / 2000
10 val, 2 byz + 1 offline                  0 / 0 / 130            0 / 300 / 2000            0 / 300 / 2000            0 / 300 / 2000
20 val, 6 byzantine (30%)                  0 / 4 / 145            0 / 300 / 2000            0 / 300 / 2000            0 / 300 / 2000
20 val, 4 byz + 3 offline                 0 / 26 / 946            0 / 300 / 2000            0 / 300 / 2000            0 / 300 / 2000
10 val, 4 byzantine (40%)               0 / 300 / 2000            0 / 300 / 2000            0 / 300 / 2000            0 / 300 / 2000

### adversary: SplitBrain
trials per cell: 300; cell = safety failures / liveness failures / mean rounds
scenario                         k=20 alpha=12 beta=15     k=20 alpha=14 beta=20     k=20 alpha=15 beta=20     k=20 alpha=16 beta=20
4 val, all honest                           0 / 0 / 18                0 / 0 / 31                0 / 0 / 41                0 / 0 / 80
4 val, 1 offline (25%)                      0 / 0 / 31              0 / 28 / 975            0 / 300 / 2000            0 / 300 / 2000
10 val, 2 byzantine (20%)              88 / 161 / 1088            0 / 238 / 1605            0 / 270 / 1814            0 / 287 / 1922
10 val, 3 byzantine (30%)             134 / 211 / 1438            0 / 282 / 1886            0 / 294 / 1969            0 / 292 / 1956
10 val, 2 byz + 1 offline                0 / 146 / 987            0 / 197 / 1336            0 / 233 / 1584            0 / 260 / 1795
20 val, 6 byzantine (30%)              283 / 79 / 1081            0 / 300 / 2000            0 / 300 / 2000            0 / 300 / 2000
20 val, 4 byz + 3 offline               0 / 236 / 1585            0 / 272 / 1832            0 / 282 / 1906            0 / 291 / 1978
10 val, 4 byzantine (40%)               291 / 15 / 186            1 / 300 / 2000            0 / 300 / 2000            0 / 300 / 2000
```

## Conclusions

1. **The old testnet setting (`alpha = 12` of 20) was unsafe.** A split-brain adversary with 20% of
   stake made honest validators finalize different blocks in 88 of 300 trials (29%); with 30%, 134
   trials. This was a real safety bug, now fixed.
2. **`alpha = 14` of 20 kept safety** in every scenario within the protocol's assumption (< 1/3
   byzantine), with a single failure at 40% (outside the assumption).
3. **Higher `alpha` costs liveness.** At 15–16, a quarter of stake offline already stalls decisions.
4. **Chosen defaults:** `k = 20, alpha = 14, beta = 20`. Every network must have `alpha >= 0.7 k`; the
   node refuses genesis files below that. Parameters live in the genesis file and are part of the
   network id.
5. **Liveness under equivocation.** The simulation's 50/50 start is pessimistic. In the node, every
   validator eventually receives both conflicting blocks by gossip, and until a poll succeeds all
   validators prefer the one with the lower hash (a deterministic tie-break that cannot affect safety),
   so the split dissolves.

## Limits of this analysis

- Simulation, not proof. Two adversary strategies; an adaptive adversary may do better.
- Equal stakes, synchronous rounds, sampling with replacement; real networks have latency and churn.
- The node additionally uses finality certificates (> 2/3 of stake). A chain split also needs two
  conflicting certificates, which requires more than 1/3 of stake to double-sign; that layer is not
  modelled here.
