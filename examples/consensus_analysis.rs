//! Monte-Carlo analysis of sampled-quorum parameters (k, alpha, beta).
//!
//! For each parameter set and scenario, run many independent decisions on two
//! conflicting blocks with the honest validators initially split 50/50 (the
//! hardest start), and measure:
//! * safety failures: honest validators finalized *different* blocks;
//! * liveness failures: some honest validator did not finalize within the round limit;
//! * mean rounds to finalize.
//!
//! Adversary: byzantine validators always vote for the block honest validators
//! currently prefer least (keeping the network split). Offline validators abstain.
//!
//! Run: cargo run --release --example consensus_analysis [trials]

use pqchain::consensus::{sampled_quorum, Adversary, Params, Voter};

fn main() {
    let trials: usize = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(300);
    for adversary in [Adversary::Stall, Adversary::SplitBrain] {
        println!("\n### adversary: {adversary:?}");
        table(trials, adversary);
    }
}

fn table(trials: usize, adversary: Adversary) {
    let sets = [(20, 12, 15), (20, 14, 20), (20, 15, 20), (20, 16, 20)];
    let scenarios: [(&str, usize, usize, usize); 8] = [
        // (label, validators, byzantine, offline)
        ("4 val, all honest", 4, 0, 0),
        ("4 val, 1 offline (25%)", 4, 0, 1),
        ("10 val, 2 byzantine (20%)", 10, 2, 0),
        ("10 val, 3 byzantine (30%)", 10, 3, 0),
        ("10 val, 2 byz + 1 offline", 10, 2, 1),
        ("20 val, 6 byzantine (30%)", 20, 6, 0),
        ("20 val, 4 byz + 3 offline", 20, 4, 3),
        ("10 val, 4 byzantine (40%)", 10, 4, 0),
    ];
    println!("trials per cell: {trials}; cell = safety failures / liveness failures / mean rounds");
    print!("{:<28}", "scenario");
    for (k, a, b) in sets {
        print!("  {:>24}", format!("k={k} alpha={a} beta={b}"));
    }
    println!();
    for (label, n, byz, off) in scenarios {
        print!("{label:<28}");
        for (k, alpha, beta) in sets {
            let p = Params { k, alpha, beta, max_rounds: 2_000, adversary };
            let (mut unsafe_, mut stuck, mut rounds) = (0, 0, 0u64);
            for _ in 0..trials {
                let voters: Vec<Voter> = (0..n)
                    .map(|i| Voter { weight: 1, byzantine: i < byz, offline: i >= byz && i < byz + off, initial: Some(i % 2) })
                    .collect();
                let o = sampled_quorum(&voters, 2, p);
                let decided: std::collections::BTreeSet<_> = o.decisions.iter().flatten().collect();
                if decided.len() > 1 {
                    unsafe_ += 1;
                }
                if o.undecided_honest > 0 {
                    stuck += 1;
                }
                rounds += o.rounds as u64;
            }
            print!("  {:>24}", format!("{unsafe_} / {stuck} / {:.0}", rounds as f64 / trials as f64));
        }
        println!();
    }
}
