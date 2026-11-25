//! Spike: how big and how fast is a STARK proof that >2/3 of N validators signed a block,
//! compared with PQ-Chain's current certificate (one ML-DSA-65 signature per vote)?
//!
//! Usage: cargo run --release -- [N ...]   (N + 1 must be a power of two; default 3 7 15 31 63 127)

mod lamport;
mod utils;

use lamport::threshold::{build_keys, measure, AggPublicKey};
use winterfell::{BatchingMethod, FieldExtension, ProofOptions};

type Sha3 = winterfell::crypto::hashers::Sha3_256<winterfell::math::fields::f128::BaseElement>;

/// ML-DSA-65 certificate as PQ-Chain encodes it today.
fn ml_dsa_cert_bytes(votes: usize) -> usize {
    8 + 32 + votes * (32 + 3309)
}

fn main() {
    let ns: Vec<usize> = std::env::args().skip(1).filter_map(|a| a.parse().ok()).collect();
    let ns = if ns.is_empty() { vec![3, 7, 15, 31, 63, 127] } else { ns };
    // ~100-bit conjectured security with SHA3-256 commitments (Winterfell's example uses the same
    // 28 queries / blowup 8; grinding adds 16 bits of proof-of-work).
    // Set SECURITY=128 for a ~128-bit configuration (more queries, higher blowup, quadratic extension).
    let options = if std::env::var("SECURITY").as_deref() == Ok("128") {
        ProofOptions::new(40, 16, 20, FieldExtension::Quadratic, 8, 31, BatchingMethod::Linear, BatchingMethod::Linear)
    } else {
        ProofOptions::new(28, 8, 16, FieldExtension::None, 8, 31, BatchingMethod::Linear, BatchingMethod::Linear)
    };
    println!(
        "{:>5} {:>6} {:>9} {:>9} {:>9} {:>12} {:>14} {:>6} {:>10} {:>8}",
        "keys", "signed", "sign ms", "prove ms", "verify ms", "STARK bytes", "ML-DSA bytes", "ratio", "security", "cheats"
    );
    for n in ns {
        assert!((n + 1).is_power_of_two(), "N + 1 must be a power of two");
        let keys = build_keys(n);
        let agg = AggPublicKey::new(keys.iter().map(|k| k.pub_key()).collect());
        let signed = n * 2 / 3 + 1;
        let m = measure::<Sha3>(&keys, &agg, signed, b"block 42 hash", options.clone());
        println!(
            "{:>5} {:>6} {:>9} {:>9} {:>9} {:>12} {:>14} {:>5.1}x {:>6} bit {:>8}",
            m.keys,
            m.signers,
            m.sign_ms,
            m.prove_ms,
            m.verify_ms,
            m.proof_bytes,
            ml_dsa_cert_bytes(m.signers),
            ml_dsa_cert_bytes(m.signers) as f64 / m.proof_bytes as f64,
            m.security_bits,
            if m.wrong_count_rejected && m.wrong_message_rejected { "caught" } else { "MISSED" }
        );
    }
}
