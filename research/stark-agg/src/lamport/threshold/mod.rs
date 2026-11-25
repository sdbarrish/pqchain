// Adapted from Winterfell's Lamport threshold example (MIT License, Copyright (c) Facebook, Inc.
// and its affiliates; see LICENSE-winterfell). The proving/verification logic (air.rs, prover.rs,
// signature.rs) is unchanged; this module replaces the example harness with a benchmark API.
//
// What the proof shows: "at least `num_signatures` distinct keys from the set committed to by
// `pub_key_root` produced valid Lamport+ signatures on `message`". Lamport+ signatures use only
// the Rescue hash, so the statement and the STARK proving it are hash-based (post-quantum).

use core::marker::PhantomData;
use std::time::Instant;

use winterfell::{
    crypto::{DefaultRandomCoin, ElementHasher, MerkleTree},
    math::{fields::f128::BaseElement, get_power_series, FieldElement, StarkField},
    Proof, ProofOptions, Prover, Trace,
};

use super::{rescue, PrivateKey, Signature, CYCLE_LENGTH as HASH_CYCLE_LENGTH, NUM_HASH_ROUNDS};

mod signature;
pub use signature::AggPublicKey;

mod air;
use air::{LamportThresholdAir, PublicInputs};

mod prover;
use prover::LamportThresholdProver;

const TRACE_WIDTH: usize = 28;
const SIG_CYCLE_LENGTH: usize = 128 * HASH_CYCLE_LENGTH; // 1024 steps

/// Deterministic test keys, sorted by public key (the order the aggregated key uses).
pub fn build_keys(num_keys: usize) -> Vec<PrivateKey> {
    let mut result: Vec<PrivateKey> = (0..num_keys)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
            PrivateKey::from_seed(seed)
        })
        .collect();
    result.sort_by_key(|k| k.pub_key());
    result
}

pub struct Measurement {
    pub signers: usize,
    pub keys: usize,
    pub sign_ms: u128,
    pub prove_ms: u128,
    pub verify_ms: u128,
    pub proof_bytes: usize,
    pub security_bits: u32,
    #[allow(dead_code)]
    pub trace_steps: usize,
    pub wrong_count_rejected: bool,
    pub wrong_message_rejected: bool,
}

pub fn verify<H>(proof: Proof, inputs: PublicInputs) -> Result<(), winterfell::VerifierError>
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
{
    let acceptable = winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);
    winterfell::verify::<LamportThresholdAir, H, DefaultRandomCoin<H>, MerkleTree<H>>(proof, inputs, &acceptable)
}

/// Prove that `num_signatures` of `keys` signed `msg`, then verify (and try to cheat).
pub fn measure<H>(keys: &[PrivateKey], agg: &AggPublicKey, num_signatures: usize, msg: &[u8], options: ProofOptions) -> Measurement
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
{
    let t = Instant::now();
    let signatures: Vec<(usize, Signature)> = (0..num_signatures).map(|i| (i, keys[i].sign(msg))).collect();
    let sign_ms = t.elapsed().as_millis();
    let message = super::message_to_elements(msg);

    let prover = LamportThresholdProver::<H>::new(agg, message, &signatures, options);
    let t = Instant::now();
    let trace = prover.build_trace(agg, message, &signatures);
    let trace_steps = trace.length();
    let proof = prover.prove(trace).expect("proving failed");
    let prove_ms = t.elapsed().as_millis();
    let proof_bytes = proof.to_bytes().len();
    let security_bits = proof.conjectured_security::<H>().bits();

    let inputs = |n: usize, m: [BaseElement; 2]| PublicInputs {
        pub_key_root: agg.root().to_elements(),
        num_pub_keys: agg.num_keys(),
        num_signatures: n,
        message: m,
    };
    let t = Instant::now();
    verify::<H>(proof.clone(), inputs(num_signatures, message)).expect("valid proof must verify");
    let verify_ms = t.elapsed().as_millis();
    let wrong_count_rejected = verify::<H>(proof.clone(), inputs(num_signatures + 1, message)).is_err();
    let other = super::message_to_elements(b"a different block hash");
    let wrong_message_rejected = verify::<H>(proof, inputs(num_signatures, other)).is_err();

    Measurement {
        signers: num_signatures,
        keys: agg.num_keys(),
        sign_ms,
        prove_ms,
        verify_ms,
        proof_bytes,
        security_bits,
        trace_steps,
        wrong_count_rejected,
        wrong_message_rejected,
    }
}

#[allow(dead_code)]
fn _unused(_: PhantomData<()>, _: &[BaseElement]) -> Vec<BaseElement> {
    get_power_series(BaseElement::ONE, 1)
}
