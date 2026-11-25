//! Kani proof harnesses: properties checked for *every* input, not samples.
//! Run with `cargo kani`. Each harness is a bounded model-checking proof.
//!
//! Reward arithmetic (shares never exceed BLOCK_REWARD; a validator's split
//! never exceeds its share) is not proved here: CBMC could not finish the
//! symbolic 128-bit divisions within 25 minutes, even with inputs bounded to
//! 8 bits. It is covered instead by `ledger::reward_math_tests` (200,000
//! random cases over the full u64 range) and the `supply` fuzzer.

use crate::codec::Reader;
use crate::feistel::{fee_for_fuel, MAX_FUEL};
use crate::ledger::ChainId;

/// Fees: never overflow, and paying for the fuel actually used is never more
/// than the declared maximum.
#[kani::proof]
fn fee_is_monotonic_and_bounded() {
    let used: u64 = kani::any();
    let max: u64 = kani::any();
    kani::assume(used <= max && max <= MAX_FUEL);
    assert!(fee_for_fuel(used) <= fee_for_fuel(max));
    assert!(fee_for_fuel(max) <= fee_for_fuel(MAX_FUEL));
}

fn chain(tag: u8, n: u32) -> ChainId {
    match tag % 4 {
        0 => ChainId::Kerckhoffs,
        1 => ChainId::Atbash,
        2 => ChainId::Feistel,
        _ => ChainId::Zone(n),
    }
}

/// Chain codes are injective (no two chains share the signature domain /
/// hash code) and never overflow, for every possible zone number.
#[kani::proof]
fn chain_codes_are_unique() {
    let (a, b) = (chain(kani::any(), kani::any()), chain(kani::any(), kani::any()));
    if a.code() == b.code() {
        assert!(a == b);
    }
}

/// The wire reader never panics or reads out of bounds, whatever the input
/// bytes and length.
#[kani::proof]
#[kani::unwind(10)]
fn reader_is_memory_safe() {
    let buf: [u8; 8] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= buf.len());
    let mut r = Reader::new(&buf[..len]);
    match kani::any::<u8>() % 4 {
        0 => drop(r.u8()),
        1 => drop(r.u32()),
        2 => drop(r.u64()),
        _ => drop(r.bytes()),
    }
    let _ = r.finish();
}
