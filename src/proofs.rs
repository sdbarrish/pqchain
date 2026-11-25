//! Kani proof harnesses: properties checked for *every* input, not samples.
//! Run with `cargo kani`. Each harness is a bounded model-checking proof.

use crate::codec::Reader;
use crate::feistel::{fee_for_fuel, MAX_FUEL};
use crate::ledger::{reward_shares, split_validator_reward, ChainId, BLOCK_REWARD};

/// Rewards never exceed issuance: for any three validator weights, the
/// per-validator shares sum to at most BLOCK_REWARD.
#[kani::proof]
#[kani::unwind(5)]
fn reward_shares_never_exceed_block_reward() {
    let w: [u64; 3] = kani::any();
    let shares = reward_shares(&w);
    let sum: u128 = shares.iter().sum();
    assert!(sum <= BLOCK_REWARD as u128);
    for s in shares {
        assert!(s <= BLOCK_REWARD as u128);
    }
}

/// A validator's split (own stake + commission + two delegators) never pays
/// more than its share and never overflows, for any stake and delegation sizes.
#[kani::proof]
#[kani::unwind(4)]
fn validator_split_never_exceeds_share() {
    let share: u128 = kani::any();
    kani::assume(share <= BLOCK_REWARD as u128);
    let stake: u64 = kani::any();
    let delegated: u64 = kani::any();
    let weight = stake.saturating_add(delegated);
    let d: [u64; 2] = kani::any();
    let (mine, parts) = split_validator_reward(share, stake.min(weight), weight, &d);
    let paid: u128 = mine + parts.iter().sum::<u128>();
    assert!(paid <= share);
}

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
