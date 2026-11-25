//! Every wire decoder must reject garbage without panicking, and anything it
//! accepts must re-encode to exactly the input (no malleable encodings).
#![no_main]
use libfuzzer_sys::fuzz_target;
use pqchain::codec::{Tx, Wire};
use pqchain::consensus::FinalityCert;
use pqchain::feistel::FeistelTx;
use pqchain::ledger::{Block, RelayIn};
use pqchain::node::Msg;

fn check<T: Wire>(data: &[u8]) {
    if let Ok(v) = T::from_bytes(data) {
        assert_eq!(v.to_bytes(), data, "decode/encode is not canonical");
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&kind, rest)) = data.split_first() else { return };
    match kind % 6 {
        0 => check::<Msg>(rest),
        1 => check::<Block>(rest),
        2 => check::<Tx>(rest),
        3 => check::<RelayIn>(rest),
        4 => check::<FeistelTx>(rest),
        _ => check::<FinalityCert>(rest),
    }
});
