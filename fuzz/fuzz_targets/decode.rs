//! Every wire decoder must reject garbage without panicking, and anything it
//! accepts must re-encode to exactly the input (no malleable encodings).
#![no_main]
use libfuzzer_sys::fuzz_target;
use pqchain::codec::{Tx, Wire};
use pqchain::consensus::FinalityCert;
use pqchain::feistel::FeistelTx;
use pqchain::hamming::InclusionProof;
use pqchain::ledger::{BlobTx, Block, PlayfairTx, RelayIn};
use pqchain::playfair::BridgeProof;
use pqchain::node::Msg;

fn check<T: Wire>(data: &[u8]) {
    if let Ok(v) = T::from_bytes(data) {
        assert_eq!(v.to_bytes(), data, "decode/encode is not canonical");
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&kind, rest)) = data.split_first() else { return };
    match kind % 10 {
        8 => check::<PlayfairTx>(rest),
        9 => check::<BridgeProof>(rest),
        0 => check::<Msg>(rest),
        1 => check::<Block>(rest),
        2 => check::<Tx>(rest),
        3 => check::<RelayIn>(rest),
        4 => check::<FeistelTx>(rest),
        5 => check::<BlobTx>(rest),
        6 => check::<InclusionProof>(rest),
        _ => check::<FinalityCert>(rest),
    }
});
