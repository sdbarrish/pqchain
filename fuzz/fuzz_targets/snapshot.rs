//! The snapshot decoder must not panic; accepted snapshots must round-trip.
#![no_main]
use libfuzzer_sys::fuzz_target;
use pqchain::snapshot;

fuzz_target!(|data: &[u8]| {
    if let Ok((l, records)) = snapshot::decode(data) {
        assert_eq!(snapshot::encode(&l, records), data, "snapshot encoding is not canonical");
    }
});
