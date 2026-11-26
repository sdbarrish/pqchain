//! K1: key files encrypted at rest.

use pqchain::crypto::Keypair;
use pqchain::node::{key_is_encrypted, load_key_with, save_key_with, KeyFile};
use std::path::PathBuf;

fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("pqchain-keys-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn encrypted_keys_round_trip_and_hide_the_seed() {
    let d = dir("rt");
    for k in [Keypair::generate(), Keypair::generate_slh()] {
        let p = d.join(format!("{}.key", k.alg()));
        save_key_with(&p, &k, Some("correct horse battery staple"), false).unwrap();
        assert!(key_is_encrypted(&p).unwrap());
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(!text.contains(&hex::encode(k.seed())), "seed must not appear in the file");
        let back = load_key_with(&p, Some("correct horse battery staple")).unwrap();
        assert_eq!(back.public, k.public);
        assert!(load_key_with(&p, Some("wrong")).err().unwrap().contains("wrong passphrase"));
        assert!(load_key_with(&p, None).err().unwrap().contains("PQCHAIN_PASSPHRASE"));
    }
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn tampering_and_swapping_are_detected() {
    let d = dir("tamper");
    let (a, b) = (Keypair::generate(), Keypair::generate());
    let (pa, pb) = (d.join("a.key"), d.join("b.key"));
    save_key_with(&pa, &a, Some("pw"), false).unwrap();
    save_key_with(&pb, &b, Some("pw"), false).unwrap();
    // Flip a ciphertext bit.
    let mut f: KeyFile = serde_json::from_str(&std::fs::read_to_string(&pa).unwrap()).unwrap();
    let mut ct = hex::decode(&f.encrypted.as_ref().unwrap().ciphertext).unwrap();
    ct[0] ^= 1;
    f.encrypted.as_mut().unwrap().ciphertext = hex::encode(ct);
    std::fs::write(&pa, serde_json::to_string(&f).unwrap()).unwrap();
    assert!(load_key_with(&pa, Some("pw")).is_err());
    // Move b's ciphertext under a's address: the address is bound as associated data.
    let fb: KeyFile = serde_json::from_str(&std::fs::read_to_string(&pb).unwrap()).unwrap();
    let mut swapped: KeyFile = serde_json::from_str(&std::fs::read_to_string(&pb).unwrap()).unwrap();
    swapped.address = a.address().to_text();
    swapped.encrypted = fb.encrypted.clone();
    std::fs::write(&pa, serde_json::to_string(&swapped).unwrap()).unwrap();
    assert!(load_key_with(&pa, Some("pw")).is_err());
    // Hostile KDF parameters are refused instead of allocating huge memory.
    let mut hostile: KeyFile = serde_json::from_str(&std::fs::read_to_string(&pb).unwrap()).unwrap();
    hostile.encrypted.as_mut().unwrap().m_cost_kib = u32::MAX;
    std::fs::write(&pb, serde_json::to_string(&hostile).unwrap()).unwrap();
    assert!(load_key_with(&pb, Some("pw")).err().unwrap().contains("excessive"));
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn plaintext_files_still_load_and_can_be_encrypted_in_place() {
    let d = dir("legacy");
    let k = Keypair::generate();
    let p = d.join("k.key");
    save_key_with(&p, &k, None, false).unwrap();
    assert!(!key_is_encrypted(&p).unwrap());
    assert_eq!(load_key_with(&p, None).unwrap().public, k.public);
    save_key_with(&p, &k, Some("pw"), true).unwrap();
    assert!(key_is_encrypted(&p).unwrap());
    assert_eq!(load_key_with(&p, Some("pw")).unwrap().public, k.public);
    std::fs::remove_dir_all(&d).unwrap();
}
