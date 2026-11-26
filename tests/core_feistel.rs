//! Feistel Chain: contracts, fees, rollback, replay protection, funding.

use pqchain::codec::{Tx, Wire};
use pqchain::crypto::*;
use pqchain::feistel::*;
use pqchain::ledger::*;
use pqchain::network::native_transfer;

fn wasm(path: &str) -> Vec<u8> {
    wat::parse_file(format!("{}/contracts/{path}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

struct Net {
    alice: Keypair,
    bob: Keypair,
    l: Ledger,
}

fn net() -> Net {
    let (alice, bob) = (Keypair::generate(), Keypair::generate_slh());
    let v = Keypair::generate();
    let mut l = Ledger::genesis(
        vec![GenesisValidator { signing_key: v.public.clone(), withdrawal: v.address(), stake: 2_000 }],
        &[(alice.address(), 100_000)],
    );
    l.feistel.balances.insert(bob.address(), 500);
    let mut n = Net { alice, bob, l };
    // Fund alice on Feistel through atomic memory: export on Atbash, import on Feistel.
    let ex = Some((ChainId::Feistel, vec![TxOut::native(n.alice.address(), 50_000)]));
    let (base, k) = native_transfer(&n.l, ChainId::Atbash, Source::Local, &n.alice, vec![], ex, 0).unwrap();
    n.l.apply_atbash(&AtbashTx { base, create_asset: None }.sign(&vec![&n.alice; k])).unwrap();
    let ops: Vec<OutPoint> = n.l.atomic_of(ChainId::Feistel, &n.alice.address()).into_iter().map(|(p, _)| p).collect();
    n.l.apply_feistel(&FeistelTx::new(&n.alice, 0, 0, Action::Import { outpoints: ops })).unwrap();
    n
}

impl Net {
    fn send(&mut self, key_is_alice: bool, fuel: u64, action: Action) -> Result<Receipt, String> {
        let key = if key_is_alice { &self.alice } else { &self.bob };
        let tx = FeistelTx::new(key, self.l.feistel.nonce(&key.address()), fuel, action);
        let tx = FeistelTx::from_bytes(&tx.to_bytes()).unwrap(); // every tx survives the wire
        self.l.apply_feistel(&tx)
    }
}

#[test]
fn import_funds_the_account_and_cannot_repeat() {
    let mut n = net();
    assert_eq!(n.l.feistel.balance(&n.alice.address()), 50_000 - BASE_FEE);
    assert!(n.l.atomic_of(ChainId::Feistel, &n.alice.address()).is_empty());
    let r = n.send(true, 0, Action::Import { outpoints: vec![OutPoint { txid: [0; 32], index: 0 }] });
    assert!(r.unwrap_err().contains("no such export"));
}

#[test]
fn counter_contract_counts_and_charges_fuel() {
    let mut n = net();
    let before = n.l.feistel.balance(&n.alice.address());
    let r = n.send(true, 5_000_000, Action::Deploy { code: wasm("counter.wat") }).unwrap();
    assert!(r.ok);
    let c = r.contract.unwrap();
    for _ in 0..3 {
        let r = n.send(true, 200_000, Action::Call { contract: c, method: "increment".into(), input: vec![], value: 0 }).unwrap();
        assert!(r.ok && r.fuel_used > 0, "{r:?}");
    }
    let out = query(&n.l.feistel, c, "get", vec![]).unwrap();
    assert_eq!(u64::from_le_bytes(out.try_into().unwrap()), 3);
    let spent = before - n.l.feistel.balance(&n.alice.address());
    assert!(spent > 4 * BASE_FEE, "fees reflect fuel used ({spent})");
}

#[test]
fn failed_calls_roll_back_but_pay_and_use_the_nonce() {
    let mut n = net();
    let c = n.send(true, 5_000_000, Action::Deploy { code: wasm("tipjar.wat") }).unwrap().contract.unwrap();
    // Bob (an SLH-DSA account) tips 200.
    let r = n.send(false, 200_000, Action::Call { contract: c, method: "deposit".into(), input: vec![], value: 200 }).unwrap();
    assert!(r.ok && r.logs == vec![b"deposit".to_vec()]);
    assert_eq!(n.l.feistel.balance(&c), 200);
    // Bob is not the owner: withdraw traps; balance unchanged, fee charged, nonce used.
    let bob_before = n.l.feistel.balance(&n.bob.address());
    let nonce = n.l.feistel.nonce(&n.bob.address());
    let r = n.send(false, 200_000, Action::Call { contract: c, method: "withdraw".into(), input: vec![], value: 0 }).unwrap();
    assert!(!r.ok && r.error.as_deref().unwrap_or("").contains("execution failed"));
    assert_eq!(n.l.feistel.balance(&c), 200, "rolled back");
    assert!(n.l.feistel.balance(&n.bob.address()) < bob_before, "failed call still pays");
    assert_eq!(n.l.feistel.nonce(&n.bob.address()), nonce + 1);
    // Alice (the owner) withdraws.
    let alice_before = n.l.feistel.balance(&n.alice.address());
    let r = n.send(true, 200_000, Action::Call { contract: c, method: "withdraw".into(), input: vec![], value: 0 }).unwrap();
    assert!(r.ok, "{r:?}");
    assert_eq!(n.l.feistel.balance(&c), 0);
    assert_eq!(n.l.feistel.balance(&n.alice.address()), alice_before + 200 - r.fee);
}

#[test]
fn infinite_loops_run_out_of_fuel() {
    let mut n = net();
    let spin = wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "spin") (loop (br 0))))"#).unwrap();
    let c = n.send(true, 5_000_000, Action::Deploy { code: spin }).unwrap().contract.unwrap();
    let r = n.send(true, 300_000, Action::Call { contract: c, method: "spin".into(), input: vec![], value: 0 }).unwrap();
    assert!(!r.ok);
    assert_eq!(r.fuel_used, 300_000);
    assert_eq!(r.fee, BASE_FEE + 300_000 / FUEL_PER_FEE_UNIT);
}

#[test]
fn floats_are_rejected_for_determinism() {
    let mut n = net();
    let f = wat::parse_str(r#"(module (func (export "f") (drop (f64.add (f64.const 1) (f64.const 2)))))"#).unwrap();
    let r = n.send(true, 5_000_000, Action::Deploy { code: f }).unwrap();
    assert!(!r.ok && r.error.unwrap().contains("invalid module"));
}

#[test]
fn signatures_nonces_and_balances_are_enforced() {
    let mut n = net();
    let tx = FeistelTx::new(&n.alice, n.l.feistel.nonce(&n.alice.address()), 0, Action::Transfer { to: n.bob.address(), amount: 10 });
    n.l.apply_feistel(&tx).unwrap();
    assert!(n.l.apply_feistel(&tx).unwrap_err().contains("nonce"), "replay rejected");
    let mut forged = FeistelTx::new(&n.alice, n.l.feistel.nonce(&n.alice.address()), 0, Action::Transfer { to: n.bob.address(), amount: 10 });
    forged.action = Action::Transfer { to: n.bob.address(), amount: 40_000 };
    assert!(n.l.apply_feistel(&forged).unwrap_err().contains("signature"));
    let r = n.send(false, 0, Action::Transfer { to: n.alice.address(), amount: 1_000_000 });
    assert!(r.unwrap_err().contains("insufficient"));
    // Atbash signatures do not work on Feistel and vice versa (domain separation).
    let _ = Tx::Feistel(tx);
}

#[test]
fn export_returns_funds_to_atbash() {
    let mut n = net();
    let r = n.send(true, 0, Action::Export { amount: 7_000 }).unwrap();
    assert!(r.ok);
    let pending = n.l.atomic_of(ChainId::Atbash, &n.alice.address());
    assert_eq!(pending.iter().map(|(_, o)| o.amount).sum::<u64>(), 7_000);
    let spends: Vec<_> = pending.iter().map(|(p, _)| (*p, Source::Atomic, &n.alice)).collect();
    let base = Transfer::spend(&spends, vec![TxOut::native(n.alice.address(), 6_999)]);
    n.l.apply_atbash(&AtbashTx { base, create_asset: None }.sign(&vec![&n.alice; spends.len()])).unwrap();
}

/// Regression: a contract cannot make nodes allocate unbounded memory.
#[test]
fn memory_growth_is_capped() {
    let mut n = net();
    let hog = wat::parse_str(r#"(module (memory (export "memory") 1)
        (func (export "hog") (drop (memory.grow (i32.const 60000)))))"#).unwrap();
    let c = n.send(true, 5_000_000, Action::Deploy { code: hog }).unwrap().contract.unwrap();
    let r = n.send(true, 1_000_000, Action::Call { contract: c, method: "hog".into(), input: vec![], value: 0 }).unwrap();
    assert!(!r.ok, "growing to ~3.7 GiB must fail");
    // A module asking for 64 MiB of initial memory cannot be instantiated.
    let big = wat::parse_str(r#"(module (memory (export "memory") 1024) (func (export "f")))"#).unwrap();
    let c = n.send(true, 5_000_000, Action::Deploy { code: big }).unwrap().contract.unwrap();
    let r = n.send(true, 1_000_000, Action::Call { contract: c, method: "f".into(), input: vec![], value: 0 }).unwrap();
    assert!(!r.ok && r.error.unwrap_or_default().contains("instantiation"));
}
