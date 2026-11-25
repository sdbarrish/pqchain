//! Arbitrary (valid) WebAssembly contracts: deployment and calls must never
//! panic the node, must stay within the fuel limit, and must be deterministic.
#![no_main]
use arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use pqchain::crypto::*;
use pqchain::feistel::{Action, FeistelTx};
use pqchain::ledger::*;
use std::sync::OnceLock;

fn base() -> &'static (Keypair, Ledger) {
    static B: OnceLock<(Keypair, Ledger)> = OnceLock::new();
    B.get_or_init(|| {
        let alice = Keypair::from_seed([42; 32]);
        let v = Keypair::from_seed([1; 32]);
        let mut l = Ledger::genesis(
            vec![GenesisValidator { signing_key: v.public.clone(), withdrawal: v.address(), stake: 2_000 }],
            &[],
        );
        l.feistel.balances.insert(alice.address(), 1_000_000_000);
        (alice, l)
    })
}

fn run(code: &[u8], methods: &[String]) -> (Hash, Vec<(bool, u64)>) {
    let (alice, l0) = base();
    let mut l = l0.clone();
    let mut out = Vec::new();
    let fuel = 2_000_000;
    let r = l.apply_feistel(&FeistelTx::new(alice, 0, fuel, Action::Deploy { code: code.to_vec() })).unwrap();
    assert!(r.fuel_used <= fuel);
    out.push((r.ok, r.fuel_used));
    if let Some(contract) = r.contract {
        for (i, m) in methods.iter().enumerate() {
            let tx = FeistelTx::new(alice, 1 + i as u64, fuel, Action::Call { contract, method: m.clone(), input: vec![1, 2, 3], value: 0 });
            let r = l.apply_feistel(&tx).unwrap();
            assert!(r.fuel_used <= fuel, "fuel limit exceeded");
            out.push((r.ok, r.fuel_used));
        }
    }
    (l.state_root(), out)
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let mut cfg = wasm_smith::Config::default();
    cfg.max_imports = 0;
    cfg.export_everything = true;
    cfg.min_memories = 1;
    cfg.max_memories = 1;
    cfg.max_memory32_bytes = 1 << 20;
    cfg.max_funcs = 8;
    cfg.max_instructions = 200;
    cfg.simd_enabled = false;
    cfg.threads_enabled = false;
    let Ok(module) = wasm_smith::Module::new(cfg, &mut u) else { return };
    let code = module.to_bytes();
    let methods: Vec<String> = (0..4).map(|i| format!("{i}")).chain(["memory".to_string(), "init".to_string()]).collect();
    let a = run(&code, &methods);
    let b = run(&code, &methods);
    assert_eq!(a, b, "contract execution is not deterministic");
});
