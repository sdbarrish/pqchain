//! Feistel Chain: account-based smart contracts with post-quantum accounts.
//!
//! * Accounts are addresses of ML-DSA-65 or SLH-DSA keys; every transaction
//!   is signed and carries a nonce (no replay).
//! * Contracts are WebAssembly modules run by `wasmi`, a deterministic
//!   interpreter, with fuel metering and floating point disabled.
//! * Fees: BASE_FEE + fuel used / FUEL_PER_FEE_UNIT, burned. A failed call is
//!   rolled back but still pays its fee and consumes its nonce.
//! * Value enters from the Atbash Chain through atomic memory (`Import`) and
//!   leaves the same way (`Export`).
//!
//! Host API (WebAssembly imports from module "env"):
//! `storage_read(key_ptr, key_len, out_ptr, out_cap) -> i32` (length, or -1 if absent),
//! `storage_write(key_ptr, key_len, val_ptr, val_len)`, `caller(out_ptr)` (32 bytes),
//! `self_address(out_ptr)`, `value() -> i64`, `balance() -> i64`, `input_len() -> i32`,
//! `input(out_ptr)`, `output(ptr, len)`, `log(ptr, len)`,
//! `transfer(to_ptr, amount) -> i32` (0 = ok, 1 = insufficient balance).
//! A contract exports `memory` and one function per method (no params, no
//! results); an optional `init` runs at deployment.

use crate::crypto::*;
use std::collections::BTreeMap;
use wasmi::{Caller, Config, Engine, Extern, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};

pub const BASE_FEE: u64 = 1;
pub const FUEL_PER_FEE_UNIT: u64 = 10_000;
pub const MAX_FUEL: u64 = 50_000_000;
pub const MAX_CODE: usize = 256 * 1024;
pub const DEPLOY_FUEL_PER_BYTE: u64 = 50;
const STORAGE_WRITE_FUEL: u64 = 5_000;
const STORAGE_BYTE_FUEL: u64 = 20;
const HOST_CALL_FUEL: u64 = 100;
const MAX_KEY: usize = 128;
const MAX_VALUE: usize = 16 * 1024;
const MAX_IO: usize = 64 * 1024;
const MAX_LOGS: usize = 64;
/// Linear memory a contract may use (initial + grown). Without a cap a
/// contract could make every node allocate up to 4 GiB.
pub const MAX_MEMORY: usize = 16 * 1024 * 1024;
const MAX_TABLE_ELEMENTS: usize = 10_000;

#[derive(Clone, Debug)]
pub struct Contract {
    pub code: Vec<u8>,
    pub code_hash: Hash,
    pub creator: Address,
    pub storage: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// Feistel Chain state (part of the replicated ledger).
#[derive(Clone, Debug, Default)]
pub struct FeistelState {
    pub balances: BTreeMap<Address, u64>,
    pub nonces: BTreeMap<Address, u64>,
    pub contracts: BTreeMap<Address, Contract>,
}

impl FeistelState {
    pub fn balance(&self, a: &Address) -> u64 {
        self.balances.get(a).copied().unwrap_or(0)
    }
    pub fn nonce(&self, a: &Address) -> u64 {
        self.nonces.get(a).copied().unwrap_or(0)
    }
    pub(crate) fn credit_pub(&mut self, a: Address, amount: u64) {
        self.credit(a, amount)
    }
    pub(crate) fn debit_pub(&mut self, a: &Address, amount: u64) -> Result<(), String> {
        self.debit(a, amount)
    }
    fn credit(&mut self, a: Address, amount: u64) {
        *self.balances.entry(a).or_default() += amount;
    }
    fn debit(&mut self, a: &Address, amount: u64) -> Result<(), String> {
        let b = self.balances.get_mut(a).filter(|b| **b >= amount).ok_or("insufficient balance")?;
        *b -= amount;
        Ok(())
    }

    pub fn encode(&self, e: &mut Enc) {
        e.u64(self.balances.len() as u64);
        for (a, b) in &self.balances {
            e.bytes(&a.0).u64(*b);
        }
        for (a, n) in &self.nonces {
            e.bytes(&a.0).u64(*n);
        }
        for (a, c) in &self.contracts {
            e.bytes(&a.0).bytes(&c.code_hash).bytes(&c.creator.0).u64(c.storage.len() as u64);
            for (k, v) in &c.storage {
                e.bytes(k).bytes(v);
            }
        }
    }
}

/// Fee for a given amount of fuel. Monotonic, so a transaction never pays
/// more than its declared maximum (proved with Kani for all fuel <= MAX_FUEL).
pub fn fee_for_fuel(fuel: u64) -> u64 {
    BASE_FEE + fuel.div_ceil(FUEL_PER_FEE_UNIT)
}

pub fn contract_address(creator: &Address, nonce: u64) -> Address {
    Address(Enc::new("pqchain/feistel/contract").bytes(&creator.0).u64(nonce).hash())
}

#[derive(Clone, Debug)]
pub enum Action {
    Deploy { code: Vec<u8> },
    Call { contract: Address, method: String, input: Vec<u8>, value: u64 },
    Transfer { to: Address, amount: u64 },
    /// Claim native tokens exported to the Feistel Chain (atomic memory) for the sender.
    Import { outpoints: Vec<crate::ledger::OutPoint> },
    /// Send native tokens back to the sender's address on the Atbash Chain.
    Export { amount: u64 },
}

#[derive(Clone, Debug)]
pub struct FeistelTx {
    pub from: PublicKey,
    pub nonce: u64,
    pub max_fuel: u64,
    pub action: Action,
    pub sig: Signature,
}

impl FeistelTx {
    pub fn id(&self) -> Hash {
        let mut e = Enc::new("pqchain/feistel-tx");
        e.u8(self.from.alg).bytes(&self.from.bytes).u64(self.nonce).u64(self.max_fuel);
        match &self.action {
            Action::Deploy { code } => e.u8(0).bytes(code),
            Action::Call { contract, method, input, value } => {
                e.u8(1).bytes(&contract.0).bytes(method.as_bytes()).bytes(input).u64(*value)
            }
            Action::Transfer { to, amount } => e.u8(2).bytes(&to.0).u64(*amount),
            Action::Import { outpoints } => {
                e.u8(3).u64(outpoints.len() as u64);
                for p in outpoints {
                    e.bytes(&p.txid).u64(p.index as u64);
                }
                &mut e
            }
            Action::Export { amount } => e.u8(4).u64(*amount),
        };
        e.hash()
    }

    pub fn new(key: &Keypair, nonce: u64, max_fuel: u64, action: Action) -> Self {
        let mut tx = FeistelTx { from: key.public.clone(), nonce, max_fuel, action, sig: Signature::empty() };
        tx.sig = key.sign(ctx::FEISTEL_TX, &tx.id());
        tx
    }

    pub fn sender(&self) -> Address {
        self.from.address()
    }

    pub fn max_fee(&self) -> u64 {
        fee_for_fuel(self.max_fuel)
    }
}

/// Outcome of a Feistel transaction (not part of consensus state).
#[derive(Clone, Debug, Default)]
pub struct Receipt {
    pub ok: bool,
    pub fuel_used: u64,
    pub fee: u64,
    pub output: Vec<u8>,
    pub logs: Vec<Vec<u8>>,
    pub error: Option<String>,
    pub contract: Option<Address>,
}

// ───────────────────────────── execution ─────────────────────────────

struct Host {
    caller: Address,
    contract: Address,
    value: u64,
    balance: u64,
    input: Vec<u8>,
    output: Vec<u8>,
    logs: Vec<Vec<u8>>,
    storage: BTreeMap<Vec<u8>, Vec<u8>>,
    transfers: Vec<(Address, u64)>,
    limits: StoreLimits,
}

type HostResult<T> = Result<T, wasmi::Error>;

fn trap(msg: &str) -> wasmi::Error {
    wasmi::Error::new(msg.to_string())
}

fn charge(c: &mut Caller<'_, Host>, fuel: u64) -> HostResult<()> {
    let left = c.get_fuel()?;
    if left < fuel {
        return Err(trap("out of fuel"));
    }
    c.set_fuel(left - fuel)
}

fn read_mem(c: &Caller<'_, Host>, ptr: i32, len: i32, max: usize) -> HostResult<Vec<u8>> {
    let len = usize::try_from(len).map_err(|_| trap("negative length"))?;
    if len > max {
        return Err(trap("buffer too large"));
    }
    let mem = c.get_export("memory").and_then(Extern::into_memory).ok_or(trap("contract exports no memory"))?;
    let mut buf = vec![0u8; len];
    mem.read(c, ptr as u32 as usize, &mut buf).map_err(|_| trap("memory read out of bounds"))?;
    Ok(buf)
}

fn write_mem(c: &mut Caller<'_, Host>, ptr: i32, data: &[u8]) -> HostResult<()> {
    let mem = c.get_export("memory").and_then(Extern::into_memory).ok_or(trap("contract exports no memory"))?;
    mem.write(c, ptr as u32 as usize, data).map_err(|_| trap("memory write out of bounds"))
}

fn linker(engine: &Engine) -> Result<Linker<Host>, String> {
    let mut l = Linker::<Host>::new(engine);
    let e = |r: Result<&mut Linker<Host>, wasmi::errors::LinkerError>| r.map(|_| ()).map_err(|e| e.to_string());
    e(l.func_wrap("env", "storage_read", |mut c: Caller<'_, Host>, kp: i32, kl: i32, op: i32, cap: i32| -> HostResult<i32> {
        charge(&mut c, HOST_CALL_FUEL)?;
        let key = read_mem(&c, kp, kl, MAX_KEY)?;
        let Some(v) = c.data().storage.get(&key).cloned() else { return Ok(-1) };
        let n = v.len().min(usize::try_from(cap).unwrap_or(0));
        write_mem(&mut c, op, &v[..n])?;
        Ok(v.len() as i32)
    }))?;
    e(l.func_wrap("env", "storage_write", |mut c: Caller<'_, Host>, kp: i32, kl: i32, vp: i32, vl: i32| -> HostResult<()> {
        let key = read_mem(&c, kp, kl, MAX_KEY)?;
        let val = read_mem(&c, vp, vl, MAX_VALUE)?;
        charge(&mut c, STORAGE_WRITE_FUEL + STORAGE_BYTE_FUEL * (key.len() + val.len()) as u64)?;
        c.data_mut().storage.insert(key, val);
        Ok(())
    }))?;
    e(l.func_wrap("env", "caller", |mut c: Caller<'_, Host>, op: i32| -> HostResult<()> {
        charge(&mut c, HOST_CALL_FUEL)?;
        let a = c.data().caller.0;
        write_mem(&mut c, op, &a)
    }))?;
    e(l.func_wrap("env", "self_address", |mut c: Caller<'_, Host>, op: i32| -> HostResult<()> {
        charge(&mut c, HOST_CALL_FUEL)?;
        let a = c.data().contract.0;
        write_mem(&mut c, op, &a)
    }))?;
    e(l.func_wrap("env", "value", |c: Caller<'_, Host>| -> i64 { c.data().value as i64 }))?;
    e(l.func_wrap("env", "balance", |c: Caller<'_, Host>| -> i64 { c.data().balance as i64 }))?;
    e(l.func_wrap("env", "input_len", |c: Caller<'_, Host>| -> i32 { c.data().input.len() as i32 }))?;
    e(l.func_wrap("env", "input", |mut c: Caller<'_, Host>, op: i32| -> HostResult<()> {
        charge(&mut c, HOST_CALL_FUEL)?;
        let i = c.data().input.clone();
        write_mem(&mut c, op, &i)
    }))?;
    e(l.func_wrap("env", "output", |mut c: Caller<'_, Host>, p: i32, n: i32| -> HostResult<()> {
        charge(&mut c, HOST_CALL_FUEL)?;
        let o = read_mem(&c, p, n, MAX_IO)?;
        c.data_mut().output = o;
        Ok(())
    }))?;
    e(l.func_wrap("env", "log", |mut c: Caller<'_, Host>, p: i32, n: i32| -> HostResult<()> {
        charge(&mut c, HOST_CALL_FUEL)?;
        let m = read_mem(&c, p, n, MAX_IO)?;
        if c.data().logs.len() >= MAX_LOGS {
            return Err(trap("too many logs"));
        }
        c.data_mut().logs.push(m);
        Ok(())
    }))?;
    e(l.func_wrap("env", "transfer", |mut c: Caller<'_, Host>, tp: i32, amount: i64| -> HostResult<i32> {
        charge(&mut c, HOST_CALL_FUEL)?;
        let to = Address(read_mem(&c, tp, 32, 32)?.try_into().unwrap());
        let amount = u64::try_from(amount).map_err(|_| trap("negative amount"))?;
        let h = c.data_mut();
        if amount > h.balance {
            return Ok(1);
        }
        h.balance -= amount;
        h.transfers.push((to, amount));
        Ok(0)
    }))?;
    Ok(l)
}

fn engine() -> Engine {
    let mut cfg = Config::default();
    cfg.consume_fuel(true);
    cfg.floats(false); // floating point is a determinism hazard; contracts may not use it
    Engine::new(&cfg)
}

/// Run `method` of `contract` against `st`. On success the contract's storage,
/// balance and outgoing transfers are applied to `st`.
fn run(
    st: &mut FeistelState,
    contract: Address,
    method: &str,
    input: Vec<u8>,
    caller: Address,
    value: u64,
    fuel: u64,
) -> Result<(Vec<u8>, Vec<Vec<u8>>, u64), (String, u64)> {
    let c = st.contracts.get(&contract).ok_or(("no contract at this address".to_string(), 0))?;
    let engine = engine();
    let module = Module::new(&engine, &c.code).map_err(|e| (format!("invalid module: {e}"), 0))?;
    let host = Host {
        caller,
        contract,
        value,
        balance: st.balance(&contract),
        input,
        output: Vec::new(),
        logs: Vec::new(),
        storage: c.storage.clone(),
        transfers: Vec::new(),
        limits: StoreLimitsBuilder::new()
            .memory_size(MAX_MEMORY)
            .memories(1)
            .tables(1)
            .table_elements(MAX_TABLE_ELEMENTS)
            .instances(1)
            .trap_on_grow_failure(true)
            .build(),
    };
    let mut store = Store::new(&engine, host);
    store.limiter(|h| &mut h.limits);
    store.set_fuel(fuel).map_err(|e| (e.to_string(), 0))?;
    let used = |s: &Store<Host>| fuel - s.get_fuel().unwrap_or(0);
    let linker = linker(&engine).map_err(|e| (e, 0))?;
    let instance = linker
        .instantiate_and_start(&mut store, &module)
        .map_err(|e| (format!("instantiation failed: {e}"), used(&store)))?;
    let f = instance
        .get_typed_func::<(), ()>(&store, method)
        .map_err(|_| (format!("contract has no method '{method}'"), used(&store)))?;
    f.call(&mut store, ()).map_err(|e| (format!("execution failed: {e}"), used(&store)))?;
    let fuel_used = used(&store);
    let h = store.into_data();
    st.contracts.get_mut(&contract).unwrap().storage = h.storage;
    st.balances.insert(contract, h.balance);
    for (to, amount) in h.transfers {
        st.credit(to, amount);
    }
    Ok((h.output, h.logs, fuel_used))
}

/// Read-only call: runs on a copy of the state and returns the output.
/// Fuel available to a read-only query (much lower than MAX_FUEL: queries
/// are free and reachable over RPC).
pub const QUERY_FUEL: u64 = 2_000_000;

pub fn query(st: &FeistelState, contract: Address, method: &str, input: Vec<u8>) -> Result<Vec<u8>, String> {
    let mut scratch = st.clone();
    run(&mut scratch, contract, method, input, Address([0; 32]), 0, QUERY_FUEL).map(|r| r.0).map_err(|e| e.0)
}

/// Execute an action on `st` (a scratch copy). Returns receipt fields on
/// success, or (error, fuel used) on failure.
pub(crate) fn execute(
    st: &mut FeistelState,
    tx: &FeistelTx,
    sender: Address,
) -> Result<(Vec<u8>, Vec<Vec<u8>>, u64, Option<Address>), (String, u64)> {
    match &tx.action {
        Action::Transfer { to, amount } => {
            st.debit(&sender, *amount).map_err(|e| (e, 0))?;
            st.credit(*to, *amount);
            Ok((Vec::new(), Vec::new(), 0, None))
        }
        Action::Deploy { code } => {
            if code.len() > MAX_CODE {
                return Err(("contract too large".into(), 0));
            }
            let deploy_fuel = DEPLOY_FUEL_PER_BYTE * code.len() as u64;
            if deploy_fuel > tx.max_fuel {
                return Err(("out of fuel (deployment)".into(), tx.max_fuel));
            }
            Module::new(&engine(), code).map_err(|e| (format!("invalid module: {e}"), deploy_fuel))?;
            let addr = contract_address(&sender, tx.nonce);
            st.contracts.insert(
                addr,
                Contract { code: code.clone(), code_hash: sha3_256(code), creator: sender, storage: BTreeMap::new() },
            );
            let has_init = Module::new(&engine(), code)
                .map(|m| m.exports().any(|e| e.name() == "init"))
                .unwrap_or(false);
            if has_init {
                let (out, logs, f) = run(st, addr, "init", Vec::new(), sender, 0, tx.max_fuel - deploy_fuel)
                    .map_err(|(e, f)| (e, deploy_fuel + f))?;
                return Ok((out, logs, deploy_fuel + f, Some(addr)));
            }
            Ok((Vec::new(), Vec::new(), deploy_fuel, Some(addr)))
        }
        Action::Call { contract, method, input, value } => {
            if method == "init" || method == "memory" {
                return Err(("method is not callable".into(), 0));
            }
            st.debit(&sender, *value).map_err(|e| (e, 0))?;
            st.credit(*contract, *value);
            let (o, l, f) = run(st, *contract, method, input.clone(), sender, *value, tx.max_fuel)?;
            Ok((o, l, f, None))
        }
        Action::Import { .. } | Action::Export { .. } => unreachable!("handled by the ledger"),
    }
}
