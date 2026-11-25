//! Ledger snapshots for fast restarts.
//!
//! A snapshot stores the full ledger state plus the number of log records it
//! covers. On startup the node loads the latest snapshot, checks its checksum
//! and state root, then re-executes only the records written after it.
//! Snapshots are local files written atomically (temp file + rename); they are
//! never accepted from peers, so they need no extra trust.

use crate::codec::{DecodeResult, Reader, Wire, Writer};
use crate::crypto::*;
use crate::feistel::{Contract, FeistelState};
use crate::ledger::*;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

const MAGIC: &[u8; 8] = b"PQSNAP01";
const MAX_SNAPSHOT_ITEMS: u64 = 1 << 32;

fn count(r: &mut Reader) -> DecodeResult<u64> {
    let n = r.u64()?;
    if n > MAX_SNAPSHOT_ITEMS {
        return Err("snapshot list too long".into());
    }
    Ok(n)
}

fn put_utxos(w: &mut Writer, m: &BTreeMap<OutPoint, TxOut>) {
    w.u64(m.len() as u64);
    for (p, o) in m {
        p.put(w);
        o.put(w);
    }
}

fn get_utxos(r: &mut Reader) -> DecodeResult<BTreeMap<OutPoint, TxOut>> {
    let mut m = BTreeMap::new();
    for _ in 0..count(r)? {
        m.insert(OutPoint::get(r)?, TxOut::get(r)?);
    }
    Ok(m)
}

fn put_validator(w: &mut Writer, v: &Validator) {
    v.node_id.put(w);
    v.signing_key.put(w);
    v.withdrawal.put(w);
    w.u64(v.stake);
    w.u64(v.delegated);
    w.u8(v.slashed as u8);
    match v.exit_at {
        None => w.u8(0),
        Some(h) => {
            w.u8(1);
            w.u64(h);
        }
    }
}

fn get_validator(r: &mut Reader) -> DecodeResult<Validator> {
    Ok(Validator {
        node_id: Address::get(r)?,
        signing_key: PublicKey::get(r)?,
        withdrawal: Address::get(r)?,
        stake: r.u64()?,
        delegated: r.u64()?,
        slashed: r.u8()? != 0,
        exit_at: match r.u8()? {
            0 => None,
            _ => Some(r.u64()?),
        },
    })
}

fn put_set(w: &mut Writer, s: &ValidatorSet) {
    w.u64(s.len() as u64);
    for v in s.values() {
        put_validator(w, v);
    }
}

fn get_set(r: &mut Reader) -> DecodeResult<ValidatorSet> {
    let mut s = BTreeMap::new();
    for _ in 0..count(r)? {
        let v = get_validator(r)?;
        s.insert(v.node_id, v);
    }
    Ok(s)
}

fn put_amounts(w: &mut Writer, m: &BTreeMap<Address, u64>) {
    w.u64(m.len() as u64);
    for (a, n) in m {
        a.put(w);
        w.u64(*n);
    }
}

fn get_amounts(r: &mut Reader) -> DecodeResult<BTreeMap<Address, u64>> {
    let mut m = BTreeMap::new();
    for _ in 0..count(r)? {
        m.insert(Address::get(r)?, r.u64()?);
    }
    Ok(m)
}

pub fn encode(l: &Ledger, records: u64) -> Vec<u8> {
    let mut w = Writer::default();
    w.u64(records);
    put_utxos(&mut w, &l.atbash_utxos);
    put_utxos(&mut w, &l.kerckhoffs_utxos);
    w.u64(l.atomic.len() as u64);
    for ((c, p), o) in &l.atomic {
        c.put(&mut w);
        p.put(&mut w);
        o.put(&mut w);
    }
    put_set(&mut w, &l.validators);
    w.u64(l.validator_history.len() as u64);
    for (h, s) in &l.validator_history {
        w.u64(*h);
        put_set(&mut w, s);
    }
    w.u64(l.delegations.len() as u64);
    for d in &l.delegations {
        d.node.put(&mut w);
        w.u64(d.stake);
        d.reward.put(&mut w);
    }
    w.u64(l.burned);
    w.u64(l.minted);
    w.u64(l.tips.len() as u64);
    for (c, (h, hash)) in &l.tips {
        c.put(&mut w);
        w.u64(*h);
        w.fixed(hash);
        w.u64(l.anchors.get(c).copied().unwrap_or(0));
    }
    w.u64(l.zones.len() as u64);
    for z in l.zones.values() {
        w.u32(z.id);
        z.name.put(&mut w);
        w.list(&z.members);
        w.u64(z.created_at);
    }
    w.u64(l.zone_utxos.len() as u64);
    for (n, m) in &l.zone_utxos {
        w.u32(*n);
        put_utxos(&mut w, m);
    }
    w.u64(l.relay_consumed.len() as u64);
    for (c, p) in &l.relay_consumed {
        c.put(&mut w);
        p.put(&mut w);
    }
    put_amounts(&mut w, &l.rewards);
    put_amounts(&mut w, &l.claim_nonces);
    put_amounts(&mut w, &l.feistel.balances);
    put_amounts(&mut w, &l.feistel.nonces);
    w.u64(l.feistel.contracts.len() as u64);
    for (a, c) in &l.feistel.contracts {
        a.put(&mut w);
        w.u32(c.code.len() as u32);
        w.fixed(&c.code);
        w.fixed(&c.code_hash);
        c.creator.put(&mut w);
        w.u64(c.storage.len() as u64);
        for (k, v) in &c.storage {
            w.bytes(k);
            w.bytes(v);
        }
    }
    w.0
}

pub fn decode(b: &[u8]) -> DecodeResult<(Ledger, u64)> {
    let mut r = Reader::new(b);
    let records = r.u64()?;
    let mut l = Ledger { atbash_utxos: get_utxos(&mut r)?, kerckhoffs_utxos: get_utxos(&mut r)?, ..Default::default() };
    for _ in 0..count(&mut r)? {
        let c = ChainId::get(&mut r)?;
        let p = OutPoint::get(&mut r)?;
        l.atomic.insert((c, p), TxOut::get(&mut r)?);
    }
    l.validators = get_set(&mut r)?;
    for _ in 0..count(&mut r)? {
        let h = r.u64()?;
        l.validator_history.insert(h, Arc::new(get_set(&mut r)?));
    }
    for _ in 0..count(&mut r)? {
        l.delegations.push(Delegation { node: Address::get(&mut r)?, stake: r.u64()?, reward: Address::get(&mut r)? });
    }
    l.burned = r.u64()?;
    l.minted = r.u64()?;
    for _ in 0..count(&mut r)? {
        let c = ChainId::get(&mut r)?;
        l.tips.insert(c, (r.u64()?, r.hash()?));
        l.anchors.insert(c, r.u64()?);
    }
    for _ in 0..count(&mut r)? {
        let id = r.u32()?;
        let z = Zone { id, name: String::get(&mut r)?, members: r.list()?, created_at: r.u64()? };
        l.zones.insert(id, z);
    }
    for _ in 0..count(&mut r)? {
        let n = r.u32()?;
        l.zone_utxos.insert(n, get_utxos(&mut r)?);
    }
    for _ in 0..count(&mut r)? {
        l.relay_consumed.insert((ChainId::get(&mut r)?, OutPoint::get(&mut r)?));
    }
    l.rewards = get_amounts(&mut r)?;
    l.claim_nonces = get_amounts(&mut r)?;
    let mut f = FeistelState { balances: get_amounts(&mut r)?, nonces: get_amounts(&mut r)?, ..Default::default() };
    for _ in 0..count(&mut r)? {
        let a = Address::get(&mut r)?;
        let n = r.u32()? as usize;
        let code: Vec<u8> = (0..n).map(|_| r.u8()).collect::<Result<_, _>>()?;
        let code_hash = r.hash()?;
        let creator = Address::get(&mut r)?;
        let mut storage = BTreeMap::new();
        for _ in 0..count(&mut r)? {
            storage.insert(r.bytes()?, r.bytes()?);
        }
        f.contracts.insert(a, Contract { code, code_hash, creator, storage });
    }
    l.feistel = f;
    r.finish()?;
    Ok((l, records))
}

/// Write `snapshot.bin` atomically: magic | state root | payload | SHA3 checksum.
pub fn save(dir: &Path, l: &Ledger, records: u64) -> Result<(), String> {
    let payload = encode(l, records);
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&l.state_root());
    out.extend_from_slice(&payload);
    out.extend_from_slice(&sha3_256(&payload));
    let tmp = dir.join("snapshot.bin.tmp");
    std::fs::write(&tmp, &out).map_err(|e| e.to_string())?;
    std::fs::File::open(&tmp).and_then(|f| f.sync_all()).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, dir.join("snapshot.bin")).map_err(|e| e.to_string())
}

/// Load and verify `snapshot.bin`; `Ok(None)` if there is none.
pub fn load(dir: &Path) -> Result<Option<(Ledger, u64)>, String> {
    let Ok(b) = std::fs::read(dir.join("snapshot.bin")) else { return Ok(None) };
    if b.len() < 8 + 32 + 32 || &b[..8] != MAGIC {
        return Err("snapshot.bin: bad header".into());
    }
    let root: Hash = b[8..40].try_into().unwrap();
    let (payload, sum) = b[40..].split_at(b.len() - 40 - 32);
    if sha3_256(payload) != sum {
        return Err("snapshot.bin: checksum mismatch".into());
    }
    let (l, records) = decode(payload)?;
    if l.state_root() != root {
        return Err("snapshot.bin: state root mismatch".into());
    }
    Ok(Some((l, records)))
}
