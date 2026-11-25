//! Wallet: builds and signs transactions locally (keys never leave the
//! machine) and talks to a node over RPC.

use crate::codec::{Tx, Wire};
use crate::crypto::*;
use crate::ledger::*;
use crate::network::native_transfer_from_pool;
use crate::node::chain_slug;
use serde_json::Value;

pub struct Client {
    base: String,
}

fn hash_from_hex(s: &str) -> Result<Hash, String> {
    hex::decode(s).map_err(|e| e.to_string())?.try_into().map_err(|_| "expected 32-byte hex".to_string())
}

impl Client {
    pub fn new(base: &str) -> Self {
        Client { base: base.trim_end_matches('/').to_string() }
    }

    pub fn get(&self, path: &str) -> Result<Value, String> {
        let url = format!("{}{path}", self.base);
        match ureq::get(&url).call() {
            Ok(r) => serde_json::from_str(&r.into_string().map_err(|e| e.to_string())?).map_err(|e| e.to_string()),
            Err(ureq::Error::Status(_, r)) => Err(r.into_string().unwrap_or_default()),
            Err(e) => Err(format!("{url}: {e}")),
        }
    }

    pub fn submit(&self, tx: &Tx) -> Result<Value, String> {
        let url = format!("{}/tx", self.base);
        match ureq::post(&url).send_string(&hex::encode(tx.to_bytes())) {
            Ok(r) => serde_json::from_str(&r.into_string().map_err(|e| e.to_string())?).map_err(|e| e.to_string()),
            Err(ureq::Error::Status(_, r)) => Err(r.into_string().unwrap_or_default()),
            Err(e) => Err(format!("{url}: {e}")),
        }
    }

    fn outputs(&self, kind: &str, chain: ChainId, a: &Address) -> Result<Vec<(OutPoint, TxOut)>, String> {
        let v = self.get(&format!("/{kind}/{}/{}", chain_slug(chain), a.to_text()))?;
        let arr = v.as_array().ok_or("unexpected RPC reply")?;
        arr.iter()
            .map(|u| {
                let s = |k: &str| u[k].as_str().ok_or(format!("missing {k}"));
                let n = |k: &str| u[k].as_u64().ok_or(format!("missing {k}"));
                Ok((
                    OutPoint { txid: hash_from_hex(s("txid")?)?, index: n("index")? as u32 },
                    TxOut { owner: Address::from_text(s("owner")?)?, asset: hash_from_hex(s("asset")?)?, amount: n("amount")? },
                ))
            })
            .collect()
    }

    pub fn utxos(&self, chain: ChainId, a: &Address) -> Result<Vec<(OutPoint, TxOut)>, String> {
        self.outputs("utxos", chain, a)
    }

    pub fn atomic(&self, chain: ChainId, a: &Address) -> Result<Vec<(OutPoint, TxOut)>, String> {
        self.outputs("atomic", chain, a)
    }
}

fn native_only(v: Vec<(OutPoint, TxOut)>) -> Vec<(OutPoint, TxOut)> {
    v.into_iter().filter(|(_, o)| o.asset == NATIVE).collect()
}

fn wrap(chain: ChainId, base: Transfer, kind: KerckhoffsKind, n: usize, key: &Keypair) -> Tx {
    match chain {
        ChainId::Kerckhoffs => Tx::Kerckhoffs(KerckhoffsTx { base, kind }.sign(&vec![key; n])),
        _ => Tx::Utxo(chain, AtbashTx { base, create_asset: None }.sign_for(chain, &vec![key; n])),
    }
}

/// Register a zone validated by `members` (primary validator node ids).
pub fn create_zone(c: &Client, key: &Keypair, name: &str, members: Vec<Address>) -> Result<Tx, String> {
    let pool = native_only(c.utxos(ChainId::Kerckhoffs, &key.address())?);
    let (base, n) = native_transfer_from_pool(pool, Source::Local, key, vec![], None, ZONE_FEE - TX_FEE)?;
    let kind = KerckhoffsKind::CreateZone { name: name.into(), members };
    Ok(wrap(ChainId::Kerckhoffs, base, kind, n, key))
}

/// Claim every relay message addressed to this wallet on `chain`. Each
/// input carries its own proof, which the receiving chain verifies against
/// the source chain's validator set.
pub fn relay_import(c: &Client, key: &Keypair, chain: ChainId) -> Result<(Tx, u64), String> {
    if chain == ChainId::Kerckhoffs {
        return Err("relay messages go to the Atbash Chain or zones".into());
    }
    let v = c.get(&format!("/inbox/{}/{}", chain_slug(chain), key.address().to_text()))?;
    let items = v.as_array().ok_or("unexpected RPC reply")?;
    let proofs: Vec<RelayIn> = items
        .iter()
        .map(|i| RelayIn::from_bytes(&hex::decode(i["proof"].as_str().unwrap_or("")).map_err(|e| e.to_string())?))
        .collect::<Result<_, _>>()?;
    let proofs: Vec<RelayIn> = proofs.into_iter().filter(|p| p.msg.out.asset == NATIVE).collect();
    let total: u64 = proofs.iter().map(|p| p.msg.out.amount).sum();
    if total <= TX_FEE {
        return Err("no relay messages to claim".into());
    }
    let spends: Vec<_> = proofs.iter().map(|p| (p.msg.outpoint(), Source::Relay, key)).collect();
    let mut base = Transfer::spend(&spends, vec![TxOut::native(key.address(), total - TX_FEE)]);
    base.relay_in = proofs;
    let n = spends.len();
    Ok((Tx::Utxo(chain, AtbashTx { base, create_asset: None }.sign_for(chain, &vec![key; n])), total - TX_FEE))
}

/// Plain payment on either chain.
pub fn send(c: &Client, key: &Keypair, chain: ChainId, to: Address, amount: u64) -> Result<Tx, String> {
    let pool = native_only(c.utxos(chain, &key.address())?);
    let (base, n) = native_transfer_from_pool(pool, Source::Local, key, vec![TxOut::native(to, amount)], None, 0)?;
    Ok(wrap(chain, base, KerckhoffsKind::Transfer, n, key))
}

/// Move `amount` from `from` chain to the same owner on `to` chain (step 1 of 2).
pub fn export(c: &Client, key: &Keypair, from: ChainId, to: ChainId, amount: u64) -> Result<Tx, String> {
    let pool = native_only(c.utxos(from, &key.address())?);
    let exp = Some((to, vec![TxOut::native(key.address(), amount)]));
    let (base, n) = native_transfer_from_pool(pool, Source::Local, key, vec![], exp, 0)?;
    Ok(wrap(from, base, KerckhoffsKind::Transfer, n, key))
}

/// Claim everything exported to `chain` (step 2 of 2).
pub fn import(c: &Client, key: &Keypair, chain: ChainId) -> Result<Tx, String> {
    let pool = native_only(c.atomic(chain, &key.address())?);
    let total: u64 = pool.iter().map(|(_, o)| o.amount).sum();
    if total <= TX_FEE {
        return Err("nothing to import".into());
    }
    let spends: Vec<_> = pool.iter().map(|(p, _)| (*p, Source::Atomic, key)).collect();
    let base = Transfer::spend(&spends, vec![TxOut::native(key.address(), total - TX_FEE)]);
    Ok(wrap(chain, base, KerckhoffsKind::Transfer, spends.len(), key))
}

/// Register a new validator whose block-signing key is `node_key`; the
/// wallet address becomes the withdrawal address.
pub fn stake(c: &Client, key: &Keypair, node_key: PublicKey, amount: u64) -> Result<Tx, String> {
    let pool = native_only(c.utxos(ChainId::Kerckhoffs, &key.address())?);
    let (base, n) = native_transfer_from_pool(pool, Source::Local, key, vec![], None, amount)?;
    let kind = KerckhoffsKind::AddValidator { signing_key: node_key, withdrawal: key.address(), stake: amount };
    Ok(wrap(ChainId::Kerckhoffs, base, kind, n, key))
}

pub fn delegate(c: &Client, key: &Keypair, node: Address, amount: u64) -> Result<Tx, String> {
    let pool = native_only(c.utxos(ChainId::Kerckhoffs, &key.address())?);
    let (base, n) = native_transfer_from_pool(pool, Source::Local, key, vec![], None, amount)?;
    let kind = KerckhoffsKind::AddDelegator { node, stake: amount, reward: key.address() };
    Ok(wrap(ChainId::Kerckhoffs, base, kind, n, key))
}

/// Ask for a validator to leave; signed by its (cold) withdrawal key. The
/// stake returns to the withdrawal address after the unbonding period.
pub fn exit(node: Address, withdrawal_key: &Keypair) -> Tx {
    Tx::Kerckhoffs(KerckhoffsTx::exit(node, withdrawal_key))
}

/// Create a new asset on the Atbash Chain; the whole supply goes to the creator.
pub fn create_asset(c: &Client, key: &Keypair, name: &str, supply: u64) -> Result<(Tx, AssetId), String> {
    let pool = native_only(c.utxos(ChainId::Atbash, &key.address())?);
    let (mut base, n) = native_transfer_from_pool(pool, Source::Local, key, vec![], None, 0)?;
    let mut tx = AtbashTx { base: base.clone(), create_asset: Some(AssetDef { name: name.into(), supply }) };
    let id = tx.new_asset_id().ok_or("asset creation needs an input")?;
    base.outputs.push(TxOut { owner: key.address(), asset: id, amount: supply });
    tx.base = base;
    Ok((Tx::Utxo(ChainId::Atbash, tx.sign(&vec![key; n])), id))
}
