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
        ChainId::Hamming => Tx::Hamming(BlobTx::new(base, [0; 8], Vec::new()).sign(&vec![key; n])),
        _ => Tx::Utxo(chain, AtbashTx { base, create_asset: None }.sign_for(chain, &vec![key; n])),
    }
}

fn feistel_nonce(c: &Client, a: &Address) -> Result<u64, String> {
    c.get(&format!("/feistel/account/{}", a.to_text()))?["nonce"].as_u64().ok_or("unexpected RPC reply".into())
}

/// Sign a Feistel action with the account's next nonce.
pub fn feistel(c: &Client, key: &Keypair, max_fuel: u64, action: crate::feistel::Action) -> Result<Tx, String> {
    let nonce = feistel_nonce(c, &key.address())?;
    Ok(Tx::Feistel(crate::feistel::FeistelTx::new(key, nonce, max_fuel, action)))
}

/// Claim everything exported to this account on the Feistel Chain.
pub fn feistel_import(c: &Client, key: &Keypair) -> Result<(Tx, u64), String> {
    let pool = native_only(c.atomic(ChainId::Feistel, &key.address())?);
    let total: u64 = pool.iter().map(|(_, o)| o.amount).sum();
    if pool.is_empty() {
        return Err("nothing exported to the Feistel Chain for this key".into());
    }
    let outpoints = pool.into_iter().map(|(p, _)| p).take(256).collect();
    Ok((feistel(c, key, 0, crate::feistel::Action::Import { outpoints })?, total))
}

/// Post a blob to the Hamming Chain (fee paid from Hamming Chain funds).
pub fn hamming_post(c: &Client, key: &Keypair, namespace: &str, data: Vec<u8>) -> Result<Tx, String> {
    if namespace.len() > 8 {
        return Err("namespace is at most 8 bytes".into());
    }
    let mut ns = [0u8; 8];
    ns[..namespace.len()].copy_from_slice(namespace.as_bytes());
    let pool = native_only(c.utxos(ChainId::Hamming, &key.address())?);
    let extra = crate::hamming::blob_fee(data.len()) - TX_FEE;
    let (base, n) = native_transfer_from_pool(pool, Source::Local, key, vec![], None, extra)?;
    Ok(Tx::Hamming(BlobTx::new(base, ns, data).sign(&vec![key; n])))
}

/// The current validator set as published by the node (a light-client
/// checkpoint: a production light client would track it via Kerckhoffs
/// Chain certificates from genesis instead of trusting one node).
pub fn validator_checkpoint(c: &Client) -> Result<ValidatorSet, String> {
    let v = c.get("/validators")?;
    let mut set = ValidatorSet::new();
    for x in v["validators"].as_array().ok_or("unexpected RPC reply")? {
        let key = PublicKey {
            alg: ALG_ML_DSA_65,
            bytes: hex::decode(x["signing_key"].as_str().unwrap_or("")).map_err(|e| e.to_string())?,
        };
        let node_id = key.address();
        if x["node_id"].as_str() != Some(node_id.to_text().as_str()) {
            return Err("node returned an inconsistent validator key".into());
        }
        set.insert(
            node_id,
            Validator {
                node_id,
                signing_key: key,
                withdrawal: Address::from_text(x["withdrawal"].as_str().unwrap_or(""))?,
                stake: x["weight"].as_u64().unwrap_or(0),
                delegated: 0,
                slashed: x["slashed"].as_bool().unwrap_or(false),
                exit_at: None,
            },
        );
    }
    Ok(set)
}

fn shard(c: &Client, height: u64, index: usize, i: u32) -> Result<(Vec<u8>, Vec<Hash>), String> {
    let v = c.get(&format!("/hamming/shard/{height}/{index}/{i}"))?;
    let shard = hex::decode(v["shard"].as_str().unwrap_or("")).map_err(|e| e.to_string())?;
    let branch = v["branch"]
        .as_array()
        .ok_or("unexpected RPC reply")?
        .iter()
        .map(|h| hex::decode(h.as_str().unwrap_or("")).ok().and_then(|b| b.try_into().ok()).ok_or("bad hash"))
        .collect::<Result<Vec<Hash>, _>>()?;
    Ok((shard, branch))
}

/// Light-client data-availability check: verify the blob is in a finalized
/// block, then fetch and verify `samples` random shards. Returns the
/// commitment and the indices sampled.
pub fn hamming_sample(c: &Client, height: u64, index: usize, samples: u32) -> Result<(crate::hamming::BlobCommitment, Vec<u32>), String> {
    let p = c.get(&format!("/hamming/proof/{height}/{index}"))?;
    let proof = crate::hamming::InclusionProof::from_bytes(
        &hex::decode(p["proof"].as_str().ok_or("no proof")?).map_err(|e| e.to_string())?,
    )?;
    proof.verify(&validator_checkpoint(c)?)?;
    let cm = proof.commitment;
    let mut picked = Vec::new();
    for _ in 0..samples {
        let i = rand::random_range(0..cm.shards());
        let (s, branch) = shard(c, height, index, i)?;
        if !crate::hamming::verify_shard(&cm, i, &s, &branch) {
            return Err(format!("shard {i} failed verification: data may be unavailable"));
        }
        picked.push(i);
    }
    Ok((cm, picked))
}

/// Download any `k` random shards (deliberately mixing data and parity) and
/// rebuild the blob, checking each shard and the result.
pub fn hamming_get(c: &Client, height: u64, index: usize) -> Result<(Vec<u8>, Vec<u32>), String> {
    let (cm, _) = hamming_sample(c, height, index, 0)?;
    let n = cm.shards();
    let mut order: Vec<u32> = (0..n).collect();
    for i in (1..order.len()).rev() {
        order.swap(i, rand::random_range(0..=i));
    }
    let mut slots: Vec<Option<Vec<u8>>> = vec![None; n as usize];
    let used: Vec<u32> = order.into_iter().take(cm.k as usize).collect();
    for &i in &used {
        let (s, branch) = shard(c, height, index, i)?;
        if !crate::hamming::verify_shard(&cm, i, &s, &branch) {
            return Err(format!("shard {i} failed verification"));
        }
        slots[i as usize] = Some(s);
    }
    Ok((crate::hamming::reconstruct(&cm, slots)?, used))
}

/// Claim accumulated staking rewards for this key's address.
pub fn claim_rewards(c: &Client, key: &Keypair) -> Result<(Tx, u64), String> {
    let v = c.get(&format!("/rewards/{}", key.address().to_text()))?;
    let amount = v["unclaimed"].as_u64().unwrap_or(0);
    if amount == 0 {
        return Err("no rewards to claim".into());
    }
    let nonce = v["nonce"].as_u64().ok_or("unexpected RPC reply")?;
    Ok((Tx::Kerckhoffs(KerckhoffsTx::claim_rewards(key, nonce)), amount))
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
