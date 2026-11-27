//! JSON-over-HTTP RPC for wallets, explorers and scripts.
//!
//! GET  /status                      node, tips, peers, state root
//! GET  /validators                  validator set
//! GET  /balance/{chain}/{address}   balances per asset
//! GET  /utxos/{chain}/{address}     spendable outputs
//! GET  /atomic/{chain}/{address}    outputs exported to `chain`, awaiting import
//! GET  /block/{chain}/{height}      block summary + certificate size
//! GET  /inbox/{chain}/{address}     relay messages to claim, with proofs
//! GET  /zones                       registered zones
//! GET  /rewards/{address}           unclaimed staking rewards and claim nonce
//! GET  /feistel/account/{address}   Feistel balance and nonce
//! GET  /feistel/contract/{address}  contract code hash, creator, balance, storage size
//! GET  /feistel/receipt/{txid}      result of a Feistel transaction
//! POST /feistel/query/{address}/{method}  read-only call; body = hex input
//! GET  /hamming/blobs/{height}             blobs in a Hamming block
//! GET  /hamming/proof/{height}/{index}     light-client inclusion proof (hex)
//! GET  /hamming/shard/{height}/{index}/{i} one erasure-coded shard + Merkle path
//! GET  /network                            this network's id and Kerckhoffs height
//! GET  /bridge/set/{k_height}              validator set at a Kerckhoffs height (hex)
//! GET  /bridge/kheader/{k_height}          certified Kerckhoffs header + resulting set (hex)
//! GET  /bridge/outbox/{dest_network}       bridge messages to a network, with proofs (hex)
//! POST /tx                          hex-encoded signed transaction

use crate::codec::{Tx, Wire};
use crate::crypto::Address;
use crate::ledger::{ChainId, OutPoint, TxOut, NATIVE};
use crate::node::{chain_from_str, chain_slug, Shared};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::collections::BTreeMap;

type Reply = Result<Json<Value>, (StatusCode, Json<Value>)>;

fn bad(msg: impl Into<String>) -> (StatusCode, Json<Value>) {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": msg.into() })))
}

fn parse(chain: &str, addr: &str) -> Result<(ChainId, Address), (StatusCode, Json<Value>)> {
    Ok((chain_from_str(chain).map_err(bad)?, Address::from_text(addr).map_err(bad)?))
}

pub fn utxo_json(p: &OutPoint, o: &TxOut) -> Value {
    json!({
        "txid": hex::encode(p.txid), "index": p.index,
        "owner": o.owner.to_text(), "asset": hex::encode(o.asset), "amount": o.amount,
    })
}

async fn status(State(e): State<Shared>) -> Json<Value> {
    Json(e.lock().unwrap().status_json())
}

async fn validators(State(e): State<Shared>) -> Json<Value> {
    let e = e.lock().unwrap();
    let list: Vec<Value> = e
        .ledger
        .validators
        .values()
        .map(|v| {
            json!({
                "node_id": v.node_id.to_text(), "stake": v.stake, "delegated": v.delegated,
                "weight": v.weight(), "slashed": v.slashed, "withdrawal": v.withdrawal.to_text(),
                "exit_at": v.exit_at,
                "signing_key": hex::encode(&v.signing_key.bytes), "stake_own": v.stake,
                "connected": e.peers.contains_key(&v.node_id) || v.node_id == e.me,
            })
        })
        .collect();
    Json(json!({ "validators": list, "total_weight": e.ledger.total_weight() }))
}

async fn balance(State(e): State<Shared>, Path((chain, addr)): Path<(String, String)>) -> Reply {
    let (c, a) = parse(&chain, &addr)?;
    let e = e.lock().unwrap();
    let mut assets: BTreeMap<String, u64> = BTreeMap::new();
    for (_, o) in e.ledger.utxos_of(c, &a) {
        let k = if o.asset == NATIVE { "native".to_string() } else { hex::encode(o.asset) };
        *assets.entry(k).or_default() += o.amount;
    }
    let pending: u64 = e.ledger.atomic_of(c, &a).iter().filter(|(_, o)| o.asset == NATIVE).map(|(_, o)| o.amount).sum();
    Ok(Json(json!({ "chain": chain_slug(c), "address": a.to_text(), "assets": assets, "pending_import": pending })))
}

async fn utxos(State(e): State<Shared>, Path((chain, addr)): Path<(String, String)>) -> Reply {
    let (c, a) = parse(&chain, &addr)?;
    let e = e.lock().unwrap();
    Ok(Json(json!(e.ledger.utxos_of(c, &a).iter().map(|(p, o)| utxo_json(p, o)).collect::<Vec<_>>())))
}

async fn atomic(State(e): State<Shared>, Path((chain, addr)): Path<(String, String)>) -> Reply {
    let (c, a) = parse(&chain, &addr)?;
    let e = e.lock().unwrap();
    Ok(Json(json!(e.ledger.atomic_of(c, &a).iter().map(|(p, o)| utxo_json(p, o)).collect::<Vec<_>>())))
}

async fn block(State(e): State<Shared>, Path((chain, height)): Path<(String, u64)>) -> Reply {
    let c = chain_from_str(&chain).map_err(bad)?;
    e.lock()
        .unwrap()
        .block_json(c, height)
        .map(Json)
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(json!({ "error": "no such block" }))))
}

async fn inbox(State(e): State<Shared>, Path((chain, addr)): Path<(String, String)>) -> Reply {
    let (c, a) = parse(&chain, &addr)?;
    let e = e.lock().unwrap();
    let items: Vec<Value> = e
        .inbox(c, &a)
        .iter()
        .map(|ri| {
            json!({
                "from": chain_slug(ri.msg.src), "amount": ri.msg.out.amount,
                "asset": hex::encode(ri.msg.out.asset), "source_height": ri.header.height,
                "proof_bytes": ri.to_bytes().len(), "proof": hex::encode(ri.to_bytes()),
            })
        })
        .collect();
    Ok(Json(json!(items)))
}

async fn rewards(State(e): State<Shared>, Path(addr): Path<String>) -> Reply {
    let a = Address::from_text(&addr).map_err(bad)?;
    let e = e.lock().unwrap();
    Ok(Json(json!({
        "address": a.to_text(),
        "unclaimed": e.ledger.rewards.get(&a).copied().unwrap_or(0),
        "nonce": e.ledger.claim_nonces.get(&a).copied().unwrap_or(0),
    })))
}

async fn feistel_account(State(e): State<Shared>, Path(addr): Path<String>) -> Reply {
    let a = Address::from_text(&addr).map_err(bad)?;
    let e = e.lock().unwrap();
    Ok(Json(json!({ "address": a.to_text(), "balance": e.ledger.feistel.balance(&a), "nonce": e.ledger.feistel.nonce(&a) })))
}

async fn feistel_contract(State(e): State<Shared>, Path(addr): Path<String>) -> Reply {
    let a = Address::from_text(&addr).map_err(bad)?;
    let e = e.lock().unwrap();
    let c = e.ledger.feistel.contracts.get(&a).ok_or_else(|| (StatusCode::NOT_FOUND, Json(json!({ "error": "no contract" }))))?;
    Ok(Json(json!({
        "address": a.to_text(), "code_hash": hex::encode(c.code_hash), "code_bytes": c.code.len(),
        "creator": c.creator.to_text(), "balance": e.ledger.feistel.balance(&a), "storage_entries": c.storage.len(),
    })))
}

async fn feistel_receipt(State(e): State<Shared>, Path(txid): Path<String>) -> Reply {
    let id: [u8; 32] = hex::decode(&txid).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| bad("txid must be 32-byte hex"))?;
    let e = e.lock().unwrap();
    let r = e.ledger.receipts.get(&id).ok_or_else(|| (StatusCode::NOT_FOUND, Json(json!({ "error": "no receipt (not yet included?)" }))))?;
    Ok(Json(json!({
        "ok": r.ok, "fuel_used": r.fuel_used, "fee": r.fee, "error": r.error,
        "output_hex": hex::encode(&r.output), "logs": r.logs.iter().map(|l| String::from_utf8_lossy(l).to_string()).collect::<Vec<_>>(),
        "contract": r.contract.map(|a| a.to_text()),
    })))
}

async fn feistel_query(State(e): State<Shared>, Path((addr, method)): Path<(String, String)>, body: String) -> Reply {
    let a = Address::from_text(&addr).map_err(bad)?;
    let input = hex::decode(body.trim()).map_err(|err| bad(err.to_string()))?;
    let st = e.lock().unwrap().ledger.feistel.clone();
    let out = crate::feistel::query(&st, a, &method, input).map_err(bad)?;
    let as_u64 = <[u8; 8]>::try_from(out.as_slice()).ok().map(u64::from_le_bytes);
    Ok(Json(json!({ "output_hex": hex::encode(&out), "as_u64": as_u64 })))
}

fn not_found(msg: &str) -> (StatusCode, Json<Value>) {
    (StatusCode::NOT_FOUND, Json(json!({ "error": msg })))
}

async fn hamming_blobs(State(e): State<Shared>, Path(height): Path<u64>) -> Reply {
    let e = e.lock().unwrap();
    let mut out = Vec::new();
    while let Some((_, cert, tx)) = e.blob(height, out.len()) {
        out.push(json!({
            "index": out.len(), "namespace": String::from_utf8_lossy(&tx.namespace).trim_end_matches('\0').to_string(),
            "bytes": tx.data.len(), "shards": tx.commitment.shards(), "data_shards": tx.commitment.k,
            "commitment": hex::encode(tx.commitment.to_bytes()), "certified": cert.is_some(),
        }));
    }
    Ok(Json(json!(out)))
}

async fn hamming_proof(State(e): State<Shared>, Path((height, index)): Path<(u64, usize)>) -> Reply {
    let e = e.lock().unwrap();
    let p = e.blob_inclusion(height, index).ok_or_else(|| not_found("no certified blob at this position"))?;
    Ok(Json(json!({ "proof": hex::encode(p.to_bytes()) })))
}

async fn hamming_shard(State(e): State<Shared>, Path((height, index, i)): Path<(u64, usize, usize)>) -> Reply {
    let e = e.lock().unwrap();
    let (_, _, tx) = e.blob(height, index).ok_or_else(|| not_found("no such blob"))?;
    let (shard, branch) = crate::hamming::shard_with_proof(&tx.data, i).ok_or_else(|| not_found("no such shard"))?;
    Ok(Json(json!({ "shard": hex::encode(shard), "branch": branch.iter().map(hex::encode).collect::<Vec<_>>() })))
}

async fn network(State(e): State<Shared>) -> Json<Value> {
    let e = e.lock().unwrap();
    Json(json!({ "network_id": hex::encode(e.ledger.network_id), "kerckhoffs_height": e.ledger.tip(ChainId::Kerckhoffs).0 }))
}

fn list_hex<T: Wire>(v: &[T]) -> String {
    let mut w = crate::codec::Writer::default();
    w.list(v);
    hex::encode(w.0)
}

async fn bridge_set(State(e): State<Shared>, Path(h): Path<u64>) -> Reply {
    let e = e.lock().unwrap();
    let set = e.ledger.validators_at(h).ok_or_else(|| not_found("no validator set at that height"))?;
    Ok(Json(json!({ "validators": list_hex(&crate::playfair::from_ledger_set(set)) })))
}

async fn bridge_kheader(State(e): State<Shared>, Path(h): Path<u64>) -> Reply {
    let e = e.lock().unwrap();
    let (header, cert, set) = e.k_header(h).ok_or_else(|| not_found("no certified Kerckhoffs block at that height"))?;
    Ok(Json(json!({ "header": hex::encode(header.to_bytes()), "cert": hex::encode(cert.to_bytes()), "validators": list_hex(&set) })))
}

async fn bridge_outbox(State(e): State<Shared>, Path(dest): Path<String>) -> Reply {
    let d: crate::crypto::Hash = hex::decode(&dest).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| bad("network id must be 32-byte hex"))?;
    let e = e.lock().unwrap();
    let items: Vec<Value> = e
        .bridge_outbox(&d)
        .iter()
        .map(|p| json!({ "amount": p.msg.amount, "recipient": p.msg.recipient.to_text(), "proof": hex::encode(p.to_bytes()) }))
        .collect();
    Ok(Json(json!(items)))
}

async fn zones(State(e): State<Shared>) -> Json<Value> {
    Json(e.lock().unwrap().status_json()["zones"].clone())
}

async fn submit(State(e): State<Shared>, body: String) -> Reply {
    let bytes = hex::decode(body.trim()).map_err(|err| bad(err.to_string()))?;
    let tx = Tx::from_bytes(&bytes).map_err(bad)?;
    let chain = tx.chain();
    let id = e.lock().unwrap().submit_tx(tx, None).map_err(bad)?;
    Ok(Json(json!({ "txid": hex::encode(id), "chain": chain_slug(chain) })))
}

/// Per-IP request budget: tokens per second and burst. Expensive endpoints
/// (contract queries, scans over all blocks, transaction submission) cost
/// HEAVY_COST tokens; others cost 1.
pub const RPC_RATE: (f64, f64) = (50.0, 100.0);
pub const HEAVY_COST: f64 = 10.0;

fn cost(path: &str) -> f64 {
    let heavy = ["/feistel/query", "/inbox", "/bridge/outbox", "/tx"];
    if heavy.iter().any(|p| path.starts_with(p)) {
        HEAVY_COST
    } else if path.starts_with("/hamming/shard") {
        2.0 // light clients fetch many shards; each re-encodes one blob
    } else {
        1.0
    }
}

async fn rate_limit(
    State(limiter): State<std::sync::Arc<crate::ratelimit::Limiter<std::net::IpAddr>>>,
    axum::extract::ConnectInfo(from): axum::extract::ConnectInfo<std::net::SocketAddr>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if limiter.take(&from.ip(), cost(req.uri().path())) {
        next.run(req).await
    } else {
        (StatusCode::TOO_MANY_REQUESTS, Json(json!({ "error": "rate limit exceeded; slow down" }))).into_response()
    }
}

pub async fn serve(addr: &str, engine: Shared) -> Result<(), String> {
    let app = Router::new()
        .route("/status", get(status))
        .route("/validators", get(validators))
        .route("/balance/{chain}/{addr}", get(balance))
        .route("/utxos/{chain}/{addr}", get(utxos))
        .route("/atomic/{chain}/{addr}", get(atomic))
        .route("/block/{chain}/{height}", get(block))
        .route("/inbox/{chain}/{addr}", get(inbox))
        .route("/zones", get(zones))
        .route("/rewards/{addr}", get(rewards))
        .route("/feistel/account/{addr}", get(feistel_account))
        .route("/feistel/contract/{addr}", get(feistel_contract))
        .route("/feistel/receipt/{txid}", get(feistel_receipt))
        .route("/feistel/query/{addr}/{method}", post(feistel_query))
        .route("/hamming/blobs/{height}", get(hamming_blobs))
        .route("/hamming/proof/{height}/{index}", get(hamming_proof))
        .route("/hamming/shard/{height}/{index}/{i}", get(hamming_shard))
        .route("/network", get(network))
        .route("/bridge/set/{h}", get(bridge_set))
        .route("/bridge/kheader/{h}", get(bridge_kheader))
        .route("/bridge/outbox/{dest}", get(bridge_outbox))
        .route("/tx", post(submit))
        .with_state(engine);
    let limiter = std::sync::Arc::new(crate::ratelimit::Limiter::new(RPC_RATE.0, RPC_RATE.1, 100_000));
    let app = app.layer(axum::middleware::from_fn_with_state(limiter, rate_limit));
    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| format!("rpc {addr}: {e}"))?;
    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await
        .map_err(|e| e.to_string())
}
