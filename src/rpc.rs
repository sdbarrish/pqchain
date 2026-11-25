//! JSON-over-HTTP RPC for wallets, explorers and scripts.
//!
//! GET  /status                      node, tips, peers, state root
//! GET  /validators                  validator set
//! GET  /balance/{chain}/{address}   balances per asset
//! GET  /utxos/{chain}/{address}     spendable outputs
//! GET  /atomic/{chain}/{address}    outputs exported to `chain`, awaiting import
//! GET  /block/{chain}/{height}      block summary + certificate size
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

async fn submit(State(e): State<Shared>, body: String) -> Reply {
    let bytes = hex::decode(body.trim()).map_err(|err| bad(err.to_string()))?;
    let tx = Tx::from_bytes(&bytes).map_err(bad)?;
    let chain = tx.chain();
    let id = e.lock().unwrap().submit_tx(tx, None).map_err(bad)?;
    Ok(Json(json!({ "txid": hex::encode(id), "chain": chain_slug(chain) })))
}

pub async fn serve(addr: &str, engine: Shared) -> Result<(), String> {
    let app = Router::new()
        .route("/status", get(status))
        .route("/validators", get(validators))
        .route("/balance/{chain}/{addr}", get(balance))
        .route("/utxos/{chain}/{addr}", get(utxos))
        .route("/atomic/{chain}/{addr}", get(atomic))
        .route("/block/{chain}/{height}", get(block))
        .route("/tx", post(submit))
        .with_state(engine);
    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| format!("rpc {addr}: {e}"))?;
    axum::serve(listener, app).await.map_err(|e| e.to_string())
}
