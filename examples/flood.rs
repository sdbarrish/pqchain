//! Attack tool for testing rate limits: connect to a node (properly
//! authenticated, with a fresh identity) and send messages as fast as
//! possible. Reports how many were sent before the node cut the connection.
//!
//! Usage: cargo run --release --example flood -- <host:port> <network-id-hex> [messages]

use pqchain::codec::Wire;
use pqchain::crypto::Keypair;
use pqchain::node::Msg;
use pqchain::transport;
use std::time::{Duration, Instant};

#[tokio::main]
async fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let addr = args.get(1).ok_or("usage: flood <host:port> <network-id-hex> [messages]")?;
    let nid: [u8; 32] = hex::decode(args.get(2).ok_or("missing network id")?)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("network id must be 32-byte hex")?;
    let n: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(20_000);
    let s = tokio::net::TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let mut sess = transport::connect(s, &Keypair::generate(), &nid, None).await?;
    let msg = Msg::Status { tips: vec![] }.to_bytes();
    let t = Instant::now();
    let mut sent = 0;
    for _ in 0..n {
        if sess.writer.send(&msg).await.is_err() {
            break;
        }
        sent += 1;
    }
    // Give the node a moment, then see whether it closed the connection.
    let closed = matches!(tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if sess.reader.recv().await.is_err() {
                return;
            }
        }
    }).await, Ok(()));
    println!("sent {sent} messages in {} ms; connection closed by node: {closed}", t.elapsed().as_millis());
    Ok(())
}
