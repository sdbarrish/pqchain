use pqchain::codec::{Tx, Wire};
use pqchain::consensus::FinalityCert;
use pqchain::crypto::*;
use pqchain::ledger::*;
use pqchain::network::native_transfer;
use pqchain::node::Msg;
use pqchain::transport;
use tokio::net::{TcpListener, TcpStream};

fn sample_block() -> (Block, Ledger, Keypair) {
    let v = Keypair::generate();
    let a = Keypair::generate();
    let l = Ledger::genesis(
        vec![GenesisValidator { signing_key: v.public.clone(), withdrawal: v.address(), stake: 2_000 }],
        &[(a.address(), 1_000)],
    );
    let (base, n) = native_transfer(&l, ChainId::Atbash, Source::Local, &a, vec![TxOut::native(v.address(), 10)], None, 0).unwrap();
    let tx = AtbashTx { base, create_asset: None }.sign(&vec![&a; n]);
    let b = propose(&l, &v, Body::Atbash(vec![tx]), 7);
    (b, l, v)
}

#[test]
fn block_roundtrips_and_still_validates() {
    let (b, l, _) = sample_block();
    let back = Block::from_bytes(&b.to_bytes()).unwrap();
    assert_eq!(back.hash(), b.hash());
    assert_eq!(back.body.tx_ids(), b.body.tx_ids());
    l.clone().apply_block(&back).unwrap();
}

#[test]
fn messages_roundtrip() {
    let (b, _, v) = sample_block();
    let mut cert = FinalityCert::new(ChainId::Atbash, 1, b.hash());
    cert.add_vote(&v);
    let tx = match &b.body {
        Body::Atbash(t) => Tx::Utxo(ChainId::Atbash, t[0].clone()),
        _ => unreachable!(),
    };
    for m in [
        Msg::Status { tips: vec![(ChainId::Kerckhoffs, 3), (ChainId::Atbash, 9), (ChainId::Zone(7), 2)] },
        Msg::Tx(tx),
        Msg::Block(b.clone()),
        Msg::Query { id: 1, chain: ChainId::Kerckhoffs, height: 2 },
        Msg::Chits { id: 1, pref: Some(b.hash()) },
        Msg::Chits { id: 2, pref: None },
        Msg::Blocks(vec![(b.clone(), cert)]),
    ] {
        let bytes = m.to_bytes();
        assert_eq!(Msg::from_bytes(&bytes).unwrap().to_bytes(), bytes);
    }
}

#[test]
fn hostile_input_is_rejected_not_panicking() {
    let (b, _, _) = sample_block();
    let bytes = b.to_bytes();
    for cut in [0, 1, 10, bytes.len() / 2, bytes.len() - 1] {
        assert!(Block::from_bytes(&bytes[..cut]).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(Block::from_bytes(&extra).is_err(), "trailing bytes");
    // Absurd length prefix must not allocate gigabytes.
    assert!(Msg::from_bytes(&[7, 0xff, 0xff, 0xff, 0xff]).is_err());
    for seed in 0u8..=255 {
        let junk: Vec<u8> = (0..64u8).map(|i| i.wrapping_mul(seed).wrapping_add(seed)).collect();
        let _ = Msg::from_bytes(&junk);
    }
}

async fn pair(net_a: Hash, net_b: Hash) -> (Result<transport::Session, String>, Result<transport::Session, String>, Address, Address) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (ka, kb) = (Keypair::generate(), Keypair::generate());
    let (aa, ab) = (ka.address(), kb.address());
    let server = tokio::spawn(async move {
        let (s, _) = listener.accept().await.unwrap();
        transport::accept(s, &kb, &net_b).await
    });
    let s = TcpStream::connect(addr).await.unwrap();
    let client = transport::connect(s, &ka, &net_a, Some(ab)).await;
    (client, server.await.unwrap(), aa, ab)
}

#[tokio::test]
async fn hybrid_handshake_authenticates_and_encrypts() {
    let net = [9u8; 32];
    let (c, s, aa, ab) = pair(net, net).await;
    let (Ok(mut c), Ok(mut s)) = (c, s) else { panic!("handshake failed") };
    assert_eq!(c.peer, ab, "client sees server identity");
    assert_eq!(s.peer, aa, "server sees client identity");
    c.writer.send(b"hello over ML-KEM + X25519").await.unwrap();
    assert_eq!(s.reader.recv().await.unwrap(), b"hello over ML-KEM + X25519");
    s.writer.send(&[1, 2, 3]).await.unwrap();
    assert_eq!(c.reader.recv().await.unwrap(), vec![1, 2, 3]);
}

#[tokio::test]
async fn different_network_is_refused() {
    let (c, s, _, _) = pair([1u8; 32], [2u8; 32]).await;
    assert!(s.err().unwrap().contains("different network"));
    assert!(c.is_err());
}

#[tokio::test]
async fn pinned_identity_mismatch_is_refused() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let kb = Keypair::generate();
    tokio::spawn(async move {
        let (s, _) = listener.accept().await.unwrap();
        let _ = transport::accept(s, &kb, &[0u8; 32]).await;
    });
    let s = TcpStream::connect(addr).await.unwrap();
    let impostor_check = Keypair::generate().address();
    let r = transport::connect(s, &Keypair::generate(), &[0u8; 32], Some(impostor_check)).await;
    assert!(r.err().unwrap().contains("unexpected peer identity"));
}
