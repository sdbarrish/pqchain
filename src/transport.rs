//! Encrypted, mutually authenticated node-to-node transport.
//!
//! Handshake (hybrid post-quantum + classical key exchange):
//!
//! ```text
//! I -> R  M1 = "PQC1" | network_id | X25519 eph pub (32) | ML-KEM-768 eph encaps key (1184)
//! R -> I  M2 = body{ X25519 eph pub | ML-KEM ciphertext (1088) | R's ML-DSA identity key }
//!              | ML-DSA sig_R(transcript)
//! keys    = SHA3( transcript | X25519 shared secret | ML-KEM shared secret ), one per direction
//! I -> R  M3 (encrypted) = I's ML-DSA identity key | ML-DSA sig_I(transcript)
//! ```
//!
//! * Session keys stay secret if EITHER X25519 or ML-KEM-768 holds (hybrid).
//! * Fresh ephemeral keys per connection give forward secrecy.
//! * Both sides prove their identity with ML-DSA-65 over the full transcript.
//! * `network_id` (the genesis hash) keeps different networks from connecting.
//! * Frames are ChaCha20-Poly1305 with per-direction counters as nonces.

use crate::codec::{Reader, Wire, Writer};
use crate::crypto::*;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use libcrux_ml_kem::mlkem768;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

pub const MAX_FRAME: usize = 16 << 20;
const MAX_HANDSHAKE_FRAME: usize = 16 << 10;
const MAGIC: &[u8; 4] = b"PQC1";
const KEM_PK: usize = 1184;
const KEM_CT: usize = 1088;
const CTX_R: &[u8] = b"pqchain/v1/handshake/responder";
const CTX_I: &[u8] = b"pqchain/v1/handshake/initiator";

pub struct SecureReader {
    half: OwnedReadHalf,
    cipher: ChaCha20Poly1305,
    counter: u64,
}

pub struct SecureWriter {
    half: OwnedWriteHalf,
    cipher: ChaCha20Poly1305,
    counter: u64,
}

fn nonce(counter: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&counter.to_le_bytes());
    Nonce::from(n)
}

impl SecureWriter {
    pub async fn send(&mut self, plain: &[u8]) -> Result<(), String> {
        if plain.len() > MAX_FRAME {
            return Err("frame too large".into());
        }
        let ct = self.cipher.encrypt(&nonce(self.counter), plain).map_err(|_| "encrypt failed")?;
        self.counter += 1;
        let mut out = Vec::with_capacity(4 + ct.len());
        out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        out.extend_from_slice(&ct);
        self.half.write_all(&out).await.map_err(|e| e.to_string())
    }
}

impl SecureReader {
    pub async fn recv(&mut self) -> Result<Vec<u8>, String> {
        let mut len = [0u8; 4];
        self.half.read_exact(&mut len).await.map_err(|e| e.to_string())?;
        let n = u32::from_be_bytes(len) as usize;
        if n > MAX_FRAME + 16 {
            return Err("frame too large".into());
        }
        let mut buf = vec![0u8; n];
        self.half.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
        let plain = self
            .cipher
            .decrypt(&nonce(self.counter), buf.as_slice())
            .map_err(|_| "frame authentication failed")?;
        self.counter += 1;
        Ok(plain)
    }
}

pub struct Session {
    pub peer_key: PublicKey,
    pub peer: Address,
    pub reader: SecureReader,
    pub writer: SecureWriter,
}

async fn write_plain(s: &mut TcpStream, b: &[u8]) -> Result<(), String> {
    let mut out = (b.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(b);
    s.write_all(&out).await.map_err(|e| e.to_string())
}

async fn read_plain(s: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len).await.map_err(|e| e.to_string())?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_HANDSHAKE_FRAME {
        return Err("handshake frame too large".into());
    }
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
    Ok(buf)
}

fn transcript(m1: &[u8], body: &[u8]) -> Hash {
    Enc::new("pqchain/v1/handshake/transcript").bytes(m1).bytes(body).hash()
}

fn session_keys(th: &Hash, ss_x: &[u8; 32], ss_k: &[u8; 32]) -> (ChaCha20Poly1305, ChaCha20Poly1305) {
    let k = |dir: &str| {
        let key = Enc::new(dir).bytes(th).bytes(ss_x).bytes(ss_k).hash();
        ChaCha20Poly1305::new(Key::from_slice(&key))
    };
    (k("pqchain/v1/kdf/initiator->responder"), k("pqchain/v1/kdf/responder->initiator"))
}

fn x25519_ephemeral() -> (StaticSecret, XPublic) {
    let mut s = [0u8; 32];
    rand::fill(&mut s);
    let sec = StaticSecret::from(s);
    let public = XPublic::from(&sec);
    (sec, public)
}

fn x25519_shared(sec: &StaticSecret, their: [u8; 32]) -> Result<[u8; 32], String> {
    let ss = sec.diffie_hellman(&XPublic::from(their)).to_bytes();
    if ss == [0u8; 32] {
        return Err("X25519: low-order point".into());
    }
    Ok(ss)
}

/// Dialer side. `expect` optionally pins the peer's identity address.
pub async fn connect(
    mut s: TcpStream,
    me: &Keypair,
    network_id: &Hash,
    expect: Option<Address>,
) -> Result<Session, String> {
    let (x_sec, x_pub) = x25519_ephemeral();
    let mut seed = [0u8; 64];
    rand::fill(&mut seed);
    let kem = mlkem768::generate_key_pair(seed);
    seed.fill(0);

    let mut w = Writer::default();
    w.fixed(MAGIC);
    w.fixed(network_id);
    w.fixed(x_pub.as_bytes());
    w.fixed(kem.public_key().as_slice());
    let m1 = w.0;
    write_plain(&mut s, &m1).await?;

    let m2 = read_plain(&mut s).await?;
    let mut r = Reader::new(&m2);
    let body = r.bytes()?;
    let sig_r = Signature::get(&mut r)?;
    r.finish()?;
    let mut br = Reader::new(&body);
    let x_peer: [u8; 32] = br.hash()?;
    let ct: [u8; KEM_CT] = (0..KEM_CT)
        .map(|_| br.u8())
        .collect::<Result<Vec<u8>, _>>()?
        .try_into()
        .unwrap();
    let peer_key = PublicKey::get(&mut br)?;
    br.finish()?;

    let th = transcript(&m1, &body);
    if !peer_key.verify(CTX_R, &th, &sig_r) {
        return Err("responder identity signature invalid".into());
    }
    let peer = peer_key.address();
    if let Some(e) = expect {
        if e != peer {
            return Err(format!("unexpected peer identity {peer}, wanted {e}"));
        }
    }
    let ss_x = x25519_shared(&x_sec, x_peer)?;
    let ss_k = mlkem768::decapsulate(kem.private_key(), &mlkem768::MlKem768Ciphertext::from(ct));
    let (i2r, r2i) = session_keys(&th, &ss_x, &ss_k);

    let (rh, wh) = s.into_split();
    let mut writer = SecureWriter { half: wh, cipher: i2r, counter: 0 };
    let reader = SecureReader { half: rh, cipher: r2i, counter: 0 };
    let mut w = Writer::default();
    me.public.put(&mut w);
    me.sign(CTX_I, &th).put(&mut w);
    writer.send(&w.0).await?;
    Ok(Session { peer_key, peer, reader, writer })
}

/// Listener side.
pub async fn accept(mut s: TcpStream, me: &Keypair, network_id: &Hash) -> Result<Session, String> {
    let m1 = read_plain(&mut s).await?;
    if m1.len() != 4 + 32 + 32 + KEM_PK || &m1[..4] != MAGIC {
        return Err("bad handshake hello".into());
    }
    if &m1[4..36] != network_id {
        return Err("peer is on a different network (genesis mismatch)".into());
    }
    let x_peer: [u8; 32] = m1[36..68].try_into().unwrap();
    let ek_bytes: [u8; KEM_PK] = m1[68..].try_into().unwrap();
    let ek = mlkem768::MlKem768PublicKey::from(ek_bytes);
    if !mlkem768::validate_public_key(&ek) {
        return Err("invalid ML-KEM public key".into());
    }

    let (x_sec, x_pub) = x25519_ephemeral();
    let mut rnd = [0u8; 32];
    rand::fill(&mut rnd);
    let (ct, ss_k) = mlkem768::encapsulate(&ek, rnd);

    let mut bw = Writer::default();
    bw.fixed(x_pub.as_bytes());
    bw.fixed(ct.as_slice());
    me.public.put(&mut bw);
    let body = bw.0;
    let th = transcript(&m1, &body);
    let mut w = Writer::default();
    w.bytes(&body);
    me.sign(CTX_R, &th).put(&mut w);
    write_plain(&mut s, &w.0).await?;

    let ss_x = x25519_shared(&x_sec, x_peer)?;
    let (i2r, r2i) = session_keys(&th, &ss_x, &ss_k);
    let (rh, wh) = s.into_split();
    let mut reader = SecureReader { half: rh, cipher: i2r, counter: 0 };
    let writer = SecureWriter { half: wh, cipher: r2i, counter: 0 };

    let m3 = reader.recv().await?;
    let mut r = Reader::new(&m3);
    let peer_key = PublicKey::get(&mut r)?;
    let sig_i = Signature::get(&mut r)?;
    r.finish()?;
    if !peer_key.verify(CTX_I, &th, &sig_i) {
        return Err("initiator identity signature invalid".into());
    }
    let peer = peer_key.address();
    Ok(Session { peer_key, peer, reader, writer })
}
