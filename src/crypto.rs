//! Post-quantum primitives.
//!
//! * Signatures: ML-DSA-65 (NIST FIPS 204) from `libcrux-ml-dsa`, a formally
//!   verified implementation (hax / F*).
//! * Hashing: SHA3-256 (NIST FIPS 202). 256-bit outputs keep ~128-bit security
//!   even against Grover's algorithm.
//!
//! Every key and signature carries an algorithm ID byte (crypto agility), so a
//! scheme can be replaced later by a fork without changing the data model.

use libcrux_ml_dsa::ml_dsa_65::{
    self, MLDSA65KeyPair, MLDSA65Signature, MLDSA65VerificationKey,
};
use sha3::{Digest, Sha3_256};
use std::fmt;

pub type Hash = [u8; 32];

/// Algorithm IDs. Only ML-DSA-65 is enabled in testnet v0.
pub const ALG_ML_DSA_65: u8 = 0x01;
pub const VK_LEN: usize = 1952;
pub const SIG_LEN: usize = 3309;

/// Domain-separation contexts (FIPS 204 `ctx` parameter). A signature made
/// for one purpose can never be replayed as another.
pub mod ctx {
    pub const PRISM_TX: &[u8] = b"pqchain/v0/prism/tx";
    pub const KEYSTONE_TX: &[u8] = b"pqchain/v0/keystone/tx";
    pub const BLOCK: &[u8] = b"pqchain/v0/block";
    pub const VOTE: &[u8] = b"pqchain/v0/finality-vote";
}

/// Canonical, length-prefixed encoder used for every hash in the protocol.
/// Unambiguous encoding prevents two different objects hashing the same.
pub struct Enc(Vec<u8>);

impl Enc {
    pub fn new(domain: &str) -> Self {
        let mut e = Enc(Vec::new());
        e.bytes(domain.as_bytes());
        e
    }
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.u64(b.len() as u64);
        self.0.extend_from_slice(b);
        self
    }
    pub fn hash(&self) -> Hash {
        sha3_256(&self.0)
    }
}

pub fn sha3_256(data: &[u8]) -> Hash {
    let mut h = Sha3_256::new();
    h.update(data);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// Binary Merkle root with leaf/node domain separation.
pub fn merkle_root(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return Enc::new("pqchain/merkle/empty").hash();
    }
    let mut level: Vec<Hash> = leaves
        .iter()
        .map(|l| Enc::new("pqchain/merkle/leaf").bytes(l).hash())
        .collect();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|c| {
                let r = c.get(1).unwrap_or(&c[0]);
                Enc::new("pqchain/merkle/node").bytes(&c[0]).bytes(r).hash()
            })
            .collect();
    }
    level[0]
}

/// 256-bit address = SHA3-256(alg_id || public key). The public key itself
/// stays hidden until the owner first spends.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address(pub Hash);

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pq1{}", hex::encode(&self.0[..8]))
    }
}
impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicKey {
    pub alg: u8,
    pub bytes: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Signature {
    pub alg: u8,
    pub bytes: Vec<u8>,
}

impl Signature {
    pub fn empty() -> Self {
        Signature { alg: ALG_ML_DSA_65, bytes: Vec::new() }
    }
}

impl PublicKey {
    pub fn address(&self) -> Address {
        Address(Enc::new("pqchain/address").u8(self.alg).bytes(&self.bytes).hash())
    }

    /// Verify; any malformed key/signature or unknown algorithm is a rejection.
    pub fn verify(&self, context: &[u8], msg: &[u8], sig: &Signature) -> bool {
        if self.alg != ALG_ML_DSA_65 || sig.alg != ALG_ML_DSA_65 {
            return false;
        }
        let Ok(vk) = <[u8; VK_LEN]>::try_from(self.bytes.as_slice()) else {
            return false;
        };
        let Ok(s) = <[u8; SIG_LEN]>::try_from(sig.bytes.as_slice()) else {
            return false;
        };
        ml_dsa_65::verify(
            &MLDSA65VerificationKey::new(vk),
            msg,
            context,
            &MLDSA65Signature::new(s),
        )
        .is_ok()
    }
}

/// An ML-DSA-65 key pair. Randomness comes from `rand`'s CSPRNG (seeded by the
/// OS). Production builds should use a hardware RNG / HSM.
pub struct Keypair {
    kp: MLDSA65KeyPair,
    pub public: PublicKey,
}

impl Keypair {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::fill(&mut seed);
        let kp = ml_dsa_65::generate_key_pair(seed);
        seed.fill(0);
        let public = PublicKey {
            alg: ALG_ML_DSA_65,
            bytes: kp.verification_key.as_slice().to_vec(),
        };
        Keypair { kp, public }
    }

    pub fn address(&self) -> Address {
        self.public.address()
    }

    /// Hedged (randomized) signing, as recommended by FIPS 204.
    pub fn sign(&self, context: &[u8], msg: &[u8]) -> Signature {
        let mut r = [0u8; 32];
        rand::fill(&mut r);
        let s = ml_dsa_65::sign(&self.kp.signing_key, msg, context, r)
            .expect("ML-DSA-65 signing failed (context too long?)");
        Signature { alg: ALG_ML_DSA_65, bytes: s.as_slice().to_vec() }
    }
}
