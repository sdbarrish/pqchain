//! Post-quantum primitives.
//!
//! * Signatures: ML-DSA-65 (NIST FIPS 204) from `libcrux-ml-dsa`, a formally
//!   verified implementation (hax / F*).
//! * Hashing: SHA3-256 (NIST FIPS 202). 256-bit outputs keep ~128-bit security
//!   even against Grover's algorithm.
//!
//! Every key and signature carries an algorithm ID byte (crypto agility), so a
//! scheme can be replaced later by a fork without changing the data model.

use fips205::slh_dsa_shake_128s as slh;
use fips205::traits::{KeyGen as _, SerDes as _, Signer as _, Verifier as _};
use libcrux_ml_dsa::ml_dsa_65::{
    self, MLDSA65KeyPair, MLDSA65Signature, MLDSA65VerificationKey,
};
use sha3::{Digest, Sha3_256};
use std::fmt;

pub type Hash = [u8; 32];

/// Algorithm IDs (crypto agility).
/// * ML-DSA-65 (FIPS 204, lattice): fast; used for hot keys (blocks, votes, wallets).
/// * SLH-DSA-SHAKE-128s (FIPS 205, hash-based): relies only on hash security;
///   slow, large signatures; used for cold keys such as validator withdrawal keys.
pub const ALG_ML_DSA_65: u8 = 0x01;
pub const ALG_SLH_DSA_SHAKE_128S: u8 = 0x02;
pub const VK_LEN: usize = 1952;
pub const SIG_LEN: usize = 3309;
pub const SLH_PK_LEN: usize = slh::PK_LEN;
pub const SLH_SIG_LEN: usize = slh::SIG_LEN;

pub fn alg_name(alg: u8) -> &'static str {
    match alg {
        ALG_ML_DSA_65 => "ML-DSA-65",
        ALG_SLH_DSA_SHAKE_128S => "SLH-DSA-SHAKE-128s",
        _ => "unknown",
    }
}

/// Domain-separation contexts (FIPS 204 `ctx` parameter). A signature made
/// for one purpose can never be replayed as another.
pub mod ctx {
    pub const ATBASH_TX: &[u8] = b"pqchain/v0/atbash/tx";
    pub const KERCKHOFFS_TX: &[u8] = b"pqchain/v0/kerckhoffs/tx";
    pub const BLOCK: &[u8] = b"pqchain/v0/block";
    pub const VOTE: &[u8] = b"pqchain/v0/finality-vote";
    pub const EXIT: &[u8] = b"pqchain/v2/validator-exit";
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
impl Address {
    /// Full textual form: "pq1" + 64 hex characters.
    pub fn to_text(&self) -> String {
        format!("pq1{}", hex::encode(self.0))
    }
    pub fn from_text(s: &str) -> Result<Self, String> {
        let h = s.strip_prefix("pq1").ok_or("address must start with pq1")?;
        let b = hex::decode(h).map_err(|e| e.to_string())?;
        Ok(Address(b.try_into().map_err(|_| "address must be 32 bytes")?))
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
        if self.alg != sig.alg {
            return false;
        }
        match self.alg {
            ALG_ML_DSA_65 => self.verify_ml_dsa(context, msg, sig),
            ALG_SLH_DSA_SHAKE_128S => self.verify_slh_dsa(context, msg, sig),
            _ => false,
        }
    }

    fn verify_slh_dsa(&self, context: &[u8], msg: &[u8], sig: &Signature) -> bool {
        let Ok(pk) = <[u8; SLH_PK_LEN]>::try_from(self.bytes.as_slice()) else {
            return false;
        };
        let Ok(s) = <[u8; SLH_SIG_LEN]>::try_from(sig.bytes.as_slice()) else {
            return false;
        };
        match slh::PublicKey::try_from_bytes(pk) {
            Ok(pk) => pk.verify(msg, &s, context),
            Err(_) => false,
        }
    }

    fn verify_ml_dsa(&self, context: &[u8], msg: &[u8], sig: &Signature) -> bool {
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

enum Secret {
    MlDsa(Box<MLDSA65KeyPair>),
    SlhDsa(Box<slh::PrivateKey>),
}

/// A signing key pair (ML-DSA-65 by default, or SLH-DSA for cold keys).
/// Randomness comes from `rand`'s CSPRNG (seeded by the OS). Production
/// builds should use a hardware RNG / HSM.
pub struct Keypair {
    secret: Secret,
    pub public: PublicKey,
    seed: [u8; 32],
}

impl Keypair {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::fill(&mut seed);
        Self::from_seed(seed)
    }

    /// Generate a hash-based SLH-DSA key (for cold storage).
    pub fn generate_slh() -> Self {
        let mut seed = [0u8; 32];
        rand::fill(&mut seed);
        Self::from_seed_alg(ALG_SLH_DSA_SHAKE_128S, seed).expect("valid algorithm")
    }

    /// Deterministic ML-DSA-65 key pair from a 32-byte seed (the seed is the
    /// secret that key files store).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self::from_seed_alg(ALG_ML_DSA_65, seed).expect("valid algorithm")
    }

    pub fn from_seed_alg(alg: u8, seed: [u8; 32]) -> Result<Self, String> {
        match alg {
            ALG_ML_DSA_65 => {
                let kp = ml_dsa_65::generate_key_pair(seed);
                let public = PublicKey { alg, bytes: kp.verification_key.as_slice().to_vec() };
                Ok(Keypair { secret: Secret::MlDsa(Box::new(kp)), public, seed })
            }
            ALG_SLH_DSA_SHAKE_128S => {
                // Expand the 32-byte seed into FIPS 205's three n-byte seeds.
                let part = |tag: &str| -> [u8; slh::N] {
                    Enc::new(tag).bytes(&seed).hash()[..slh::N].try_into().unwrap()
                };
                let (pk, sk) = slh::KG::keygen_from_seed(
                    &part("pqchain/slh/sk-seed"),
                    &part("pqchain/slh/sk-prf"),
                    &part("pqchain/slh/pk-seed"),
                );
                let public = PublicKey { alg, bytes: pk.into_bytes().to_vec() };
                Ok(Keypair { secret: Secret::SlhDsa(Box::new(sk)), public, seed })
            }
            _ => Err(format!("unknown signature algorithm {alg}")),
        }
    }

    pub fn alg(&self) -> u8 {
        self.public.alg
    }

    /// The secret seed. Handle with care.
    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }

    pub fn address(&self) -> Address {
        self.public.address()
    }

    /// Hedged (randomized) signing, as recommended by FIPS 204 and FIPS 205.
    pub fn sign(&self, context: &[u8], msg: &[u8]) -> Signature {
        match &self.secret {
            Secret::MlDsa(kp) => {
                let mut r = [0u8; 32];
                rand::fill(&mut r);
                let s = ml_dsa_65::sign(&kp.signing_key, msg, context, r)
                    .expect("ML-DSA-65 signing failed (context too long?)");
                Signature { alg: ALG_ML_DSA_65, bytes: s.as_slice().to_vec() }
            }
            Secret::SlhDsa(sk) => {
                let s = sk.try_sign(msg, context, true).expect("SLH-DSA signing failed");
                Signature { alg: ALG_SLH_DSA_SHAKE_128S, bytes: s.to_vec() }
            }
        }
    }
}
