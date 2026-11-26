//! Hamming Chain: hash-based data availability.
//!
//! Rollups and zones post *blobs*. Each blob is Reed–Solomon coded at rate 1/2:
//! `k` data shards plus `k` parity shards, any `k` of which rebuild the blob.
//! The commitment is a Merkle root over the shards, so it is hash-based and
//! post-quantum (unlike KZG commitments, which rely on elliptic-curve pairings).
//!
//! Every validator re-encodes every blob when validating a block, so a block
//! with a finality certificate has a correct encoding. A light client then
//! checks availability by sampling: to hide a blob, a producer must withhold
//! more than half of its shards, so each random shard the client fetches and
//! verifies halves the chance of being fooled. `s` samples leave < 2^-s.

use crate::consensus::{FinalityCert, LightClient};
use crate::crypto::*;
use crate::ledger::{BlockHeader, ValidatorSet};
use reed_solomon_erasure::galois_8::ReedSolomon;

pub const MAX_BLOB: usize = 128 * 1024;
pub const MAX_BLOCK_DATA: usize = 2 * 1024 * 1024;
const MIN_SHARD: usize = 64;
const MAX_DATA_SHARDS: usize = 64;
pub const BLOB_BASE_FEE: u64 = 1;
pub const BYTES_PER_FEE_UNIT: u64 = 256;

pub fn blob_fee(len: usize) -> u64 {
    BLOB_BASE_FEE + (len as u64).div_ceil(BYTES_PER_FEE_UNIT)
}

/// Shard layout for a blob of `len` bytes: `k` data shards of `shard_len`.
pub fn layout(len: usize) -> (usize, usize) {
    let k = len.div_ceil(MIN_SHARD).clamp(1, MAX_DATA_SHARDS);
    (k, len.div_ceil(k).max(1))
}

/// Reed–Solomon encode `data` into `2k` equal shards (data first, then parity).
pub fn encode(data: &[u8]) -> Vec<Vec<u8>> {
    let (k, shard_len) = layout(data.len());
    let mut shards: Vec<Vec<u8>> = (0..k)
        .map(|i| {
            let mut s = data.get(i * shard_len..).unwrap_or(&[]).iter().take(shard_len).copied().collect::<Vec<u8>>();
            s.resize(shard_len, 0);
            s
        })
        .collect();
    shards.extend((0..k).map(|_| vec![0u8; shard_len]));
    ReedSolomon::new(k, k).expect("valid shard counts").encode(&mut shards).expect("equal shard sizes");
    shards
}

fn shard_leaf(index: u32, shard: &[u8]) -> Hash {
    Enc::new("pqchain/hamming/shard").u64(index as u64).bytes(shard).hash()
}

/// Binding commitment to a blob: its length, shard count, and the Merkle root
/// of its erasure-coded shards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobCommitment {
    pub len: u32,
    pub k: u16,
    pub root: Hash,
}

impl BlobCommitment {
    pub fn hash(&self) -> Hash {
        Enc::new("pqchain/hamming/commitment").u64(self.len as u64).u64(self.k as u64).bytes(&self.root).hash()
    }
    pub fn shards(&self) -> u32 {
        2 * self.k as u32
    }
}

pub fn commit(data: &[u8]) -> BlobCommitment {
    let shards = encode(data);
    let leaves: Vec<Hash> = shards.iter().enumerate().map(|(i, s)| shard_leaf(i as u32, s)).collect();
    BlobCommitment { len: data.len() as u32, k: (shards.len() / 2) as u16, root: merkle_root(&leaves) }
}

/// Shard `index` of `data` with its Merkle path to the commitment root.
pub fn shard_with_proof(data: &[u8], index: usize) -> Option<(Vec<u8>, Vec<Hash>)> {
    let shards = encode(data);
    let leaves: Vec<Hash> = shards.iter().enumerate().map(|(i, s)| shard_leaf(i as u32, s)).collect();
    Some((shards.get(index)?.clone(), merkle_branch(&leaves, index)))
}

/// Check one sampled shard against a commitment.
pub fn verify_shard(c: &BlobCommitment, index: u32, shard: &[u8], branch: &[Hash]) -> bool {
    let (k, shard_len) = layout(c.len as usize);
    k == c.k as usize
        && index < c.shards()
        && shard.len() == shard_len
        && merkle_verify(&shard_leaf(index, shard), index, branch, &c.root)
}

/// Rebuild a blob from any `k` of its `2k` shards; the result is checked
/// against the commitment, so inconsistent shards are detected.
pub fn reconstruct(c: &BlobCommitment, mut shards: Vec<Option<Vec<u8>>>) -> Result<Vec<u8>, String> {
    let k = c.k as usize;
    if shards.len() != 2 * k {
        return Err("wrong number of shard slots".into());
    }
    ReedSolomon::new(k, k)
        .map_err(|e| e.to_string())?
        .reconstruct_data(&mut shards)
        .map_err(|e| format!("cannot reconstruct: {e:?}"))?;
    let mut data: Vec<u8> = shards.into_iter().take(k).flat_map(|s| s.unwrap_or_default()).collect();
    data.truncate(c.len as usize);
    if commit(&data) != *c {
        return Err("reconstructed data does not match the commitment".into());
    }
    Ok(data)
}

/// Everything a light client needs to check that a blob was included in a
/// finalized Hamming block (no blob data needed): the header, its finality
/// certificate, the blob's transaction id parts, and a Merkle path from the
/// transaction id to the header's tx_root.
#[derive(Clone, Debug)]
pub struct InclusionProof {
    pub header: BlockHeader,
    pub cert: FinalityCert,
    /// Transaction id without the data: id = H(prefix_hash, commitment).
    pub prefix_hash: Hash,
    pub commitment: BlobCommitment,
    pub tx_index: u32,
    pub tx_branch: Vec<Hash>,
}

/// The Hamming transaction id is built from a prefix hash (payment and
/// namespace) and the blob commitment, so it can be checked without the data.
pub fn tx_id(prefix_hash: &Hash, c: &BlobCommitment) -> Hash {
    Enc::new("pqchain/hamming-tx").bytes(prefix_hash).bytes(&c.hash()).hash()
}

impl InclusionProof {
    /// Verify the header is finalized by `validators` (> 2/3 of stake) and
    /// the blob's commitment is in it.
    pub fn verify(&self, validators: &ValidatorSet) -> Result<(), String> {
        let h = &self.header;
        if h.chain != crate::ledger::ChainId::Hamming {
            return Err("header is not from the Hamming Chain".into());
        }
        if self.cert.chain != h.chain || self.cert.height != h.height || self.cert.block != h.hash() {
            return Err("certificate does not match the header".into());
        }
        LightClient::from_validators(validators).verify(&self.cert)?;
        let id = tx_id(&self.prefix_hash, &self.commitment);
        if !merkle_verify(&id, self.tx_index, &self.tx_branch, &h.tx_root) {
            return Err("blob is not included in this block".into());
        }
        Ok(())
    }
}

/// Probability that `samples` successful random samples fail to detect a
/// withheld blob (an upper bound for rate-1/2 coding).
pub fn miss_probability(samples: u32) -> f64 {
    0.5f64.powi(samples as i32)
}
