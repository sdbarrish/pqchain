//! Sampled Quorum Consensus (repeated random-subsample voting) + finality certificates.
//!
//! Sampled quorum voting needs no signature certificates to *reach* agreement: each node
//! repeatedly polls `k` stake-weighted random validators. That makes it a good
//! fit for large post-quantum signatures. Signatures are only gathered once,
//! after acceptance, into a finality certificate that light clients check.

use crate::crypto::*;
use crate::ledger::{ChainId, Ledger};
use rand::RngExt;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug)]
pub struct Params {
    /// Sample size per poll.
    pub k: usize,
    /// Votes needed for a successful poll (> k/2).
    pub alpha: usize,
    /// Consecutive successful polls needed to finalize.
    pub beta: u32,
    pub max_rounds: u32,
}

impl Default for Params {
    fn default() -> Self {
        // k=20, alpha=14, beta=20: parameters from the published metastable-consensus research.
        Params { k: 20, alpha: 14, beta: 20, max_rounds: 5_000 }
    }
}

pub struct Voter {
    pub weight: u64,
    pub byzantine: bool,
    /// Initial preferred candidate index (None = has no valid candidate).
    pub initial: Option<usize>,
}

#[derive(Debug)]
pub struct Outcome {
    /// Decision of each honest voter (None for byzantine voters).
    pub decisions: Vec<Option<usize>>,
    pub rounds: u32,
    pub polls: u64,
    /// Honest voters that had not finalized when the round limit hit.
    pub undecided_honest: usize,
}

impl Outcome {
    /// The unanimous honest decision, if any.
    pub fn agreed(&self) -> Option<usize> {
        let set: BTreeSet<_> = self.decisions.iter().flatten().collect();
        if set.len() == 1 && self.undecided_honest == 0 {
            set.into_iter().next().copied()
        } else {
            None
        }
    }
}

struct QuorumState {
    pref: usize,
    counts: Vec<u64>,
    last: Option<usize>,
    conf: u32,
    decided: Option<usize>,
}

/// Run sampled quorum voting over `n_candidates` conflicting blocks for one height.
/// Byzantine voters always answer with whatever honest nodes currently
/// prefer least, trying to keep the network split.
pub fn sampled_quorum(voters: &[Voter], n_candidates: usize, p: Params) -> Outcome {
    let mut rng = rand::rng();
    let total: u64 = voters.iter().map(|v| v.weight).sum();
    let mut cum = Vec::with_capacity(voters.len());
    let mut acc = 0;
    for v in voters {
        acc += v.weight;
        cum.push(acc);
    }

    let mut st: Vec<Option<QuorumState>> = voters
        .iter()
        .map(|v| {
            (!v.byzantine).then(|| QuorumState {
                pref: v.initial.unwrap_or(0),
                counts: vec![0; n_candidates],
                last: None,
                conf: 0,
                decided: None,
            })
        })
        .collect();

    let mut rounds = 0;
    let mut polls = 0u64;
    while rounds < p.max_rounds && st.iter().flatten().any(|s| s.decided.is_none()) {
        rounds += 1;
        // Snapshot of current answers.
        let answers: Vec<Option<usize>> =
            st.iter().map(|s| s.as_ref().map(|s| s.decided.unwrap_or(s.pref))).collect();
        let mut honest_tally = vec![0u64; n_candidates];
        for (i, a) in answers.iter().enumerate() {
            if let Some(a) = a {
                honest_tally[*a] += voters[i].weight;
            }
        }
        let least = (0..n_candidates).min_by_key(|c| honest_tally[*c]).unwrap();

        for s in st.iter_mut().flatten().filter(|s| s.decided.is_none()) {
            polls += 1;
            let mut votes = vec![0usize; n_candidates];
            for _ in 0..p.k {
                let r = rng.random_range(0..total);
                let j = cum.partition_point(|c| *c <= r);
                let ans = answers[j].unwrap_or(least);
                votes[ans] += 1;
            }
            let (best, n) = votes.iter().enumerate().max_by_key(|(_, n)| **n).unwrap();
            if *n >= p.alpha {
                s.counts[best] += 1;
                if s.counts[best] > s.counts[s.pref] {
                    s.pref = best;
                }
                if s.last == Some(best) {
                    s.conf += 1;
                } else {
                    s.last = Some(best);
                    s.conf = 1;
                }
                if s.conf >= p.beta {
                    s.decided = Some(s.pref);
                }
            } else {
                s.conf = 0;
            }
        }
    }
    Outcome {
        decisions: st.iter().map(|s| s.as_ref().and_then(|s| s.decided)).collect(),
        rounds,
        polls,
        undecided_honest: st.iter().flatten().filter(|s| s.decided.is_none()).count(),
    }
}

// ───────────────────────── finality certificates ─────────────────────────

pub fn vote_msg(chain: ChainId, height: u64, block: &Hash) -> Hash {
    Enc::new("pqchain/vote").u8(chain.tag()).u64(height).bytes(block).hash()
}

/// After acceptance, validators sign the block hash. A certificate with more
/// than 2/3 of stake lets a light client trust the block without replaying it.
/// v0 stores raw ML-DSA signatures (~3.3 KB each); v2 compresses them into
/// one STARK proof.
#[derive(Clone, Debug)]
pub struct FinalityCert {
    pub chain: ChainId,
    pub height: u64,
    pub block: Hash,
    pub votes: Vec<(Address, Signature)>,
}

impl FinalityCert {
    pub fn new(chain: ChainId, height: u64, block: Hash) -> Self {
        FinalityCert { chain, height, block, votes: Vec::new() }
    }
    pub fn add_vote(&mut self, key: &Keypair) {
        let sig = key.sign(ctx::VOTE, &vote_msg(self.chain, self.height, &self.block));
        self.votes.push((key.address(), sig));
    }
    pub fn size_bytes(&self) -> usize {
        8 + 32 + self.votes.iter().map(|(_, s)| 32 + s.bytes.len()).sum::<usize>()
    }
}

/// Tier "light client": keeps only the validator set (keys + weights), never
/// the UTXO state. Verifies finality certificates.
pub struct LightClient {
    validators: BTreeMap<Address, (PublicKey, u64)>,
}

impl LightClient {
    pub fn from_ledger(l: &Ledger) -> Self {
        Self::from_validators(&l.validators)
    }

    pub fn from_validators(set: &crate::ledger::ValidatorSet) -> Self {
        LightClient {
            validators: set
                .values()
                .filter(|v| !v.slashed)
                .map(|v| (v.node_id, (v.signing_key.clone(), v.weight())))
                .collect(),
        }
    }

    pub fn verify(&self, cert: &FinalityCert) -> Result<u64, String> {
        let total: u64 = self.validators.values().map(|(_, w)| w).sum();
        let msg = vote_msg(cert.chain, cert.height, &cert.block);
        let mut seen = BTreeSet::new();
        let mut signed = 0u64;
        for (who, sig) in &cert.votes {
            let (pk, w) = self.validators.get(who).ok_or("vote from unknown validator")?;
            if !seen.insert(*who) {
                return Err("duplicate vote".into());
            }
            if !pk.verify(ctx::VOTE, &msg, sig) {
                return Err("invalid vote signature".into());
            }
            signed += w;
        }
        if signed * 3 > total * 2 {
            Ok(signed * 100 / total)
        } else {
            Err(format!("only {}% of stake signed (need > 66%)", signed * 100 / total))
        }
    }
}
