//! In-process testnet: validator nodes and full nodes, each with its own
//! ledger replica, plus wallet helpers. (v0 simulates the network in one
//! process; v1 replaces this with real P2P over ML-KEM-768 + X25519.)

use crate::consensus::{sampled_quorum, FinalityCert, LightClient, Params, Voter};
use crate::crypto::*;
use crate::ledger::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Tier 1: stakes, proposes, votes, re-executes everything.
    Validator,
    /// No stake: re-executes and stores everything, serves RPC.
    FullNode,
}

pub struct Node {
    pub name: String,
    pub role: Role,
    /// Hot block-signing key (validators only).
    pub key: Option<Keypair>,
    pub ledger: Ledger,
}

pub struct Network {
    pub nodes: Vec<Node>,
    pub params: Params,
    pub clock: u64,
}

#[derive(Debug)]
pub struct Report {
    pub chain: ChainId,
    pub height: u64,
    pub winner: usize,
    pub rounds: u32,
    pub polls: u64,
    pub cert_votes: usize,
    pub cert_bytes: usize,
    pub light_client_stake_pct: u64,
}

impl Network {
    /// Reference ledger (all honest replicas are identical; checked by tests).
    pub fn ledger(&self) -> &Ledger {
        &self.nodes.iter().find(|n| n.role == Role::FullNode).unwrap_or(&self.nodes[0]).ledger
    }

    pub fn node_by_addr(&self, a: &Address) -> Option<&Node> {
        self.nodes.iter().find(|n| n.key.as_ref().map(|k| k.address()) == Some(*a))
    }

    /// The validator scheduled to propose the next block on `chain`.
    pub fn next_proposer(&self, chain: ChainId) -> &Node {
        let l = self.ledger();
        let (h, parent) = l.tip(chain);
        let a = l.scheduled_proposer(chain, h + 1, &parent).expect("no validators");
        self.node_by_addr(&a).expect("proposer node not running")
    }

    pub fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    /// Run consensus over competing candidate blocks for the next height of
    /// one chain and apply the winner on every replica.
    ///
    /// * `split(i)`: which candidate honest validator `i` hears about first.
    /// * `byzantine`: validators that vote adversarially.
    pub fn finalize(
        &mut self,
        candidates: &[Block],
        split: impl Fn(usize) -> usize,
        byzantine: &[Address],
    ) -> Result<Report, String> {
        let chain = candidates[0].header().chain;
        let height = candidates[0].header().height;
        let pre = self.ledger().clone();

        // Each validator independently re-executes every candidate.
        let mut voters = Vec::new();
        let mut voter_nodes = Vec::new();
        for (i, n) in self.nodes.iter().enumerate().filter(|(_, n)| n.role == Role::Validator) {
            let addr = n.key.as_ref().unwrap().address();
            let weight = pre.validators.get(&addr).map_or(0, |v| v.weight());
            if weight == 0 {
                continue; // not (or no longer) an active validator
            }
            let valid: Vec<bool> =
                candidates.iter().map(|b| n.ledger.clone().apply_block(b).is_ok()).collect();
            let first = split(voters.len()) % candidates.len();
            let initial = if valid[first] { Some(first) } else { valid.iter().position(|v| *v) };
            voters.push(Voter { weight, byzantine: byzantine.contains(&addr), initial });
            voter_nodes.push(i);
        }
        if voters.iter().all(|v| v.byzantine || v.initial.is_none()) {
            return Err("no valid candidate block".into());
        }

        let out = sampled_quorum(&voters, candidates.len(), self.params);
        let winner = out.agreed().ok_or("consensus did not converge")?;
        let block = &candidates[winner];

        // Every replica (validators + full nodes) applies the accepted block.
        for n in &mut self.nodes {
            n.ledger.apply_block(block).map_err(|e| format!("{}: {e}", n.name))?;
        }

        // Honest validators sign a finality certificate for light clients.
        let mut cert = FinalityCert::new(chain, height, block.hash());
        for (vi, ni) in voter_nodes.iter().enumerate() {
            if !voters[vi].byzantine {
                cert.add_vote(self.nodes[*ni].key.as_ref().unwrap());
            }
        }
        let pct = LightClient::from_ledger(&pre).verify(&cert)?;

        Ok(Report {
            chain,
            height,
            winner,
            rounds: out.rounds,
            polls: out.polls,
            cert_votes: cert.votes.len(),
            cert_bytes: cert.size_bytes(),
            light_client_stake_pct: pct,
        })
    }
}

// ───────────────────────────── wallet helpers ─────────────────────────────

/// Pick native outputs owned by `owner` until `need` is covered.
pub fn select_native(
    l: &Ledger,
    chain: ChainId,
    source: Source,
    owner: &Address,
    need: u64,
) -> Result<(Vec<OutPoint>, u64), String> {
    let pool = match source {
        Source::Local => l.utxos_of(chain, owner),
        Source::Atomic => l.atomic_of(chain, owner),
    };
    let mut picked = Vec::new();
    let mut total = 0;
    for (p, o) in pool.into_iter().filter(|(_, o)| o.asset == NATIVE) {
        if total >= need {
            break;
        }
        picked.push(p);
        total += o.amount;
    }
    if total < need {
        return Err(format!("insufficient funds: have {total}, need {need}"));
    }
    Ok((picked, total))
}

/// Build an unsigned native transfer from `from`, with change back to `from`.
/// `locked` is value consumed without an output (stake).
pub fn native_transfer(
    l: &Ledger,
    chain: ChainId,
    source: Source,
    from: &Keypair,
    outputs: Vec<TxOut>,
    export: Option<(ChainId, Vec<TxOut>)>,
    locked: u64,
) -> Result<(Transfer, usize), String> {
    let sent: u64 = outputs.iter().chain(export.iter().flat_map(|(_, e)| e)).map(|o| o.amount).sum();
    let need = sent + locked + TX_FEE;
    let (ins, total) = select_native(l, chain, source, &from.address(), need)?;
    let spends: Vec<_> = ins.iter().map(|p| (*p, source, from)).collect();
    let mut outs = outputs;
    if total > need {
        outs.push(TxOut::native(from.address(), total - need));
    }
    let mut t = Transfer::spend(&spends, outs);
    if let Some((dest, e)) = export {
        t.export_to = Some(dest);
        t.exported = e;
    }
    Ok((t, spends.len()))
}
