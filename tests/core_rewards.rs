//! Staking rewards: issuance per block, commission, delegators, claims.

use pqchain::codec::{Tx, Wire};
use pqchain::crypto::*;
use pqchain::ledger::*;

struct Net {
    hot: Vec<Keypair>,
    cold: Vec<Keypair>,
    l: Ledger,
}

fn net() -> Net {
    let hot: Vec<Keypair> = (0..4).map(|_| Keypair::generate()).collect();
    let cold: Vec<Keypair> = (0..4).map(|_| Keypair::generate()).collect();
    let l = Ledger::genesis(
        hot.iter()
            .zip(&cold)
            .map(|(h, c)| GenesisValidator { signing_key: h.public.clone(), withdrawal: c.address(), stake: 2_000 })
            .collect(),
        &[],
    );
    Net { hot, cold, l }
}

impl Net {
    fn k_block(&mut self, txs: Vec<KerckhoffsTx>) -> Result<(), String> {
        let (h, parent) = self.l.tip(ChainId::Kerckhoffs);
        let who = self.l.scheduled_proposer(ChainId::Kerckhoffs, h + 1, &parent, 0, self.l.current_anchor()).unwrap();
        let key = self.hot.iter().find(|k| k.address() == who).unwrap();
        let b = propose(&self.l, key, Body::Kerckhoffs(txs), h + 1);
        self.l.apply_block(&b)
    }
}

#[test]
fn each_block_issues_rewards_by_stake() {
    let mut n = net();
    n.k_block(vec![]).unwrap();
    assert_eq!(n.l.minted, BLOCK_REWARD);
    for c in &n.cold {
        assert_eq!(n.l.rewards[&c.address()], BLOCK_REWARD / 4, "equal stake, equal share");
    }
    n.k_block(vec![]).unwrap();
    assert_eq!(n.l.minted, 2 * BLOCK_REWARD);
}

#[test]
fn delegators_earn_minus_commission() {
    let mut n = net();
    let node = n.hot[0].address();
    let alice = Keypair::generate().address();
    // Validator 0: 2,000 own + 2,000 delegated -> weight 4,000 of 10,000.
    n.l.delegations.push(Delegation { node, stake: 2_000, reward: alice });
    n.l.validators.get_mut(&node).unwrap().delegated = 2_000;
    n.l.validator_history.insert(0, std::sync::Arc::new(n.l.validators.clone()));
    n.k_block(vec![]).unwrap();
    let share = BLOCK_REWARD * 4_000 / 10_000; // 400
    let to_delegators = share / 2; // 200
    let fee = to_delegators * DELEGATION_FEE_BPS / 10_000; // 20
    assert_eq!(n.l.rewards[&alice], to_delegators - fee);
    assert_eq!(n.l.rewards[&n.cold[0].address()], share / 2 + fee);
    assert_eq!(n.l.rewards[&n.cold[1].address()], BLOCK_REWARD * 2_000 / 10_000);
}

#[test]
fn claim_pays_once_and_cannot_be_replayed() {
    let mut n = net();
    n.k_block(vec![]).unwrap();
    let key = Keypair::from_seed(n.cold[2].seed());
    let claim = KerckhoffsTx::claim_rewards(&key, 0);
    let claim = KerckhoffsTx::from_bytes(&claim.to_bytes()).unwrap();
    n.k_block(vec![claim.clone()]).unwrap();
    let paid = n.l.balance(ChainId::Kerckhoffs, &key.address(), &NATIVE);
    assert_eq!(paid, BLOCK_REWARD / 4, "rewards up to the previous block");
    // More rewards accrued (this block), but the same signed claim cannot be reused.
    assert!(n.l.rewards[&key.address()] > 0);
    assert!(n.l.clone().apply_kerckhoffs(&claim).unwrap_err().contains("nonce"));
    // A fresh claim with the next nonce works.
    n.k_block(vec![KerckhoffsTx::claim_rewards(&key, 1)]).unwrap();
    assert!(n.l.balance(ChainId::Kerckhoffs, &key.address(), &NATIVE) > paid);
    // Someone else cannot claim this address's rewards.
    let thief = Keypair::generate();
    let mut forged = KerckhoffsTx::claim_rewards(&thief, 0);
    if let KerckhoffsKind::ClaimRewards { authority, .. } = &mut forged.kind {
        *authority = key.public.clone();
    }
    assert!(n.l.clone().apply_kerckhoffs(&forged).is_err());
    let _ = Tx::Kerckhoffs(forged);
}

#[test]
fn exiting_and_slashed_validators_earn_nothing() {
    let mut n = net();
    let node = n.hot[3].address();
    n.k_block(vec![KerckhoffsTx::exit(node, &n.cold[3])]).unwrap();
    let before = n.l.rewards.get(&n.cold[3].address()).copied().unwrap_or(0);
    n.k_block(vec![]).unwrap();
    n.k_block(vec![]).unwrap();
    assert_eq!(n.l.rewards.get(&n.cold[3].address()).copied().unwrap_or(0), before);
    assert_eq!(n.l.rewards[&n.cold[0].address()], BLOCK_REWARD / 4 + 2 * (BLOCK_REWARD / 3));
}
