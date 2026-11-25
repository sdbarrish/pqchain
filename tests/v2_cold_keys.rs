//! v2: SLH-DSA cold keys, validator exit and unbonding.

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
    let cold: Vec<Keypair> = (0..4).map(|_| Keypair::generate_slh()).collect();
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
    /// Produce and apply the next Kerckhoffs block with `txs`.
    fn k_block(&mut self, txs: Vec<KerckhoffsTx>) -> Result<(), String> {
        let (h, parent) = self.l.tip(ChainId::Kerckhoffs);
        let who = self.l.scheduled_proposer(ChainId::Kerckhoffs, h + 1, &parent, 0, self.l.current_anchor()).unwrap();
        let key = self.hot.iter().find(|k| k.address() == who).unwrap();
        let b = propose(&self.l, key, Body::Kerckhoffs(txs), h + 1);
        self.l.apply_block(&b)
    }
}

#[test]
fn slh_dsa_keys_sign_verify_and_are_deterministic() {
    let k = Keypair::generate_slh();
    assert_eq!(k.alg(), ALG_SLH_DSA_SHAKE_128S);
    let s = k.sign(ctx::EXIT, b"leave");
    assert_eq!((k.public.bytes.len(), s.bytes.len()), (SLH_PK_LEN, SLH_SIG_LEN));
    assert!(k.public.verify(ctx::EXIT, b"leave", &s));
    assert!(!k.public.verify(ctx::BLOCK, b"leave", &s), "context binds");
    assert!(!k.public.verify(ctx::EXIT, b"stay", &s));
    let again = Keypair::from_seed_alg(ALG_SLH_DSA_SHAKE_128S, k.seed()).unwrap();
    assert_eq!(again.public, k.public, "same seed, same key");
    // An SLH-DSA signature must never pass as ML-DSA and vice versa.
    let ml = Keypair::generate();
    assert!(!ml.public.verify(ctx::EXIT, b"leave", &s));
    let ml_sig = ml.sign(ctx::EXIT, b"leave");
    assert!(!k.public.verify(ctx::EXIT, b"leave", &ml_sig));
}

#[test]
fn exit_unbonds_then_returns_stake_to_cold_address() {
    let mut n = net();
    let node = n.hot[1].address();
    let cold_addr = n.cold[1].address();
    n.l.delegations.push(Delegation { node, stake: 300, reward: n.cold[0].address() });
    n.l.validators.get_mut(&node).unwrap().delegated = 300;
    let before = n.l.total_weight();

    let exit = KerckhoffsTx::exit(node, &n.cold[1]);
    let exit = KerckhoffsTx::from_bytes(&exit.to_bytes()).unwrap(); // survives the wire
    n.k_block(vec![exit]).unwrap();
    let release = n.l.validators[&node].exit_at.unwrap();
    assert_eq!(release, 1 + UNBONDING_BLOCKS);
    assert_eq!(n.l.validators[&node].weight(), 0, "exiting validator stops voting at once");
    assert_eq!(n.l.total_weight(), before - 2_300);

    while n.l.tip(ChainId::Kerckhoffs).0 < release - 1 {
        n.k_block(vec![]).unwrap();
        assert!(n.l.validators.contains_key(&node), "still bonded (slashable) during unbonding");
    }
    n.k_block(vec![]).unwrap();
    assert!(!n.l.validators.contains_key(&node), "removed after unbonding");
    assert_eq!(n.l.balance(ChainId::Kerckhoffs, &cold_addr, &NATIVE), 2_000);
    assert_eq!(n.l.balance(ChainId::Kerckhoffs, &n.cold[0].address(), &NATIVE), 300, "delegator refunded");
}

#[test]
fn exit_requires_the_withdrawal_key() {
    let mut n = net();
    let node = n.hot[2].address();
    // Signed by the hot block key (stolen-hot-key scenario): rejected.
    assert!(n.l.clone().apply_kerckhoffs(&KerckhoffsTx::exit(node, &n.hot[2])).unwrap_err().contains("withdrawal key"));
    // Another validator's cold key: rejected.
    assert!(n.l.clone().apply_kerckhoffs(&KerckhoffsTx::exit(node, &n.cold[3])).is_err());
    // Tampered signature: rejected.
    let mut t = KerckhoffsTx::exit(node, &n.cold[2]);
    if let KerckhoffsKind::Exit { sig, .. } = &mut t.kind {
        sig.bytes[10] ^= 1;
    }
    assert!(n.l.clone().apply_kerckhoffs(&t).unwrap_err().contains("invalid exit signature"));
    // Correct key: accepted once, not twice.
    let ok = KerckhoffsTx::exit(node, &n.cold[2]);
    n.l.apply_kerckhoffs(&ok).unwrap();
    assert!(n.l.apply_kerckhoffs(&ok).is_err());
}

#[test]
fn misbehaviour_during_unbonding_is_still_slashed() {
    let mut n = net();
    let node = n.hot[0].address();
    // Two conflicting headers signed by validator 0 (evidence collected earlier).
    let a = propose(&n.l, &n.hot[0], Body::Atbash(vec![]), 1).signed;
    let b = propose(&n.l, &n.hot[0], Body::Atbash(vec![]), 2).signed;
    n.k_block(vec![KerckhoffsTx::exit(node, &n.cold[0])]).unwrap();
    let burned = n.l.burned;
    let slash = KerckhoffsTx { base: Transfer::default(), kind: KerckhoffsKind::Slash { a: Box::new(a), b: Box::new(b) } };
    n.k_block(vec![slash]).unwrap();
    assert!(n.l.validators[&node].slashed);
    assert_eq!(n.l.burned, burned + 2_000);
    for _ in 0..UNBONDING_BLOCKS + 1 {
        n.k_block(vec![]).unwrap();
    }
    assert_eq!(n.l.balance(ChainId::Kerckhoffs, &n.cold[0].address(), &NATIVE), 0, "nothing released");
}

#[test]
fn validator_hot_key_must_be_ml_dsa() {
    let n = net();
    let mut l = n.l.clone();
    l.kerckhoffs_utxos.insert(OutPoint { txid: [9; 32], index: 0 }, TxOut::native(n.hot[0].address(), 10_000));
    let slh_hot = Keypair::generate_slh();
    let base = Transfer::spend(&[(OutPoint { txid: [9; 32], index: 0 }, Source::Local, &n.hot[0])], vec![]);
    let tx = KerckhoffsTx {
        base,
        kind: KerckhoffsKind::AddValidator { signing_key: slh_hot.public.clone(), withdrawal: n.cold[0].address(), stake: 5_000 },
    }
    .sign(&[&n.hot[0]]);
    assert!(l.apply_kerckhoffs(&tx).unwrap_err().contains("ML-DSA-65"));
    // And Tx-level wire roundtrip of an exit keeps the SLH-DSA signature intact.
    let t = Tx::Kerckhoffs(KerckhoffsTx::exit(n.hot[0].address(), &n.cold[0]));
    assert_eq!(Tx::from_bytes(&t.to_bytes()).unwrap().id(), t.id());
}
