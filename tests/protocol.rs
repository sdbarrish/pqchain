use pqchain::consensus::*;
use pqchain::crypto::*;
use pqchain::ledger::*;
use pqchain::network::native_transfer;

fn setup() -> (Vec<Keypair>, Keypair, Keypair, Ledger) {
    let vals: Vec<Keypair> = (0..4).map(|_| Keypair::generate()).collect();
    let (a, b) = (Keypair::generate(), Keypair::generate());
    let l = Ledger::genesis(
        vals.iter()
            .map(|v| GenesisValidator { signing_key: v.public.clone(), withdrawal: v.address(), stake: 2_000 })
            .collect(),
        &[(a.address(), 1_000)],
    );
    (vals, a, b, l)
}

fn proposer<'a>(vals: &'a [Keypair], l: &Ledger, c: ChainId) -> &'a Keypair {
    let (h, p) = l.tip(c);
    let s = l.scheduled_proposer(c, h + 1, &p, 0, l.current_anchor()).unwrap();
    vals.iter().find(|k| k.address() == s).unwrap()
}

#[test]
fn ml_dsa_sign_verify_and_domain_separation() {
    let k = Keypair::generate();
    let s = k.sign(ctx::ATBASH_TX, b"m");
    assert!(k.public.verify(ctx::ATBASH_TX, b"m", &s));
    assert!(!k.public.verify(ctx::KERCKHOFFS_TX, b"m", &s), "context must bind");
    assert!(!k.public.verify(ctx::ATBASH_TX, b"n", &s));
    assert_eq!((k.public.bytes.len(), s.bytes.len()), (VK_LEN, SIG_LEN));
}

#[test]
fn double_spend_inside_one_block_rejected() {
    let (vals, a, b, l) = setup();
    let (base, n) = native_transfer(&l, ChainId::Atbash, Source::Local, &a, vec![TxOut::native(b.address(), 10)], None, 0).unwrap();
    let t1 = AtbashTx { base: base.clone(), create_asset: None }.sign(&vec![&a; n]);
    let mut base2 = base;
    base2.outputs[0].amount = 11;
    let t2 = AtbashTx { base: base2, create_asset: None }.sign(&vec![&a; n]);
    let blk = propose(&l, proposer(&vals, &l, ChainId::Atbash), Body::Atbash(vec![t1, t2]), 1);
    let mut l2 = l.clone();
    assert!(l2.apply_block(&blk).unwrap_err().contains("double-spend"));
    assert_eq!(l2.state_root(), l.state_root(), "failed block must not change state");
}

#[test]
fn tampered_block_rejected() {
    let (vals, _, _, l) = setup();
    let mut blk = propose(&l, proposer(&vals, &l, ChainId::Atbash), Body::Atbash(vec![]), 1);
    blk.signed.header.timestamp = 2;
    assert!(l.clone().apply_block(&blk).is_err());
}

#[test]
fn equivocation_slashes_and_refunds_delegators() {
    let (vals, _, _, mut l) = setup();
    let p = proposer(&vals, &l, ChainId::Atbash);
    l.delegations.push(Delegation { node: p.address(), stake: 100, reward: vals[0].address() });
    l.validators.get_mut(&p.address()).unwrap().delegated = 100;
    let a = propose(&l, p, Body::Atbash(vec![]), 1);
    let b = propose(&l, p, Body::Atbash(vec![]), 2);
    let tx = KerckhoffsTx { base: Transfer::default(), kind: KerckhoffsKind::Slash { a: Box::new(a.signed), b: Box::new(b.signed) } };
    l.apply_kerckhoffs(&tx).unwrap();
    assert!(l.validators[&p.address()].slashed);
    assert_eq!(l.balance(ChainId::Kerckhoffs, &vals[0].address(), &NATIVE), 100);
    assert!(l.apply_kerckhoffs(&tx).is_err(), "cannot slash twice");
}

#[test]
fn export_import_moves_value_exactly_once() {
    let (_, a, _, mut l) = setup();
    let (base, n) = native_transfer(&l, ChainId::Atbash, Source::Local, &a, vec![], Some((ChainId::Kerckhoffs, vec![TxOut::native(a.address(), 500)])), 0).unwrap();
    l.apply_atbash(&AtbashTx { base, create_asset: None }.sign(&vec![&a; n])).unwrap();
    let (base, n) = native_transfer(&l, ChainId::Kerckhoffs, Source::Atomic, &a, vec![TxOut::native(a.address(), 499)], None, 0).unwrap();
    let imp = KerckhoffsTx { base, kind: KerckhoffsKind::Transfer }.sign(&vec![&a; n]);
    l.clone().apply_kerckhoffs(&imp).unwrap();
    let mut l2 = l.clone();
    l2.apply_kerckhoffs(&imp).unwrap();
    assert!(l2.apply_kerckhoffs(&imp).is_err(), "import replay must fail");
    assert_eq!(l2.balance(ChainId::Kerckhoffs, &a.address(), &NATIVE), 499);
}

#[test]
fn sampled_quorum_is_safe_and_live_with_20pct_byzantine() {
    for _ in 0..20 {
        let voters: Vec<Voter> =
            (0..10).map(|i| Voter { weight: 1, byzantine: i < 2, offline: false, initial: Some(i % 2) }).collect();
        let o = sampled_quorum(&voters, 2, Params::default());
        assert!(o.agreed().is_some(), "honest nodes must agree: {o:?}");
    }
}

#[test]
fn light_client_rejects_minority_and_forged_votes() {
    let (vals, _, _, l) = setup();
    let lc = LightClient::from_ledger(&l);
    let mut c = FinalityCert::new(ChainId::Atbash, 1, [1; 32]);
    for v in &vals[..3] {
        c.add_vote(v);
    }
    assert!(lc.verify(&c).is_ok()); // 75% > 2/3
    c.votes.pop();
    assert!(lc.verify(&c).is_err()); // 50%
    c.add_vote(&vals[3]);
    c.votes[0].1.bytes[5] ^= 1;
    assert!(lc.verify(&c).is_err());
}

/// Regression (found by the `supply` fuzzer): a transaction rejected late in
/// validation (here, a delegation over the 5x cap) must leave no partial
/// effects behind: inputs unspent, nothing burned.
#[test]
fn rejected_transactions_leave_no_partial_effects() {
    let (vals, a, _, mut l) = setup();
    l.kerckhoffs_utxos.insert(OutPoint { txid: [9; 32], index: 0 }, TxOut::native(a.address(), 900_000));
    let before = l.state_root();
    let (base, n) = native_transfer(&l, ChainId::Kerckhoffs, Source::Local, &a, vec![], None, 60_000).unwrap();
    let kind = KerckhoffsKind::AddDelegator { node: vals[0].address(), stake: 60_000, reward: a.address() };
    let tx = KerckhoffsTx { base, kind }.sign(&vec![&a; n]);
    assert!(l.apply_kerckhoffs(&tx).unwrap_err().contains("cap"));
    assert_eq!(l.state_root(), before, "state changed by a rejected transaction");
    assert_eq!(l.burned, 0);
}

/// Regression (found by examples/consensus_analysis): alpha=12 of k=20 let a
/// split-brain adversary with 20% of stake make honest validators finalize
/// different blocks. The defaults (alpha=14) must not, and genesis files with
/// alpha below 70% of k are rejected.
#[test]
fn consensus_params_resist_split_brain() {
    use pqchain::consensus::Adversary;
    use pqchain::node::ConsensusParams;
    let run = |alpha: usize, beta: u32| {
        let p = Params { k: 20, alpha, beta, max_rounds: 1_500, adversary: Adversary::SplitBrain };
        (0..100)
            .filter(|_| {
                let voters: Vec<Voter> =
                    (0..10).map(|i| Voter { weight: 1, byzantine: i < 2, offline: false, initial: Some(i % 2) }).collect();
                let o = sampled_quorum(&voters, 2, p);
                o.decisions.iter().flatten().collect::<std::collections::BTreeSet<_>>().len() > 1
            })
            .count()
    };
    assert!(run(12, 15) > 0, "the old testnet setting is expected to be breakable");
    assert_eq!(run(14, 20), 0, "default setting must stay safe at 20% byzantine");
    assert!(ConsensusParams { k: 20, alpha: 12, beta: 15 }.validate().is_err());
    assert!(ConsensusParams::default().validate().is_ok());
}
