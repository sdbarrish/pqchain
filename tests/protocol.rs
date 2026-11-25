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
    let s = l.scheduled_proposer(c, h + 1, &p).unwrap();
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
            (0..10).map(|i| Voter { weight: 1, byzantine: i < 2, initial: Some(i % 2) }).collect();
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
