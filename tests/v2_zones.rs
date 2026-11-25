//! v2: zones (application chains) and relay messages proven by finality certificates.

use pqchain::codec::Wire;
use pqchain::consensus::FinalityCert;
use pqchain::crypto::*;
use pqchain::ledger::*;
use pqchain::network::native_transfer;

struct Net {
    vals: Vec<Keypair>,
    alice: Keypair,
    l: Ledger,
}

const Z: ChainId = ChainId::Zone(0);

fn net() -> Net {
    let vals: Vec<Keypair> = (0..4).map(|_| Keypair::generate()).collect();
    let alice = Keypair::generate();
    let l = Ledger::genesis(
        vals.iter()
            .map(|v| GenesisValidator { signing_key: v.public.clone(), withdrawal: v.address(), stake: 2_000 })
            .collect(),
        &[(alice.address(), 100_000)],
    );
    let mut n = Net { vals, alice, l };
    n.l.kerckhoffs_utxos.insert(OutPoint { txid: [7; 32], index: 0 }, TxOut::native(n.alice.address(), 1_000));
    n
}

impl Net {
    fn key(&self, a: Address) -> &Keypair {
        self.vals.iter().find(|k| k.address() == a).unwrap()
    }
    /// Produce and apply the next block on `chain`; returns it.
    fn block(&mut self, chain: ChainId, body: Body) -> Result<Block, String> {
        let (h, parent) = self.l.tip(chain);
        let who = self.l.scheduled_proposer(chain, h + 1, &parent, 0, self.l.current_anchor()).ok_or("no proposer")?;
        let b = propose_on(&self.l, self.key(who), chain, body, h + 1, 0);
        self.l.apply_block(&b)?;
        Ok(b)
    }
    /// Finality certificate for `b` signed by `signers`.
    fn cert(&self, b: &Block, signers: &[usize]) -> FinalityCert {
        let mut c = FinalityCert::new(b.header().chain, b.header().height, b.hash());
        for i in signers {
            c.add_vote(&self.vals[*i]);
        }
        c
    }
    fn create_zone(&mut self, members: &[usize]) -> Result<(), String> {
        let spend = (OutPoint { txid: [7; 32], index: 0 }, Source::Local, &self.alice);
        let base = Transfer::spend(&[spend], vec![TxOut::native(self.alice.address(), 1_000 - ZONE_FEE)]);
        let kind = KerckhoffsKind::CreateZone {
            name: "games".into(),
            members: members.iter().map(|i| self.vals[*i].address()).collect(),
        };
        let tx = KerckhoffsTx { base, kind }.sign(&[&self.alice]);
        self.block(ChainId::Kerckhoffs, Body::Kerckhoffs(vec![tx])).map(|_| ())
    }
    /// Export `amount` from alice on `from` to alice on `to`; returns (block, proof).
    fn export(&mut self, from: ChainId, to: ChainId, amount: u64, signers: &[usize]) -> (Block, RelayIn) {
        let ex = Some((to, vec![TxOut::native(self.alice.address(), amount)]));
        let (base, n) = native_transfer(&self.l, from, Source::Local, &self.alice, vec![], ex, 0).unwrap();
        let tx = AtbashTx { base, create_asset: None }.sign_for(from, &vec![&self.alice; n]);
        let b = self.block(from, Body::Atbash(vec![tx])).unwrap();
        let msgs = b.messages();
        assert_eq!(msgs.len(), 1);
        let hashes: Vec<Hash> = msgs.iter().map(RelayMsg::hash).collect();
        let proof = RelayIn {
            msg: msgs[0].clone(),
            header: b.header().clone(),
            cert: self.cert(&b, signers),
            leaf: 0,
            branch: merkle_branch(&hashes, 0),
        };
        (b, proof)
    }
    fn claim(&self, chain: ChainId, proof: RelayIn) -> AtbashTx {
        let amount = proof.msg.out.amount;
        let mut base = Transfer::spend(
            &[(proof.msg.outpoint(), Source::Relay, &self.alice)],
            vec![TxOut::native(self.alice.address(), amount - TX_FEE)],
        );
        base.relay_in = vec![proof];
        AtbashTx { base, create_asset: None }.sign_for(chain, &[&self.alice])
    }
}

#[test]
fn merkle_branches_verify_and_reject_tampering() {
    for n in 1..=9usize {
        let leaves: Vec<Hash> = (0..n as u8).map(|i| [i; 32]).collect();
        let root = merkle_root(&leaves);
        for i in 0..n {
            let br = merkle_branch(&leaves, i);
            assert!(merkle_verify(&leaves[i], i as u32, &br, &root), "n={n} i={i}");
            assert!(!merkle_verify(&[99; 32], i as u32, &br, &root));
            if (i ^ 1) < n {
                // The same path does not prove the leaf at its sibling's position.
                assert!(!merkle_verify(&leaves[i], (i as u32) ^ 1, &br, &root));
            }
        }
    }
}

#[test]
fn zone_registration_rules() {
    let mut n = net();
    let outsider = Keypair::generate().address();
    let bad = |n: &Net, members: Vec<Address>| {
        let spend = (OutPoint { txid: [7; 32], index: 0 }, Source::Local, &n.alice);
        let base = Transfer::spend(&[spend], vec![TxOut::native(n.alice.address(), 900)]);
        let tx = KerckhoffsTx { base, kind: KerckhoffsKind::CreateZone { name: "z".into(), members } }.sign(&[&n.alice]);
        n.l.clone().apply_kerckhoffs(&tx)
    };
    assert!(bad(&n, vec![]).is_err(), "no members");
    assert!(bad(&n, vec![outsider]).unwrap_err().contains("not an active primary validator"));
    let v0 = n.vals[0].address();
    assert!(bad(&n, vec![v0, v0]).unwrap_err().contains("duplicate"));
    n.create_zone(&[0, 1, 2]).unwrap();
    assert!(n.l.knows(Z));
    assert_eq!(n.l.zones[&0].members.len(), 3);
    // Only members are ever scheduled to propose zone blocks.
    let (h, p) = n.l.tip(Z);
    for round in 0..50 {
        let who = n.l.scheduled_proposer(Z, h + 1, &p, round, n.l.current_anchor()).unwrap();
        assert_ne!(who, n.vals[3].address());
    }
    // A non-member's zone block is rejected.
    let b = propose_on(&n.l, &n.vals[3], Z, Body::Atbash(vec![]), 1, 0);
    assert!(n.l.clone().apply_block(&b).is_err());
}

#[test]
fn relay_atbash_to_zone_and_back() {
    let mut n = net();
    n.create_zone(&[0, 1, 2]).unwrap();

    // Atbash -> Zone 0: the message is proven by a primary-validator certificate (3 of 4).
    let (_, proof) = n.export(ChainId::Atbash, Z, 5_000, &[0, 1, 3]);
    assert!(n.l.atomic.is_empty(), "relay transfers do not use atomic memory");
    let claim = n.claim(Z, proof.clone());
    let claim = AtbashTx::from_bytes(&claim.to_bytes()).unwrap(); // proofs survive the wire
    n.block(Z, Body::Atbash(vec![claim.clone()])).unwrap();
    assert_eq!(n.l.balance(Z, &n.alice.address(), &NATIVE), 4_999);

    // Claiming the same message twice fails.
    let mut again = n.l.clone();
    assert!(again.apply_utxo(Z, &n.claim(Z, proof)).unwrap_err().contains("already claimed"));

    // Zone 0 -> Atbash: proven by a zone-member certificate (2 of 3 members is not enough...).
    let (_, weak) = n.export(Z, ChainId::Atbash, 1_000, &[0, 1]);
    assert!(n.l.clone().apply_utxo(ChainId::Atbash, &n.claim(ChainId::Atbash, weak.clone())).is_err());
    // ...but 3 of 3 members is.
    let mut strong = weak;
    strong.cert = FinalityCert::new(Z, strong.header.height, strong.header.hash());
    for i in [0, 1, 2] {
        strong.cert.add_vote(&n.vals[i]);
    }
    let back = n.claim(ChainId::Atbash, strong);
    n.block(ChainId::Atbash, Body::Atbash(vec![back])).unwrap();
    assert!(n.l.balance(ChainId::Atbash, &n.alice.address(), &NATIVE) > 90_000);
}

#[test]
fn forged_relay_proofs_are_rejected() {
    let mut n = net();
    n.create_zone(&[0, 1, 2]).unwrap();
    let (_, proof) = n.export(ChainId::Atbash, Z, 5_000, &[0, 1, 2]);
    let try_claim = |p: RelayIn| n.l.clone().apply_utxo(Z, &n.claim(Z, p));

    let mut inflated = proof.clone();
    inflated.msg.out.amount = 5_000_000;
    assert!(try_claim(inflated).unwrap_err().contains("not included"));

    let mut stolen = proof.clone();
    stolen.msg.out.owner = n.vals[3].address();
    assert!(try_claim(stolen).is_err());

    let mut minority = proof.clone();
    minority.cert = n.cert(&Block { signed: SignedHeader { header: proof.header.clone(), sig: Signature::empty() }, body: Body::Atbash(vec![]) }, &[0, 1]);
    assert!(try_claim(minority).unwrap_err().contains("certificate"));

    let mut outsider_votes = proof.clone();
    let rogue = Keypair::generate();
    outsider_votes.cert.votes = vec![(rogue.address(), rogue.sign(ctx::VOTE, b"x"))];
    assert!(try_claim(outsider_votes).is_err());

    let mut rewritten = proof.clone();
    rewritten.header.timestamp += 1; // header no longer matches the certificate
    assert!(try_claim(rewritten).unwrap_err().contains("does not match"));

    let mut misrouted = proof.clone();
    misrouted.msg.dest = ChainId::Zone(9);
    assert!(try_claim(misrouted).is_err());

    // The genuine proof works.
    assert!(try_claim(proof).is_ok());
}

#[test]
fn kerckhoffs_and_zones_do_not_exchange_directly_and_roots_are_checked() {
    let mut n = net();
    n.create_zone(&[0, 1, 2]).unwrap();
    let ex = Some((Z, vec![TxOut::native(n.alice.address(), 10)]));
    let (base, k) = native_transfer(&n.l, ChainId::Kerckhoffs, Source::Local, &n.alice, vec![], ex, 0).unwrap();
    let tx = KerckhoffsTx { base, kind: KerckhoffsKind::Transfer }.sign(&vec![&n.alice; k]);
    assert!(n.l.clone().apply_kerckhoffs(&tx).unwrap_err().contains("not Kerckhoffs"));

    // A block whose header lies about its relay messages is rejected.
    let ex = Some((Z, vec![TxOut::native(n.alice.address(), 10)]));
    let (base, k) = native_transfer(&n.l, ChainId::Atbash, Source::Local, &n.alice, vec![], ex, 0).unwrap();
    let tx = AtbashTx { base, create_asset: None }.sign(&vec![&n.alice; k]);
    let (h, parent) = n.l.tip(ChainId::Atbash);
    let who = n.l.scheduled_proposer(ChainId::Atbash, h + 1, &parent, 0, n.l.current_anchor()).unwrap();
    let mut b = propose_on(&n.l, n.key(who), ChainId::Atbash, Body::Atbash(vec![tx]), 1, 0);
    b.signed.header.msg_root = [0; 32];
    b.signed.sig = n.key(who).sign(ctx::BLOCK, &b.signed.header.hash());
    assert!(n.l.clone().apply_block(&b).unwrap_err().contains("relay message root"));

    // Zone signatures are domain-separated from Atbash signatures.
    let (base, k) = native_transfer(&n.l, ChainId::Atbash, Source::Local, &n.alice, vec![TxOut::native(n.vals[0].address(), 5)], None, 0).unwrap();
    let atbash_signed = AtbashTx { base, create_asset: None }.sign(&vec![&n.alice; k]);
    assert!(n.l.clone().apply_utxo(Z, &atbash_signed).is_err());
}
