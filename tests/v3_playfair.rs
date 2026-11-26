//! Playfair bridges between two independent networks (A and B), with
//! on-chain light clients, escrow, wrapped tokens and attack cases.

use pqchain::codec::Wire;
use pqchain::consensus::FinalityCert;
use pqchain::crypto::*;
use pqchain::ledger::*;
use pqchain::network::native_transfer;
use pqchain::playfair::*;

struct Net {
    vals: Vec<Keypair>,
    user: Keypair,
    l: Ledger,
}

fn net(tag: u8) -> Net {
    let vals: Vec<Keypair> = (0..4).map(|i| Keypair::from_seed([tag * 16 + i; 32])).collect();
    let user = Keypair::from_seed([tag * 16 + 9; 32]);
    let mut l = Ledger::genesis(
        vals.iter().map(|v| GenesisValidator { signing_key: v.public.clone(), withdrawal: v.address(), stake: 2_000 }).collect(),
        &[],
    );
    l.network_id = [tag; 32];
    l.playfair_utxos.insert(OutPoint { txid: [tag; 32], index: 0 }, TxOut::native(user.address(), 100_000));
    Net { vals, user, l }
}

impl Net {
    fn block(&mut self, chain: ChainId, body: Body) -> Block {
        let (h, p) = self.l.tip(chain);
        let who = self.l.scheduled_proposer(chain, h + 1, &p, 0, self.l.current_anchor()).unwrap();
        let key = self.vals.iter().find(|k| k.address() == who).unwrap();
        let b = propose_on(&self.l, key, chain, body, h + 1, 0);
        self.l.apply_block(&b).unwrap();
        b
    }
    fn cert(&self, b: &Block, signers: &[usize]) -> FinalityCert {
        let mut c = FinalityCert::new(b.header().chain, b.header().height, b.hash());
        for i in signers {
            c.add_vote(&self.vals[*i]);
        }
        c
    }
    fn pf(&mut self, txs: Vec<PlayfairTx>) -> Block {
        self.block(ChainId::Playfair, Body::Playfair(txs))
    }
    fn send(&self, dest: Hash, to: Address, amount: u64, origin: Hash) -> PlayfairTx {
        let kind = PlayfairKind::Send { dest_network: dest, recipient: to, origin, amount };
        if origin == self.l.network_id {
            let (base, n) = native_transfer(&self.l, ChainId::Playfair, Source::Local, &self.user, vec![], None, amount).unwrap();
            PlayfairTx { base, kind }.sign(&vec![&self.user; n])
        } else {
            let w = wrapped_asset(&origin);
            let mut ins: Vec<OutPoint> = Vec::new();
            let (mut hw, mut hn) = (0, 0);
            for (p, o) in self.l.utxos_of(ChainId::Playfair, &self.user.address()) {
                if o.asset == w && hw < amount { ins.push(p); hw += o.amount }
                else if o.asset == NATIVE && hn < TX_FEE { ins.push(p); hn += o.amount }
            }
            let mut outs = vec![TxOut::native(self.user.address(), hn - TX_FEE)];
            if hw > amount { outs.push(TxOut { owner: self.user.address(), asset: w, amount: hw - amount }); }
            let spends: Vec<_> = ins.iter().map(|p| (*p, Source::Local, &self.user)).collect();
            PlayfairTx { base: Transfer::spend(&spends, outs), kind }.sign(&vec![&self.user; spends.len()])
        }
    }
}

/// `local` registers `remote` at its current Kerckhoffs height.
fn register(local: &mut Net, remote: &Net) {
    let k = remote.l.current_anchor();
    let validators = from_ledger_set(remote.l.validators_at(k).unwrap());
    let (base, n) = native_transfer(&local.l, ChainId::Playfair, Source::Local, &local.user, vec![], None, REGISTER_FEE - TX_FEE).unwrap();
    let kind = PlayfairKind::Register { network_id: remote.l.network_id, name: "peer".into(), k_height: k, validators };
    let tx = PlayfairTx { base, kind }.sign(&vec![&local.user; n]);
    local.pf(vec![tx]);
}

fn update(remote: &Net, b: &Block, signers: &[usize]) -> PlayfairTx {
    let validators = from_ledger_set(remote.l.validator_history.get(&b.header().height).unwrap());
    PlayfairTx::proven(PlayfairKind::Update { network_id: remote.l.network_id, header: b.header().clone(), cert: remote.cert(b, signers), validators })
}

fn proof(src: &Net, b: &Block, signers: &[usize]) -> BridgeProof {
    let msgs = bridge_messages(&src.l.network_id, &b.body);
    let hashes: Vec<Hash> = msgs.iter().map(|m| m.hash()).collect();
    BridgeProof { msg: msgs[0].clone(), header: b.header().clone(), cert: src.cert(b, signers), leaf: 0, branch: merkle_branch(&hashes, 0) }
}

fn receive(p: BridgeProof) -> PlayfairTx {
    let tx = PlayfairTx::proven(PlayfairKind::Receive { proof: Box::new(p) });
    PlayfairTx::from_bytes(&tx.to_bytes()).unwrap()
}

#[test]
fn round_trip_with_validator_rotation_and_attacks() {
    let (mut a, mut b) = (net(1), net(2));
    register(&mut a, &b);
    register(&mut b, &a);

    // B rotates its validator set (validator 3 exits); A's light client follows.
    let exit = KerckhoffsTx::exit(b.vals[3].address(), &b.vals[3]);
    let kb = b.block(ChainId::Kerckhoffs, Body::Kerckhoffs(vec![exit]));
    // An update signed by too few validators is rejected...
    assert!(a.l.clone().apply_playfair(&update(&b, &kb, &[0, 1])).is_err());
    // ...as is one whose validator list does not match the certified set root.
    let mut lie = update(&b, &kb, &[0, 1, 2]);
    if let PlayfairKind::Update { validators, .. } = &mut lie.kind {
        validators.pop();
    }
    assert!(a.l.clone().apply_playfair(&lie).unwrap_err().contains("set root"));
    a.pf(vec![update(&b, &kb, &[0, 1, 2])]);
    assert_eq!(a.l.counterparties[&b.l.network_id].tip, 1);

    // A -> B: 1,000 native escrowed on A, minted as wrapped-A on B.
    let s = a.send(b.l.network_id, b.user.address(), 1_000, a.l.network_id);
    let ab = a.pf(vec![s]);
    assert_eq!(a.l.escrowed[&b.l.network_id], 1_000);
    let p = proof(&a, &ab, &[0, 1, 2]);
    // Attacks on the delivery:
    let mut inflated = p.clone();
    inflated.msg.amount = 1_000_000;
    assert!(b.l.clone().apply_playfair(&receive(inflated)).unwrap_err().contains("not included"));
    let mut weak = p.clone();
    weak.cert.votes.truncate(2);
    assert!(b.l.clone().apply_playfair(&receive(weak)).is_err());
    let mut misrouted = p.clone();
    misrouted.msg.dest_network = [9; 32];
    assert!(b.l.clone().apply_playfair(&receive(misrouted)).is_err());
    b.pf(vec![receive(p.clone())]);
    let wa = wrapped_asset(&a.l.network_id);
    assert_eq!(b.l.balance(ChainId::Playfair, &b.user.address(), &wa), 1_000);
    assert!(b.l.clone().apply_playfair(&receive(p)).unwrap_err().contains("already received"));

    // B -> A: 400 wrapped-A burned on B, released from escrow on A.
    let back = b.send(a.l.network_id, a.user.address(), 400, a.l.network_id);
    let ba = b.pf(vec![back]);
    // B's Playfair block is anchored after the rotation: A must have synced it (it has).
    let p = proof(&b, &ba, &[0, 1, 2]);
    // The exited validator can no longer help certify.
    let stale = { let mut q = p.clone(); q.cert = b.cert(&ba, &[0, 1, 3]); q };
    assert!(a.l.clone().apply_playfair(&receive(stale)).is_err());
    let before = a.l.balance(ChainId::Playfair, &a.user.address(), &NATIVE);
    a.pf(vec![receive(p)]);
    assert_eq!(a.l.balance(ChainId::Playfair, &a.user.address(), &NATIVE), before + 400);
    assert_eq!(a.l.escrowed[&b.l.network_id], 600);
    assert_eq!(b.l.balance(ChainId::Playfair, &b.user.address(), &wa), 600);
}

#[test]
fn escrow_caps_what_a_counterparty_can_release() {
    let (mut a, mut b) = (net(3), net(4));
    register(&mut a, &b);
    register(&mut b, &a);
    // A malicious B mints a fake "returning" transfer for more than A ever sent.
    // B's validators sign it (they control B), but A's escrow for B is 0.
    let wa = wrapped_asset(&a.l.network_id);
    b.l.playfair_utxos.insert(OutPoint { txid: [7; 32], index: 0 }, TxOut { owner: b.user.address(), asset: wa, amount: 5_000 });
    let forged = b.send(a.l.network_id, b.user.address(), 5_000, a.l.network_id);
    let blk = b.pf(vec![forged]);
    let p = proof(&b, &blk, &[0, 1, 2]);
    assert!(a.l.clone().apply_playfair(&receive(p)).unwrap_err().contains("escrow"));
}

#[test]
fn rules_on_routing_and_sync() {
    let (mut a, mut b, c) = (net(5), net(6), net(7));
    register(&mut a, &b);
    // Updates must be in order.
    let k1 = b.block(ChainId::Kerckhoffs, Body::Kerckhoffs(vec![]));
    let k2 = b.block(ChainId::Kerckhoffs, Body::Kerckhoffs(vec![]));
    assert!(a.l.clone().apply_playfair(&update(&b, &k2, &[0, 1, 2])).unwrap_err().contains("#1"));
    // A proof whose anchor A has not synced yet is deferred, not accepted.
    register(&mut b, &a);
    let s = b.send(a.l.network_id, a.user.address(), 10, b.l.network_id);
    let blk = b.pf(vec![s]);
    assert!(a.l.clone().apply_playfair(&receive(proof(&b, &blk, &[0, 1, 2]))).unwrap_err().contains("retry later"));
    a.pf(vec![update(&b, &k1, &[0, 1, 2]), update(&b, &k2, &[0, 1, 2])]);
    a.pf(vec![receive(proof(&b, &blk, &[0, 1, 2]))]);
    assert_eq!(a.l.balance(ChainId::Playfair, &a.user.address(), &wrapped_asset(&b.l.network_id)), 10);
    // Sending to an unregistered network, or wrapped tokens to a third network, fails.
    let unknown = a.send(c.l.network_id, c.user.address(), 5, a.l.network_id);
    assert!(a.l.clone().apply_playfair(&unknown).unwrap_err().contains("unknown destination"));
    // Self-registration is refused.
    let (base, n) = native_transfer(&a.l, ChainId::Playfair, Source::Local, &a.user, vec![], None, REGISTER_FEE - TX_FEE).unwrap();
    let kind = PlayfairKind::Register { network_id: a.l.network_id, name: "me".into(), k_height: 0, validators: from_ledger_set(&a.l.validators) };
    assert!(a.l.clone().apply_playfair(&PlayfairTx { base, kind }.sign(&vec![&a.user; n])).is_err());
}
