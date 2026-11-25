//! Testnet v0 demo: boots a 10-validator network plus a full node and a light
//! client, then exercises payments, asset creation, a double-spend attack,
//! slashing, cross-chain staking, delegation, and several forgery attempts.

#![forbid(unsafe_code)]

use pqchain::consensus::{LightClient, Params};
use pqchain::crypto::*;
use pqchain::ledger::*;
use pqchain::network::*;
use std::time::Instant;

fn h(x: &Hash) -> String {
    hex::encode(&x[..6])
}

fn report(r: &Report, label: &str) {
    println!(
        "  ✔ {} #{} accepted ({label}): {} rounds / {} polls; finality cert {} votes, {:.1} KB, light client verified {}% stake",
        r.chain.name(),
        r.height,
        r.rounds,
        r.polls,
        r.cert_votes,
        r.cert_bytes as f64 / 1024.0,
        r.light_client_stake_pct
    );
}

fn section(t: &str) {
    println!("\n━━ {t} {}", "━".repeat(70usize.saturating_sub(t.len())));
}

fn main() -> Result<(), String> {
    println!("PQ-Chain testnet v0 · ML-DSA-65 (FIPS 204) · SHA3-256 · Sampled Quorum Consensus");

    // ── keys ──
    section("1. Keys (formally verified libcrux ML-DSA-65)");
    let t = Instant::now();
    let signing: Vec<Keypair> = (0..10).map(|_| Keypair::generate()).collect();
    let cold: Vec<Keypair> = (0..10).map(|_| Keypair::generate()).collect();
    let (alice, bob, carol) = (Keypair::generate(), Keypair::generate(), Keypair::generate());
    println!("  generated 23 key pairs in {:?}", t.elapsed());
    let s = alice.sign(ctx::PRISM_TX, b"size probe");
    println!(
        "  public key {} B · signature {} B · address 32 B (SHA3-256)   [Bitcoin Schnorr: 32 B / 64 B]",
        alice.public.bytes.len(),
        s.bytes.len()
    );
    println!("  alice={} bob={} carol={}", alice.address(), bob.address(), carol.address());

    // ── genesis ──
    section("2. Genesis: 10 Tier-1 validators, 1 full node, 1 light client");
    let genesis = Ledger::genesis(
        signing
            .iter()
            .zip(&cold)
            .map(|(s, c)| GenesisValidator {
                signing_key: s.public.clone(),
                withdrawal: c.address(),
                stake: 2_000,
            })
            .collect(),
        &[(alice.address(), 1_000_000), (bob.address(), 50_000)],
    );
    let mut nodes: Vec<Node> = signing
        .into_iter()
        .enumerate()
        .map(|(i, k)| Node {
            name: format!("validator-{i}"),
            role: Role::Validator,
            key: Some(k),
            ledger: genesis.clone(),
        })
        .collect();
    nodes.push(Node { name: "full-node".into(), role: Role::FullNode, key: None, ledger: genesis.clone() });
    let mut net = Network { nodes, params: Params::default(), clock: 0 };
    println!(
        "  total stake {} · consensus k={} alpha={} beta={} · state root {}",
        genesis.total_weight(),
        net.params.k,
        net.params.alpha,
        net.params.beta,
        h(&genesis.state_root())
    );

    // ── Prism Chain payment + asset ──
    section("3. Prism Chain: payment + new asset");
    let l = net.ledger().clone();
    let (base, n) = native_transfer(&l, ChainId::Prism, Source::Local, &alice, vec![TxOut::native(bob.address(), 250_000)], None, 0)?;
    let pay = PrismTx { base, create_asset: None }.sign(&vec![&alice; n]);
    // Asset creation must spend a different UTXO: use bob's.
    let (mut base, n) = native_transfer(&l, ChainId::Prism, Source::Local, &bob, vec![], None, 0)?;
    let mut gold = PrismTx { base: base.clone(), create_asset: Some(AssetDef { name: "GOLD".into(), supply: 1_000 }) };
    let gold_id = gold.new_asset_id().unwrap();
    base.outputs.push(TxOut { owner: bob.address(), asset: gold_id, amount: 1_000 });
    gold.base = base;
    let gold = gold.sign(&vec![&bob; n]);
    let ts = net.tick();
    let p = net.next_proposer(ChainId::Prism);
    println!("  scheduled proposer: {}", p.name);
    let b = propose(&p.ledger, p.key.as_ref().unwrap(), Body::Prism(vec![pay, gold]), ts);
    report(&net.finalize(&[b], |_| 0, &[])?, "2 txs");
    let l = net.ledger();
    println!(
        "  alice {} · bob {} native + {} GOLD (asset {})",
        l.balance(ChainId::Prism, &alice.address(), &NATIVE),
        l.balance(ChainId::Prism, &bob.address(), &NATIVE),
        l.balance(ChainId::Prism, &bob.address(), &gold_id),
        h(&gold_id)
    );

    // ── double spend + byzantine proposer ──
    section("4. Attack: double-spend by a byzantine proposer (20% stake byzantine)");
    let l = net.ledger().clone();
    let ts = net.tick();
    let evil_name = net.next_proposer(ChainId::Prism).name.clone();
    let evil_idx = net.nodes.iter().position(|n| n.name == evil_name).unwrap();
    let evil = net.nodes[evil_idx].key.as_ref().unwrap();
    let evil_addr = evil.address();
    let accomplice = net
        .nodes
        .iter()
        .filter_map(|n| n.key.as_ref())
        .map(|k| k.address())
        .find(|a| *a != evil_addr)
        .unwrap();
    let (base_a, n) = native_transfer(&l, ChainId::Prism, Source::Local, &alice, vec![TxOut::native(bob.address(), 100_000)], None, 0)?;
    let mut base_b = base_a.clone();
    base_b.outputs[0].owner = carol.address(); // same inputs, different recipient
    let tx_a = PrismTx { base: base_a, create_asset: None }.sign(&vec![&alice; n]);
    let tx_b = PrismTx { base: base_b, create_asset: None }.sign(&vec![&alice; n]);
    let block_a = propose(&l, evil, Body::Prism(vec![tx_a]), ts);
    let block_b = propose(&l, evil, Body::Prism(vec![tx_b]), ts);
    println!("  {evil_name} signs TWO blocks at Prism #{}: A={} (pays bob) B={} (pays carol)", block_a.header().height, h(&block_a.hash()), h(&block_b.hash()));
    println!("  network split 50/50 on first sight; 2 byzantine validators vote for the minority");
    let candidates = [block_a.clone(), block_b.clone()];
    let r = net.finalize(&candidates, |i| i % 2, &[evil_addr, accomplice])?;
    report(&r, &format!("winner = block {}", ["A", "B"][r.winner]));
    let l = net.ledger();
    println!(
        "  bob {} · carol {} → exactly one payment happened; the loser is now invalid everywhere",
        l.balance(ChainId::Prism, &bob.address(), &NATIVE),
        l.balance(ChainId::Prism, &carol.address(), &NATIVE)
    );

    // ── slashing ──
    section("5. Keystone Chain: slash the equivocating validator");
    let slash = KeystoneTx {
        base: Transfer::default(),
        kind: KeystoneKind::Slash { a: Box::new(block_a.signed.clone()), b: Box::new(block_b.signed.clone()) },
    };
    let ts = net.tick();
    let p = net.next_proposer(ChainId::Keystone);
    let b = propose(&p.ledger, p.key.as_ref().unwrap(), Body::Keystone(vec![slash]), ts);
    report(&net.finalize(&[b], |_| 0, &[])?, "slash evidence");
    let v = &net.ledger().validators[&evil_addr];
    println!("  {evil_addr}: slashed={} · burned so far {} · total stake now {}", v.slashed, net.ledger().burned, net.ledger().total_weight());

    // ── cross-chain staking ──
    section("6. Cross-chain: Prism → Keystone export/import, new validator + delegator");
    let new_val = Keypair::generate();
    let new_cold = Keypair::generate();
    let l = net.ledger().clone();
    let (base, n) = native_transfer(&l, ChainId::Prism, Source::Local, &alice, vec![], Some((ChainId::Keystone, vec![TxOut::native(alice.address(), 10_000)])), 0)?;
    let ex1 = PrismTx { base, create_asset: None }.sign(&vec![&alice; n]);
    let (base, n) = native_transfer(&l, ChainId::Prism, Source::Local, &bob, vec![], Some((ChainId::Keystone, vec![TxOut::native(bob.address(), 1_000)])), 0)?;
    let ex2 = PrismTx { base, create_asset: None }.sign(&vec![&bob; n]);
    let ts = net.tick();
    let p = net.next_proposer(ChainId::Prism);
    let b = propose(&p.ledger, p.key.as_ref().unwrap(), Body::Prism(vec![ex1, ex2]), ts);
    report(&net.finalize(&[b], |_| 0, &[])?, "2 exports into atomic memory");

    let l = net.ledger().clone();
    let (base, n) = native_transfer(&l, ChainId::Keystone, Source::Atomic, &alice, vec![], None, 5_000)?;
    let add_v = KeystoneTx {
        base,
        kind: KeystoneKind::AddValidator { signing_key: new_val.public.clone(), withdrawal: new_cold.address(), stake: 5_000 },
    }
    .sign(&vec![&alice; n]);
    let (base, n) = native_transfer(&l, ChainId::Keystone, Source::Atomic, &bob, vec![], None, 600)?;
    let add_d = KeystoneTx {
        base,
        kind: KeystoneKind::AddDelegator { node: new_val.address(), stake: 600, reward: bob.address() },
    }
    .sign(&vec![&bob; n]);
    let ts = net.tick();
    let p = net.next_proposer(ChainId::Keystone);
    let b = propose(&p.ledger, p.key.as_ref().unwrap(), Body::Keystone(vec![add_v, add_d]), ts);
    report(&net.finalize(&[b], |_| 0, &[])?, "import + AddValidator + AddDelegator");
    let ledger_now = net.ledger().clone();
    net.nodes.push(Node { name: "validator-10".into(), role: Role::Validator, key: Some(new_val), ledger: ledger_now });
    let v = &net.ledger().validators[&net.nodes.last().unwrap().key.as_ref().unwrap().address()];
    println!("  validator-10 joined: stake {} + delegated {} (cap {}x) · alice Keystone change {}", v.stake, v.delegated, MAX_DELEGATION_FACTOR, net.ledger().balance(ChainId::Keystone, &alice.address(), &NATIVE));

    // ── attacks that must fail ──
    section("7. Attacks that must be rejected");
    let l = net.ledger().clone();
    let check = |name: &str, r: Result<(), String>| match r {
        Err(e) => println!("  ✔ rejected  {name}: {e}"),
        Ok(()) => println!("  ✘ ACCEPTED  {name}  <-- BUG"),
    };
    // a) carol tries to spend alice's coins with her own key
    let (mut base, _) = native_transfer(&l, ChainId::Prism, Source::Local, &alice, vec![TxOut::native(carol.address(), 5)], None, 0)?;
    for i in &mut base.inputs {
        i.pubkey = carol.public.clone();
    }
    let n = base.inputs.len();
    check("theft with wrong key", l.clone().apply_prism(&PrismTx { base, create_asset: None }.sign(&vec![&carol; n])));
    // b) valid tx, then one bit of the signature flipped
    let (base, n) = native_transfer(&l, ChainId::Prism, Source::Local, &alice, vec![TxOut::native(carol.address(), 5)], None, 0)?;
    let mut tx = PrismTx { base, create_asset: None }.sign(&vec![&alice; n]);
    tx.base.inputs[0].sig.bytes[100] ^= 1;
    check("forged signature (1 bit flipped)", l.clone().apply_prism(&tx));
    // c) signature replay across chains (Prism signature used on Keystone Chain)
    let (base, n) = native_transfer(&l, ChainId::Keystone, Source::Local, &alice, vec![], None, 0)?;
    let mut ptx = KeystoneTx { base, kind: KeystoneKind::Transfer };
    let id = ptx.id();
    for i in &mut ptx.base.inputs {
        i.sig = alice.sign(ctx::PRISM_TX, &id);
    }
    let _ = n;
    check("cross-chain signature replay", l.clone().apply_keystone(&ptx));
    // d) printing money
    let (mut base, n) = native_transfer(&l, ChainId::Prism, Source::Local, &bob, vec![TxOut::native(carol.address(), 10)], None, 0)?;
    base.outputs[0].amount = 10_000_000;
    check("outputs exceed inputs", l.clone().apply_prism(&PrismTx { base, create_asset: None }.sign(&vec![&bob; n])));
    // e) delegation beyond the 5x cap
    let (base, n) = native_transfer(&l, ChainId::Keystone, Source::Local, &alice, vec![], None, 0)
        .map(|(mut b, n)| {
            b.outputs.clear();
            (b, n)
        })?;
    let vid = net.nodes.last().unwrap().key.as_ref().unwrap().address();
    let mut big = KeystoneTx { base, kind: KeystoneKind::AddDelegator { node: vid, stake: 4_000, reward: alice.address() } };
    big = big.sign(&vec![&alice; n]);
    let mut near_cap = l.clone(); // validator already holding 24,000 of its 25,000 cap
    near_cap.validators.get_mut(&vid).unwrap().delegated = 24_000;
    check("delegation over 5x cap", near_cap.apply_keystone(&big));
    // f) block from an unscheduled proposer
    let sched = net.next_proposer(ChainId::Prism).key.as_ref().unwrap().address();
    let rogue = net.nodes.iter().filter_map(|n| n.key.as_ref()).find(|k| k.address() != sched && !l.validators[&k.address()].slashed).unwrap();
    let rb = propose(&l, rogue, Body::Prism(vec![]), 99);
    check("block from unscheduled proposer", l.clone().apply_block(&rb));
    // g) the slashed validator can no longer propose
    let sb = propose(&l, net.nodes[evil_idx].key.as_ref().unwrap(), Body::Prism(vec![]), 99);
    check("block from slashed validator", l.clone().apply_block(&sb));
    // h) light client given a certificate signed by too little stake
    let mut cert = pqchain::consensus::FinalityCert::new(ChainId::Prism, 99, [7u8; 32]);
    cert.add_vote(rogue);
    check("light client: 1-vote certificate", LightClient::from_ledger(&l).verify(&cert).map(|_| ()));

    // ── summary ──
    section("8. Replica agreement");
    let roots: Vec<_> = net.nodes.iter().map(|n| (n.name.clone(), n.ledger.state_root())).collect();
    let all_same = roots.iter().all(|(_, r)| *r == roots[0].1);
    for (n, r) in &roots {
        print!("{n}={} ", h(r));
    }
    println!("\n  {} — all {} replicas {}", if all_same { "✔" } else { "✘" }, roots.len(), if all_same { "hold identical state" } else { "DIVERGED" });
    let l = net.ledger();
    println!(
        "  Prism height {} · Keystone height {} · {} active validators · stake {} · burned {}",
        l.tip(ChainId::Prism).0,
        l.tip(ChainId::Keystone).0,
        l.validators.values().filter(|v| !v.slashed).count(),
        l.total_weight(),
        l.burned
    );
    if !all_same {
        return Err("replicas diverged".into());
    }
    Ok(())
}
