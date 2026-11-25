//! Snapshots: a busy ledger survives encode/decode bit-for-bit; damage is detected.

use pqchain::crypto::*;
use pqchain::ledger::*;
use pqchain::network::native_transfer;
use pqchain::snapshot;

fn busy_ledger() -> Ledger {
    let vals: Vec<Keypair> = (0..4).map(|_| Keypair::generate()).collect();
    let alice = Keypair::generate();
    let mut l = Ledger::genesis(
        vals.iter()
            .map(|v| GenesisValidator { signing_key: v.public.clone(), withdrawal: v.address(), stake: 2_000 })
            .collect(),
        &[(alice.address(), 50_000)],
    );
    l.kerckhoffs_utxos.insert(OutPoint { txid: [7; 32], index: 0 }, TxOut::native(alice.address(), 1_000));
    let key = |l: &Ledger, c: ChainId| {
        let (h, p) = l.tip(c);
        let who = l.scheduled_proposer(c, h + 1, &p, 0, l.current_anchor()).unwrap();
        vals.iter().find(|k| k.address() == who).unwrap()
    };
    // Zone registration + exit + delegation on Kerckhoffs.
    let base = Transfer::spend(&[(OutPoint { txid: [7; 32], index: 0 }, Source::Local, &alice)], vec![TxOut::native(alice.address(), 900)]);
    let zone = KerckhoffsTx { base, kind: KerckhoffsKind::CreateZone { name: "games".into(), members: vals[..3].iter().map(|v| v.address()).collect() } }.sign(&[&alice]);
    let exit = KerckhoffsTx::exit(vals[3].address(), &vals[3]);
    let b = propose(&l, key(&l, ChainId::Kerckhoffs), Body::Kerckhoffs(vec![zone, exit]), 1);
    l.apply_block(&b).unwrap();
    l.delegations.push(Delegation { node: vals[0].address(), stake: 500, reward: alice.address() });
    // Atbash: export to the zone (relay message) and an atomic export.
    let ex = Some((ChainId::Zone(0), vec![TxOut::native(alice.address(), 4_000)]));
    let (base, n) = native_transfer(&l, ChainId::Atbash, Source::Local, &alice, vec![], ex, 0).unwrap();
    let tx = AtbashTx { base, create_asset: None }.sign(&vec![&alice; n]);
    let b = propose(&l, key(&l, ChainId::Atbash), Body::Atbash(vec![tx]), 2);
    l.apply_block(&b).unwrap();
    let ex = Some((ChainId::Kerckhoffs, vec![TxOut::native(alice.address(), 100)]));
    let (base, n) = native_transfer(&l, ChainId::Atbash, Source::Local, &alice, vec![], ex, 0).unwrap();
    let tx = AtbashTx { base, create_asset: None }.sign(&vec![&alice; n]);
    let b = propose(&l, key(&l, ChainId::Atbash), Body::Atbash(vec![tx]), 3);
    l.apply_block(&b).unwrap();
    l.relay_consumed.insert((ChainId::Atbash, OutPoint { txid: [1; 32], index: 2 }));
    l.zone_utxos.entry(0).or_default().insert(OutPoint { txid: [2; 32], index: 0 }, TxOut::native(alice.address(), 3_999));
    l.claim_nonces.insert(alice.address(), 3);
    assert!(l.minted > 0 && !l.atomic.is_empty() && !l.zones.is_empty());
    l
}

#[test]
fn snapshot_roundtrip_preserves_state_root() {
    let l = busy_ledger();
    let (back, records) = snapshot::decode(&snapshot::encode(&l, 42)).unwrap();
    assert_eq!(records, 42);
    assert_eq!(back.state_root(), l.state_root());
    assert_eq!(back.validator_history.len(), l.validator_history.len());
    assert_eq!(back.tip(ChainId::Zone(0)), l.tip(ChainId::Zone(0)));
}

#[test]
fn snapshot_files_detect_damage() {
    let dir = std::env::temp_dir().join(format!("pqchain-snap-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let l = busy_ledger();
    snapshot::save(&dir, &l, 7).unwrap();
    let (back, n) = snapshot::load(&dir).unwrap().unwrap();
    assert_eq!((back.state_root(), n), (l.state_root(), 7));
    let p = dir.join("snapshot.bin");
    let mut bytes = std::fs::read(&p).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 1;
    std::fs::write(&p, &bytes).unwrap();
    assert!(snapshot::load(&dir).unwrap_err().contains("checksum"));
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(snapshot::load(&dir).unwrap().is_none(), "no snapshot is fine");
}
