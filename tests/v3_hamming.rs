//! Hamming Chain: erasure coding, commitments, sampling and inclusion proofs.

use pqchain::codec::Wire;
use pqchain::consensus::FinalityCert;
use pqchain::crypto::*;
use pqchain::hamming::{self, *};
use pqchain::ledger::*;
use pqchain::network::native_transfer;

fn blob(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

/// Pseudo-random subset of `n` indices of size `k` (deterministic per seed).
fn subset(n: usize, k: usize, seed: u64) -> Vec<usize> {
    let mut v: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let h = Enc::new("subset").u64(seed).u64(i as u64).hash();
        v.swap(i, (u64::from_le_bytes(h[..8].try_into().unwrap()) % (i as u64 + 1)) as usize);
    }
    v.truncate(k);
    v
}

#[test]
fn any_half_of_the_shards_rebuilds_the_blob() {
    for len in [0, 1, 63, 64, 65, 1_000, 4_096, 128 * 1024] {
        let data = blob(len);
        let c = commit(&data);
        let shards = encode(&data);
        assert_eq!(shards.len(), c.shards() as usize);
        for seed in 0..6u64 {
            let mut keep: Vec<Option<Vec<u8>>> = vec![None; shards.len()];
            let pick = if seed == 0 { (c.k as usize..shards.len()).collect() } else { subset(shards.len(), c.k as usize, seed) };
            for i in pick {
                keep[i] = Some(shards[i].clone());
            }
            assert_eq!(reconstruct(&c, keep).unwrap(), data, "len {len} seed {seed}");
        }
        // One shard short of half: not enough.
        if c.k > 1 {
            let mut keep: Vec<Option<Vec<u8>>> = vec![None; shards.len()];
            for i in subset(shards.len(), c.k as usize - 1, 99) {
                keep[i] = Some(shards[i].clone());
            }
            assert!(reconstruct(&c, keep).is_err());
        }
    }
}

#[test]
fn shard_proofs_bind_content_and_position() {
    let data = blob(10_000);
    let c = commit(&data);
    for i in [0usize, 5, c.k as usize, c.shards() as usize - 1] {
        let (s, br) = shard_with_proof(&data, i).unwrap();
        assert!(verify_shard(&c, i as u32, &s, &br));
        let mut bad = s.clone();
        bad[0] ^= 1;
        assert!(!verify_shard(&c, i as u32, &bad, &br), "tampered shard");
        assert!(!verify_shard(&c, (i as u32 + 1) % c.shards(), &s, &br), "wrong position");
        assert!(!verify_shard(&c, i as u32, &s[1..], &br), "wrong length");
    }
    assert!(!verify_shard(&c, c.shards(), &[], &[]), "index out of range");
}

#[test]
fn corrupted_shards_cannot_fake_a_reconstruction() {
    let data = blob(5_000);
    let c = commit(&data);
    let shards = encode(&data);
    let mut keep: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
    for s in keep.iter_mut().skip(c.k as usize) {
        *s = None;
    }
    keep[0].as_mut().unwrap()[3] ^= 0xff;
    assert!(reconstruct(&c, keep).unwrap_err().contains("does not match"));
}

struct Net {
    vals: Vec<Keypair>,
    alice: Keypair,
    l: Ledger,
}

fn net() -> Net {
    let vals: Vec<Keypair> = (0..4).map(|_| Keypair::generate()).collect();
    let alice = Keypair::generate();
    let mut l = Ledger::genesis(
        vals.iter().map(|v| GenesisValidator { signing_key: v.public.clone(), withdrawal: v.address(), stake: 2_000 }).collect(),
        &[(alice.address(), 100_000)],
    );
    // Fund alice on Hamming: export from Atbash, import via atomic memory.
    let ex = Some((ChainId::Hamming, vec![TxOut::native(alice.address(), 10_000)]));
    let (base, n) = native_transfer(&l, ChainId::Atbash, Source::Local, &alice, vec![], ex, 0).unwrap();
    l.apply_atbash(&AtbashTx { base, create_asset: None }.sign(&vec![&alice; n])).unwrap();
    let (base, n) = native_transfer(&l, ChainId::Hamming, Source::Atomic, &alice, vec![], None, 0).unwrap();
    l.apply_blob(&BlobTx::new(base, [0; 8], vec![]).sign(&vec![&alice; n])).unwrap();
    Net { vals, alice, l }
}

impl Net {
    fn post(&self, data: Vec<u8>) -> BlobTx {
        let extra = blob_fee(data.len()) - TX_FEE;
        let (base, n) = native_transfer(&self.l, ChainId::Hamming, Source::Local, &self.alice, vec![], None, extra).unwrap();
        BlobTx::new(base, *b"rollup-1", data).sign(&vec![&self.alice; n])
    }
    fn block(&mut self, txs: Vec<BlobTx>) -> Result<Block, String> {
        let (h, p) = self.l.tip(ChainId::Hamming);
        let who = self.l.scheduled_proposer(ChainId::Hamming, h + 1, &p, 0, self.l.current_anchor()).unwrap();
        let key = self.vals.iter().find(|k| k.address() == who).unwrap();
        let b = propose_on(&self.l, key, ChainId::Hamming, Body::Hamming(txs), h + 1, 0);
        self.l.apply_block(&b)?;
        Ok(b)
    }
}

#[test]
fn blobs_pay_per_byte_and_must_match_their_commitment() {
    let mut n = net();
    let before = n.l.burned;
    let tx = n.post(blob(3_000));
    let tx = BlobTx::from_bytes(&tx.to_bytes()).unwrap();
    n.block(vec![tx]).unwrap();
    assert_eq!(n.l.burned - before, blob_fee(3_000));
    // A proposer cannot swap the data under an honest commitment...
    let mut lie = n.post(blob(2_000));
    lie.data[7] ^= 1;
    assert!(n.l.clone().apply_blob(&lie).unwrap_err().contains("bad encoding"));
    // ...or underpay.
    let (base, k) = native_transfer(&n.l, ChainId::Hamming, Source::Local, &n.alice, vec![], None, 0).unwrap();
    let cheap = BlobTx::new(base, [0; 8], blob(5_000)).sign(&vec![&n.alice; k]);
    assert!(n.l.clone().apply_blob(&cheap).unwrap_err().contains("blob fee"));
    // Oversized blobs are rejected.
    let (base, k) = native_transfer(&n.l, ChainId::Hamming, Source::Local, &n.alice, vec![], None, 0).unwrap();
    let huge = BlobTx::new(base, [0; 8], blob(MAX_BLOB + 1)).sign(&vec![&n.alice; k]);
    assert!(n.l.clone().apply_blob(&huge).unwrap_err().contains("larger"));
    // Kerckhoffs cannot fund Hamming directly.
    n.l.kerckhoffs_utxos.insert(OutPoint { txid: [3; 32], index: 0 }, TxOut::native(n.alice.address(), 500));
    let ex = Some((ChainId::Hamming, vec![TxOut::native(n.alice.address(), 100)]));
    let (base, k) = native_transfer(&n.l, ChainId::Kerckhoffs, Source::Local, &n.alice, vec![], ex, 0).unwrap();
    let tx = KerckhoffsTx { base, kind: KerckhoffsKind::Transfer }.sign(&vec![&n.alice; k]);
    assert!(n.l.clone().apply_kerckhoffs(&tx).unwrap_err().contains("Hamming"));
}

#[test]
fn light_client_inclusion_proof_and_sampling() {
    let mut n = net();
    let data = blob(20_000);
    let other = n.post(blob(100));
    // Build the second transaction from the first one's change output.
    let mut after_first = n.l.clone();
    after_first.apply_blob(&other).unwrap();
    let extra = blob_fee(data.len()) - TX_FEE;
    let (base, k) = native_transfer(&after_first, ChainId::Hamming, Source::Local, &n.alice, vec![], None, extra).unwrap();
    let mine = BlobTx::new(base, *b"rollup-1", data.clone()).sign(&vec![&n.alice; k]);
    let b = n.block(vec![other, mine.clone()]).unwrap();
    let mut cert = FinalityCert::new(ChainId::Hamming, b.header().height, b.hash());
    for v in &n.vals[..3] {
        cert.add_vote(v);
    }
    let proof = InclusionProof {
        header: b.header().clone(),
        cert,
        prefix_hash: mine.prefix_hash(),
        commitment: mine.commitment,
        tx_index: 1,
        tx_branch: merkle_branch(&b.body.tx_ids(), 1),
    };
    let proof = InclusionProof::from_bytes(&proof.to_bytes()).unwrap();
    let set = n.l.validators.clone();
    proof.verify(&set).unwrap();
    // Sampling: every shard verifies against the proven commitment.
    for i in 0..proof.commitment.shards() {
        let (s, br) = shard_with_proof(&data, i as usize).unwrap();
        assert!(verify_shard(&proof.commitment, i, &s, &br));
    }
    // A different commitment, a minority certificate or a wrong position all fail.
    let mut swapped = proof.clone();
    swapped.commitment = commit(b"something else");
    assert!(swapped.verify(&set).unwrap_err().contains("not included"));
    let mut weak = proof.clone();
    weak.cert.votes.truncate(2);
    assert!(weak.verify(&set).is_err());
    let mut moved = proof.clone();
    moved.tx_index = 0;
    assert!(moved.verify(&set).is_err());
    assert!(hamming::miss_probability(20) < 1e-6);
}
