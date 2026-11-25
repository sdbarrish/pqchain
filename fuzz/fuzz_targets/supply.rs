//! Money conservation. The fuzzer drives arbitrary sequences of correctly
//! signed operations (payments, cross-chain moves, Feistel transfers,
//! delegation, exits, reward claims, blocks). Whatever is accepted, after every
//! step: native tokens held + burned == genesis supply + minted.
#![no_main]
use libfuzzer_sys::fuzz_target;
use pqchain::crypto::*;
use pqchain::feistel::{Action, FeistelTx};
use pqchain::ledger::*;
use pqchain::network::native_transfer;
use std::sync::OnceLock;

struct Keys {
    vals: Vec<Keypair>,
    users: Vec<Keypair>,
    genesis: Ledger,
    supply: u128,
}

fn keys() -> &'static Keys {
    static K: OnceLock<Keys> = OnceLock::new();
    K.get_or_init(|| {
        let vals: Vec<Keypair> = (0..4u8).map(|i| Keypair::from_seed([i; 32])).collect();
        let users: Vec<Keypair> = (10..13u8).map(|i| Keypair::from_seed([i; 32])).collect();
        let genesis = Ledger::genesis(
            vals.iter()
                .map(|v| GenesisValidator { signing_key: v.public.clone(), withdrawal: v.address(), stake: 2_000 })
                .collect(),
            &users.iter().map(|u| (u.address(), 1_000_000)).collect::<Vec<_>>(),
        );
        let supply = genesis.native_held();
        Keys { vals, users, genesis, supply }
    })
}

struct Cursor<'a>(&'a [u8]);
impl Cursor<'_> {
    fn byte(&mut self) -> Option<u8> {
        let (b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(*b)
    }
    fn amount(&mut self) -> Option<u64> {
        Some(u16::from_le_bytes([self.byte()?, self.byte()?]) as u64 + 1)
    }
}

fn block(k: &Keys, l: &mut Ledger, chain: ChainId) {
    let (h, p) = l.tip(chain);
    let Some(who) = l.scheduled_proposer(chain, h + 1, &p, 0, l.current_anchor()) else { return };
    let key = k.vals.iter().find(|v| v.address() == who).unwrap();
    let body = match chain {
        ChainId::Kerckhoffs => Body::Kerckhoffs(vec![]),
        ChainId::Feistel => Body::Feistel(vec![]),
        _ => Body::Atbash(vec![]),
    };
    let b = propose_on(l, key, chain, body, h + 1, 0);
    l.apply_block(&b).expect("empty block by the scheduled proposer must apply");
}

fn step(k: &Keys, l: &mut Ledger, c: &mut Cursor) -> Option<()> {
    let op = c.byte()?;
    let u = &k.users[(c.byte()? % 3) as usize];
    let other = &k.users[(c.byte()? % 3) as usize];
    let amount = c.amount()?;
    let utxo = |l: &Ledger, chain, outs, export| native_transfer(l, chain, Source::Local, u, outs, export, 0);
    let _ = match op % 12 {
        0 => utxo(l, ChainId::Atbash, vec![TxOut::native(other.address(), amount)], None)
            .and_then(|(b, n)| l.apply_atbash(&AtbashTx { base: b, create_asset: None }.sign(&vec![u; n]))),
        1 | 2 => {
            let dest = if op % 12 == 1 { ChainId::Kerckhoffs } else { ChainId::Feistel };
            utxo(l, ChainId::Atbash, vec![], Some((dest, vec![TxOut::native(u.address(), amount)])))
                .and_then(|(b, n)| l.apply_atbash(&AtbashTx { base: b, create_asset: None }.sign(&vec![u; n])))
        }
        3 => {
            let pool = l.atomic_of(ChainId::Kerckhoffs, &u.address());
            let total: u64 = pool.iter().map(|(_, o)| o.amount).sum();
            if total <= TX_FEE {
                return Some(());
            }
            let spends: Vec<_> = pool.iter().map(|(p, _)| (*p, Source::Atomic, u)).collect();
            let b = Transfer::spend(&spends, vec![TxOut::native(u.address(), total - TX_FEE)]);
            l.apply_kerckhoffs(&KerckhoffsTx { base: b, kind: KerckhoffsKind::Transfer }.sign(&vec![u; spends.len()]))
        }
        4 => {
            let ops: Vec<OutPoint> = l.atomic_of(ChainId::Feistel, &u.address()).into_iter().map(|(p, _)| p).collect();
            let n = l.feistel.nonce(&u.address());
            l.apply_feistel(&FeistelTx::new(u, n, 0, Action::Import { outpoints: ops })).map(|_| ())
        }
        5 | 6 => {
            let n = l.feistel.nonce(&u.address());
            let action = if op % 12 == 5 {
                Action::Transfer { to: other.address(), amount }
            } else {
                Action::Export { amount }
            };
            l.apply_feistel(&FeistelTx::new(u, n, 0, action)).map(|_| ())
        }
        7 => {
            let pool = l.atomic_of(ChainId::Atbash, &u.address());
            let total: u64 = pool.iter().map(|(_, o)| o.amount).sum();
            if total <= TX_FEE {
                return Some(());
            }
            let spends: Vec<_> = pool.iter().map(|(p, _)| (*p, Source::Atomic, u)).collect();
            let b = Transfer::spend(&spends, vec![TxOut::native(u.address(), total - TX_FEE)]);
            l.apply_atbash(&AtbashTx { base: b, create_asset: None }.sign(&vec![u; spends.len()]))
        }
        8 => {
            let node = k.vals[(amount % 4) as usize].address();
            native_transfer(l, ChainId::Kerckhoffs, Source::Local, u, vec![], None, amount).and_then(|(b, n)| {
                let kind = KerckhoffsKind::AddDelegator { node, stake: amount, reward: u.address() };
                l.apply_kerckhoffs(&KerckhoffsTx { base: b, kind }.sign(&vec![u; n]))
            })
        }
        9 => {
            let v = &k.vals[(amount % 4) as usize];
            l.apply_kerckhoffs(&KerckhoffsTx::exit(v.address(), v))
        }
        10 => {
            let v = &k.vals[(amount % 4) as usize];
            let nonce = l.claim_nonces.get(&v.address()).copied().unwrap_or(0);
            l.apply_kerckhoffs(&KerckhoffsTx::claim_rewards(v, nonce))
        }
        _ => {
            let chain = [ChainId::Kerckhoffs, ChainId::Atbash, ChainId::Feistel][(amount % 3) as usize];
            block(k, l, chain);
            Ok(())
        }
    };
    Some(())
}

fuzz_target!(|data: &[u8]| {
    let k = keys();
    let mut l = k.genesis.clone();
    let mut c = Cursor(data);
    let debug = std::env::var("PQ_DEBUG").is_ok();
    for i in 0..24 {
        let op = c.0.first().copied();
        if step(k, &mut l, &mut c).is_none() {
            break;
        }
        if debug {
            let gap = (k.supply + l.minted as u128) as i128 - (l.native_held() + l.burned as u128) as i128;
            eprintln!("step {i}: op {:?} -> missing {gap}; validators {:?}", op.map(|o| o % 12),
                l.validators.values().map(|v| (v.stake, v.delegated, v.exit_at, v.slashed)).collect::<Vec<_>>());
        }
        assert_eq!(
            l.native_held() + l.burned as u128,
            k.supply + l.minted as u128,
            "native supply not conserved"
        );
    }
});
