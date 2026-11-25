//! Compact binary wire format for network messages and on-disk storage.
//!
//! Decoding is defensive: every length is bounded and every read is checked,
//! so malformed or hostile input produces an error, never a panic or a huge
//! allocation.

use crate::consensus::FinalityCert;
use crate::crypto::*;
use crate::ledger::*;

pub const MAX_BYTES: usize = 1 << 20; // any single byte string
pub const MAX_ITEMS: usize = 100_000; // any list

pub type DecodeResult<T> = Result<T, String>;

#[derive(Default)]
pub struct Writer(pub Vec<u8>);

impl Writer {
    pub fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    pub fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn bytes(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.0.extend_from_slice(b);
    }
    pub fn fixed(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    pub fn list<T: Wire>(&mut self, items: &[T]) {
        self.u32(items.len() as u32);
        for i in items {
            i.put(self);
        }
    }
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> DecodeResult<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or("length overflow")?;
        let s = self.buf.get(self.pos..end).ok_or("unexpected end of input")?;
        self.pos = end;
        Ok(s)
    }
    pub fn u8(&mut self) -> DecodeResult<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u32(&mut self) -> DecodeResult<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> DecodeResult<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn bytes(&mut self) -> DecodeResult<Vec<u8>> {
        let n = self.u32()? as usize;
        if n > MAX_BYTES {
            return Err("byte string too long".into());
        }
        Ok(self.take(n)?.to_vec())
    }
    pub fn hash(&mut self) -> DecodeResult<Hash> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    pub fn list<T: Wire>(&mut self) -> DecodeResult<Vec<T>> {
        let n = self.u32()? as usize;
        if n > MAX_ITEMS {
            return Err("list too long".into());
        }
        let mut v = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            v.push(T::get(self)?);
        }
        Ok(v)
    }
    pub fn finish(&self) -> DecodeResult<()> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err("trailing bytes".into())
        }
    }
}

pub trait Wire: Sized {
    fn put(&self, w: &mut Writer);
    fn get(r: &mut Reader) -> DecodeResult<Self>;

    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::default();
        self.put(&mut w);
        w.0
    }
    fn from_bytes(b: &[u8]) -> DecodeResult<Self> {
        let mut r = Reader::new(b);
        let v = Self::get(&mut r)?;
        r.finish()?;
        Ok(v)
    }
}

impl Wire for Hash {
    fn put(&self, w: &mut Writer) {
        w.fixed(self)
    }
    fn get(r: &mut Reader) -> DecodeResult<Self> {
        r.hash()
    }
}

impl Wire for u64 {
    fn put(&self, w: &mut Writer) {
        w.u64(*self)
    }
    fn get(r: &mut Reader) -> DecodeResult<Self> {
        r.u64()
    }
}

impl Wire for Address {
    fn put(&self, w: &mut Writer) {
        w.fixed(&self.0)
    }
    fn get(r: &mut Reader) -> DecodeResult<Self> {
        Ok(Address(r.hash()?))
    }
}

impl Wire for PublicKey {
    fn put(&self, w: &mut Writer) {
        w.u8(self.alg);
        w.bytes(&self.bytes);
    }
    fn get(r: &mut Reader) -> DecodeResult<Self> {
        Ok(PublicKey { alg: r.u8()?, bytes: r.bytes()? })
    }
}

impl Wire for Signature {
    fn put(&self, w: &mut Writer) {
        w.u8(self.alg);
        w.bytes(&self.bytes);
    }
    fn get(r: &mut Reader) -> DecodeResult<Self> {
        Ok(Signature { alg: r.u8()?, bytes: r.bytes()? })
    }
}

impl Wire for ChainId {
    fn put(&self, w: &mut Writer) {
        match self {
            ChainId::Kerckhoffs => w.u8(0),
            ChainId::Atbash => w.u8(1),
            ChainId::Zone(n) => {
                w.u8(2);
                w.u32(*n);
            }
        }
    }
    fn get(r: &mut Reader) -> DecodeResult<Self> {
        match r.u8()? {
            0 => Ok(ChainId::Kerckhoffs),
            1 => Ok(ChainId::Atbash),
            2 => Ok(ChainId::Zone(r.u32()?)),
            _ => Err("unknown chain id".into()),
        }
    }
}

impl Wire for Option<ChainId> {
    fn put(&self, w: &mut Writer) {
        match self {
            None => w.u8(0),
            Some(c) => {
                w.u8(1);
                c.put(w);
            }
        }
    }
    fn get(r: &mut Reader) -> DecodeResult<Self> {
        match r.u8()? {
            0 => Ok(None),
            1 => Ok(Some(ChainId::get(r)?)),
            _ => Err("bad optional chain flag".into()),
        }
    }
}

impl Wire for RelayMsg {
    fn put(&self, w: &mut Writer) {
        self.src.put(w);
        self.dest.put(w);
        w.fixed(&self.txid);
        w.u32(self.index);
        self.out.put(w);
    }
    fn get(r: &mut Reader) -> DecodeResult<Self> {
        Ok(RelayMsg {
            src: ChainId::get(r)?,
            dest: ChainId::get(r)?,
            txid: r.hash()?,
            index: r.u32()?,
            out: TxOut::get(r)?,
        })
    }
}

impl Wire for RelayIn {
    fn put(&self, w: &mut Writer) {
        self.msg.put(w);
        self.header.put(w);
        self.cert.put(w);
        w.u32(self.leaf);
        w.list(&self.branch);
    }
    fn get(r: &mut Reader) -> DecodeResult<Self> {
        Ok(RelayIn {
            msg: RelayMsg::get(r)?,
            header: BlockHeader::get(r)?,
            cert: FinalityCert::get(r)?,
            leaf: r.u32()?,
            branch: r.list()?,
        })
    }
}

impl Wire for OutPoint {
    fn put(&self, w: &mut Writer) {
        w.fixed(&self.txid);
        w.u32(self.index);
    }
    fn get(r: &mut Reader) -> DecodeResult<Self> {
        Ok(OutPoint { txid: r.hash()?, index: r.u32()? })
    }
}

impl Wire for TxOut {
    fn put(&self, w: &mut Writer) {
        self.owner.put(w);
        w.fixed(&self.asset);
        w.u64(self.amount);
    }
    fn get(r: &mut Reader) -> DecodeResult<Self> {
        Ok(TxOut { owner: Address::get(r)?, asset: r.hash()?, amount: r.u64()? })
    }
}

impl Wire for TxIn {
    fn put(&self, w: &mut Writer) {
        self.prev.put(w);
        w.u8(match self.source {
            Source::Local => 0,
            Source::Atomic => 1,
            Source::Relay => 2,
        });
        self.pubkey.put(w);
        self.sig.put(w);
    }
    fn get(r: &mut Reader) -> DecodeResult<Self> {
        let prev = OutPoint::get(r)?;
        let source = match r.u8()? {
            0 => Source::Local,
            1 => Source::Atomic,
            2 => Source::Relay,
            _ => return Err("bad input source".into()),
        };
        Ok(TxIn { prev, source, pubkey: PublicKey::get(r)?, sig: Signature::get(r)? })
    }
}

impl Wire for Transfer {
    fn put(&self, w: &mut Writer) {
        w.list(&self.inputs);
        w.list(&self.outputs);
        self.export_to.put(w);
        w.list(&self.exported);
        w.list(&self.relay_in);
    }
    fn get(r: &mut Reader) -> DecodeResult<Self> {
        Ok(Transfer {
            inputs: r.list()?,
            outputs: r.list()?,
            export_to: Option::<ChainId>::get(r)?,
            exported: r.list()?,
            relay_in: r.list()?,
        })
    }
}

impl Wire for AtbashTx {
    fn put(&self, w: &mut Writer) {
        self.base.put(w);
        match &self.create_asset {
            None => w.u8(0),
            Some(a) => {
                w.u8(1);
                w.bytes(a.name.as_bytes());
                w.u64(a.supply);
            }
        }
    }
    fn get(r: &mut Reader) -> DecodeResult<Self> {
        let base = Transfer::get(r)?;
        let create_asset = match r.u8()? {
            0 => None,
            1 => {
                let name = String::from_utf8(r.bytes()?).map_err(|_| "asset name not UTF-8")?;
                if name.len() > 64 {
                    return Err("asset name too long".into());
                }
                Some(AssetDef { name, supply: r.u64()? })
            }
            _ => return Err("bad asset flag".into()),
        };
        Ok(AtbashTx { base, create_asset })
    }
}

impl Wire for BlockHeader {
    fn put(&self, w: &mut Writer) {
        self.chain.put(w);
        w.u64(self.height);
        w.fixed(&self.parent);
        w.fixed(&self.tx_root);
        self.proposer.put(w);
        w.u64(self.timestamp);
        w.u32(self.round);
        w.u64(self.anchor);
        w.fixed(&self.msg_root);
    }
    fn get(r: &mut Reader) -> DecodeResult<Self> {
        Ok(BlockHeader {
            chain: ChainId::get(r)?,
            height: r.u64()?,
            parent: r.hash()?,
            tx_root: r.hash()?,
            proposer: Address::get(r)?,
            timestamp: r.u64()?,
            round: r.u32()?,
            anchor: r.u64()?,
            msg_root: r.hash()?,
        })
    }
}

impl Wire for SignedHeader {
    fn put(&self, w: &mut Writer) {
        self.header.put(w);
        self.sig.put(w);
    }
    fn get(r: &mut Reader) -> DecodeResult<Self> {
        Ok(SignedHeader { header: BlockHeader::get(r)?, sig: Signature::get(r)? })
    }
}

impl Wire for KerckhoffsTx {
    fn put(&self, w: &mut Writer) {
        self.base.put(w);
        match &self.kind {
            KerckhoffsKind::Transfer => w.u8(0),
            KerckhoffsKind::AddValidator { signing_key, withdrawal, stake } => {
                w.u8(1);
                signing_key.put(w);
                withdrawal.put(w);
                w.u64(*stake);
            }
            KerckhoffsKind::AddDelegator { node, stake, reward } => {
                w.u8(2);
                node.put(w);
                w.u64(*stake);
                reward.put(w);
            }
            KerckhoffsKind::Slash { a, b } => {
                w.u8(3);
                a.put(w);
                b.put(w);
            }
            KerckhoffsKind::Exit { node, authority, sig } => {
                w.u8(4);
                node.put(w);
                authority.put(w);
                sig.put(w);
            }
            KerckhoffsKind::CreateZone { name, members } => {
                w.u8(5);
                w.bytes(name.as_bytes());
                w.list(members);
            }
        }
    }
    fn get(r: &mut Reader) -> DecodeResult<Self> {
        let base = Transfer::get(r)?;
        let kind = match r.u8()? {
            0 => KerckhoffsKind::Transfer,
            1 => KerckhoffsKind::AddValidator {
                signing_key: PublicKey::get(r)?,
                withdrawal: Address::get(r)?,
                stake: r.u64()?,
            },
            2 => KerckhoffsKind::AddDelegator {
                node: Address::get(r)?,
                stake: r.u64()?,
                reward: Address::get(r)?,
            },
            3 => KerckhoffsKind::Slash {
                a: Box::new(SignedHeader::get(r)?),
                b: Box::new(SignedHeader::get(r)?),
            },
            4 => KerckhoffsKind::Exit {
                node: Address::get(r)?,
                authority: PublicKey::get(r)?,
                sig: Signature::get(r)?,
            },
            5 => {
                let name = String::from_utf8(r.bytes()?).map_err(|_| "zone name not UTF-8")?;
                if name.len() > 32 {
                    return Err("zone name too long".into());
                }
                KerckhoffsKind::CreateZone { name, members: r.list()? }
            }
            _ => return Err("unknown Kerckhoffs tx kind".into()),
        };
        Ok(KerckhoffsTx { base, kind })
    }
}

impl Wire for Block {
    fn put(&self, w: &mut Writer) {
        self.signed.put(w);
        match &self.body {
            Body::Kerckhoffs(t) => {
                w.u8(0);
                w.list(t);
            }
            Body::Atbash(t) => {
                w.u8(1);
                w.list(t);
            }
        }
    }
    fn get(r: &mut Reader) -> DecodeResult<Self> {
        let signed = SignedHeader::get(r)?;
        let body = match r.u8()? {
            0 => Body::Kerckhoffs(r.list()?),
            1 => Body::Atbash(r.list()?),
            _ => return Err("unknown body".into()),
        };
        Ok(Block { signed, body })
    }
}

impl Wire for (Address, Signature) {
    fn put(&self, w: &mut Writer) {
        self.0.put(w);
        self.1.put(w);
    }
    fn get(r: &mut Reader) -> DecodeResult<Self> {
        Ok((Address::get(r)?, Signature::get(r)?))
    }
}

impl Wire for FinalityCert {
    fn put(&self, w: &mut Writer) {
        self.chain.put(w);
        w.u64(self.height);
        w.fixed(&self.block);
        w.list(&self.votes);
    }
    fn get(r: &mut Reader) -> DecodeResult<Self> {
        Ok(FinalityCert {
            chain: ChainId::get(r)?,
            height: r.u64()?,
            block: r.hash()?,
            votes: r.list()?,
        })
    }
}

/// Any transaction, tagged by chain. `Utxo` covers the Atbash Chain and zones.
#[derive(Clone, Debug)]
pub enum Tx {
    Kerckhoffs(KerckhoffsTx),
    Utxo(ChainId, AtbashTx),
}

impl Tx {
    pub fn chain(&self) -> ChainId {
        match self {
            Tx::Kerckhoffs(_) => ChainId::Kerckhoffs,
            Tx::Utxo(c, _) => *c,
        }
    }
    pub fn id(&self) -> Hash {
        match self {
            Tx::Kerckhoffs(t) => t.id(),
            Tx::Utxo(_, t) => t.id(),
        }
    }
    /// Validate and apply to `l` (callers pass a clone to test).
    pub fn apply(&self, l: &mut Ledger) -> Result<(), String> {
        match self {
            Tx::Kerckhoffs(t) => l.apply_kerckhoffs(t),
            Tx::Utxo(c, t) => l.apply_utxo(*c, t),
        }
    }
}

impl Wire for Tx {
    fn put(&self, w: &mut Writer) {
        match self {
            Tx::Kerckhoffs(t) => {
                w.u8(0);
                t.put(w);
            }
            Tx::Utxo(c, t) => {
                w.u8(1);
                c.put(w);
                t.put(w);
            }
        }
    }
    fn get(r: &mut Reader) -> DecodeResult<Self> {
        match r.u8()? {
            0 => Ok(Tx::Kerckhoffs(KerckhoffsTx::get(r)?)),
            1 => Ok(Tx::Utxo(ChainId::get(r)?, AtbashTx::get(r)?)),
            _ => Err("unknown tx chain".into()),
        }
    }
}
