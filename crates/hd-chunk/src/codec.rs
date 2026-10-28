//! The binary encoding of journal records, snapshots, and manifests.
//!
//! Integers are little-endian and fixed-width; byte strings and text carry
//! a `u32` length. Decoding is strict: every length is checked against
//! what remains, text must be UTF-8, and [`Dec::end`] refuses trailing
//! bytes, so one encoding means one value.

use crate::ObjectId;
use hd_common::{Error, Result};

#[derive(Debug, Default)]
pub struct Enc(Vec<u8>);

impl Enc {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }

    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.u8(u8::from(v))
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn i64(&mut self, v: i64) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn raw(&mut self, v: &[u8]) -> &mut Self {
        self.0.extend_from_slice(v);
        self
    }

    /// A length-prefixed byte string. Every caller's strings are bounded
    /// far below 4 GiB (paths, names, lists of IDs), so a longer one is a
    /// bug and saturates rather than wrapping.
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.u32(u32::try_from(v.len()).unwrap_or(u32::MAX));
        self.raw(v)
    }

    pub fn str(&mut self, v: &str) -> &mut Self {
        self.bytes(v.as_bytes())
    }

    pub fn id(&mut self, v: &ObjectId) -> &mut Self {
        self.raw(&v.0)
    }

    /// A count for a list that follows.
    pub fn len(&mut self, n: usize) -> &mut Self {
        self.u64(n as u64)
    }

    pub fn finish(self) -> Vec<u8> {
        self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug)]
pub struct Dec<'a> {
    buf: &'a [u8],
    pos: usize,
}

fn malformed() -> Error {
    Error::new("malformed encoding")
}

impl<'a> Dec<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or_else(malformed)?;
        let out = self.buf.get(self.pos..end).ok_or_else(malformed)?;
        self.pos = end;
        Ok(out)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0_u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn bool(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(malformed()),
        }
    }

    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    pub fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_le_bytes(self.array()?))
    }

    pub fn raw32(&mut self) -> Result<[u8; 32]> {
        self.array()
    }

    pub fn bytes(&mut self) -> Result<&'a [u8]> {
        let n = usize::try_from(self.u32()?).map_err(|_| malformed())?;
        self.take(n)
    }

    pub fn str(&mut self) -> Result<String> {
        std::str::from_utf8(self.bytes()?).map(str::to_owned).map_err(|_| malformed())
    }

    pub fn id(&mut self) -> Result<ObjectId> {
        Ok(ObjectId(self.array()?))
    }

    /// A list count, refused when it promises more items (of at least
    /// `min_item` bytes each) than the remaining input could hold, so a
    /// corrupt count cannot make a decoder reserve huge amounts of memory.
    pub fn len(&mut self, min_item: usize) -> Result<usize> {
        let n = usize::try_from(self.u64()?).map_err(|_| malformed())?;
        if n.saturating_mul(min_item.max(1)) > self.remaining() {
            return Err(malformed());
        }
        Ok(n)
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Fails unless everything was consumed.
    pub fn end(&self) -> Result<()> {
        if self.pos == self.buf.len() { Ok(()) } else { Err(malformed()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_strictness() {
        let id = ObjectId::of(b"x").unwrap();
        let mut e = Enc::new();
        e.u8(7).bool(true).u32(9).u64(u64::MAX).i64(-5).str("héllo").id(&id).len(2);
        let bytes = e.finish();
        let mut d = Dec::new(&bytes);
        assert_eq!(d.u8().unwrap(), 7);
        assert!(d.bool().unwrap());
        assert_eq!(d.u32().unwrap(), 9);
        assert_eq!(d.u64().unwrap(), u64::MAX);
        assert_eq!(d.i64().unwrap(), -5);
        assert_eq!(d.str().unwrap(), "héllo");
        assert_eq!(d.id().unwrap(), id);
        assert!(d.end().is_err());
        // A count of 2 with nothing after it cannot be honest.
        assert!(d.len(1).is_err());
        for cut in 0..bytes.len() {
            let mut d = Dec::new(&bytes[..cut]);
            let ok = (|| -> Result<()> {
                d.u8()?;
                d.bool()?;
                d.u32()?;
                d.u64()?;
                d.i64()?;
                d.str()?;
                d.id()?;
                d.u64()?;
                d.end()
            })();
            assert!(ok.is_err(), "cut at {cut}");
        }
        assert!(Dec::new(&[2]).bool().is_err());
        assert!(Dec::new(&[1, 0, 0, 0, 0xff]).str().is_err());
    }
}
