//! A growable byte buffer with a hard ceiling, and a checked read cursor.
//!
//! Every [`BoundedBuf`] is created with the most it may ever hold. An append
//! that would pass it, or an allocation that fails, marks the buffer failed
//! and leaves its contents as they were; every later append is a no-op.
//! Callers build a whole document and check [`BoundedBuf::failed`] once
//! instead of checking every append and risking the one that was missed.

use std::fmt;

#[derive(Debug, Default)]
pub struct BoundedBuf {
    data: Vec<u8>,
    limit: usize,
    failed: bool,
}

impl BoundedBuf {
    pub const fn new(limit: usize) -> Self {
        Self { data: Vec::new(), limit, failed: false }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    pub fn failed(&self) -> bool {
        self.failed
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// The contents as text, or "" when they are not valid UTF-8.
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.data).unwrap_or("")
    }

    /// Makes room for `extra` more bytes without passing the limit.
    pub fn reserve(&mut self, extra: usize) -> bool {
        if self.failed {
            return false;
        }
        let Some(need) = self.data.len().checked_add(extra).filter(|&n| n <= self.limit) else {
            self.failed = true;
            return false;
        };
        if need <= self.data.capacity() {
            return true;
        }
        // Geometric growth from 64 bytes, never past the limit.
        let mut cap = self.data.capacity().max(64);
        while cap < need {
            cap = cap.saturating_mul(2);
        }
        let cap = cap.min(self.limit);
        if self.data.try_reserve_exact(cap - self.data.len()).is_err() {
            self.failed = true;
            return false;
        }
        true
    }

    pub fn append(&mut self, bytes: &[u8]) {
        if self.reserve(bytes.len()) {
            self.data.extend_from_slice(bytes);
        }
    }

    pub fn push(&mut self, byte: u8) {
        self.append(&[byte]);
    }

    pub fn push_str(&mut self, text: &str) {
        self.append(text.as_bytes());
    }

    /// Appends `bytes` as lowercase hex.
    pub fn hex(&mut self, bytes: &[u8]) {
        let Some(width) = bytes.len().checked_mul(2) else {
            self.failed = true;
            return;
        };
        if !self.reserve(width) {
            return;
        }
        for &b in bytes {
            self.data.push(HEX[usize::from(b >> 4)]);
            self.data.push(HEX[usize::from(b & 15)]);
        }
    }

    /// Removes the first `n` bytes, keeping the rest.
    pub fn consume(&mut self, n: usize) {
        if n >= self.data.len() {
            self.clear();
        } else {
            self.data.drain(..n);
        }
    }

    pub fn clear(&mut self) {
        self.data.clear();
        self.failed = false;
    }

    /// The contents, or `None` for a failed buffer.
    pub fn into_vec(self) -> Option<Vec<u8>> {
        if self.failed { None } else { Some(self.data) }
    }

    /// The contents as text, or `None` for a failed or non-UTF-8 buffer.
    pub fn into_string(self) -> Option<String> {
        self.into_vec().and_then(|v| String::from_utf8(v).ok())
    }

    /// Zeroes the contents, including spare capacity, before releasing them.
    pub fn wipe(&mut self) {
        wipe_vec(&mut self.data);
        self.failed = false;
    }
}

impl fmt::Write for BoundedBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.push_str(s);
        if self.failed { Err(fmt::Error) } else { Ok(()) }
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 15)]));
    }
    out
}

/// Decodes hex of either case; `None` for an odd length or a non-hex digit.
pub fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let digit = |c: u8| char::from(c).to_digit(16).and_then(|d| u8::try_from(d).ok());
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs.iter().map(|&[hi, lo]| Some(digit(hi)? << 4 | digit(lo)?)).collect()
}

/// Overwrites a vector's whole allocation with zeroes, then empties it.
///
/// The zeroes are one memset over the capacity; handing the result to
/// `std::hint::black_box` makes the optimiser treat it as read, so it cannot
/// drop the stores as dead writes to memory about to be freed.
pub fn wipe_vec(v: &mut Vec<u8>) {
    let cap = v.capacity();
    v.clear();
    v.resize(cap, 0);
    std::hint::black_box(v.as_slice());
    v.clear();
}

/// Overwrites a string's allocation with zeroes, then empties it.
pub fn wipe_string(s: &mut String) {
    let mut bytes = std::mem::take(s).into_bytes();
    wipe_vec(&mut bytes);
}

/// A read-only view with a cursor. Every read checks the remaining length
/// and returns `None` rather than reading past the end.
#[derive(Clone, Copy, Debug)]
pub struct Cursor<'a> {
    rest: &'a [u8],
}

impl<'a> Cursor<'a> {
    pub const fn new(data: &'a [u8]) -> Self {
        Self { rest: data }
    }

    pub const fn remaining(&self) -> usize {
        self.rest.len()
    }

    pub const fn rest(&self) -> &'a [u8] {
        self.rest
    }

    pub fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }

    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.rest.split_at_checked(n)?;
        self.rest = tail;
        Some(head)
    }

    pub fn u8(&mut self) -> Option<u8> {
        let (&b, tail) = self.rest.split_first()?;
        self.rest = tail;
        Some(b)
    }

    pub fn be16(&mut self) -> Option<u16> {
        let (head, tail) = self.rest.split_first_chunk::<2>()?;
        self.rest = tail;
        Some(u16::from_be_bytes(*head))
    }

    pub fn be24(&mut self) -> Option<u32> {
        let (head, tail) = self.rest.split_first_chunk::<3>()?;
        self.rest = tail;
        Some(u32::from(head[0]) << 16 | u32::from(head[1]) << 8 | u32::from(head[2]))
    }

    pub fn be32(&mut self) -> Option<u32> {
        let (head, tail) = self.rest.split_first_chunk::<4>()?;
        self.rest = tail;
        Some(u32::from_be_bytes(*head))
    }

    pub fn be64(&mut self) -> Option<u64> {
        let (head, tail) = self.rest.split_first_chunk::<8>()?;
        self.rest = tail;
        Some(u64::from_be_bytes(*head))
    }

    pub fn le16(&mut self) -> Option<u16> {
        let (head, tail) = self.rest.split_first_chunk::<2>()?;
        self.rest = tail;
        Some(u16::from_le_bytes(*head))
    }

    pub fn le32(&mut self) -> Option<u32> {
        let (head, tail) = self.rest.split_first_chunk::<4>()?;
        self.rest = tail;
        Some(u32::from_le_bytes(*head))
    }

    pub fn le64(&mut self) -> Option<u64> {
        let (head, tail) = self.rest.split_first_chunk::<8>()?;
        self.rest = tail;
        Some(u64::from_le_bytes(*head))
    }

    /// A 28-bit ID3v2 "syncsafe" integer: four bytes of seven bits each.
    pub fn syncsafe32(&mut self) -> Option<u32> {
        let (head, tail) = self.rest.split_first_chunk::<4>()?;
        if head.iter().any(|&b| b & 0x80 != 0) {
            return None;
        }
        self.rest = tail;
        Some(head.iter().fold(0, |acc, &b| acc << 7 | u32::from(b)))
    }
}

/// Parses an unsigned decimal of only ASCII digits, rejecting empty input,
/// signs, whitespace, and values above `max`.
pub fn parse_u64(s: &[u8], max: u64) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut value: u64 = 0;
    for &c in s {
        if !c.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u64::from(c - b'0'))?;
        if value > max {
            return None;
        }
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_stop_at_the_limit_and_stay_failed() {
        let mut b = BoundedBuf::new(4);
        b.push_str("abc");
        b.push_str("de");
        assert!(b.failed());
        assert_eq!(b.as_bytes(), b"abc");
        b.push(b'x');
        assert_eq!(b.as_bytes(), b"abc");
        b.clear();
        b.hex(&[0xab, 0x01]);
        assert_eq!(b.as_str(), "ab01");
        b.consume(2);
        assert_eq!(b.as_str(), "01");
    }

    #[test]
    fn cursor_never_reads_past_the_end() {
        let mut c = Cursor::new(&[0, 0, 0, 7, 9]);
        assert_eq!(c.be32(), Some(7));
        assert_eq!(c.be32(), None);
        assert_eq!(c.u8(), Some(9));
        assert_eq!(c.u8(), None);
        assert!(c.take(1).is_none());
    }

    #[test]
    fn little_endian_and_syncsafe_reads() {
        let mut c = Cursor::new(&[1, 2, 3, 4, 5, 6, 7, 0, 0, 2, 1]);
        assert_eq!(c.le16(), Some(0x0201));
        assert_eq!(c.be24(), Some(0x0003_0405));
        assert_eq!(c.le16(), Some(0x0706));
        assert_eq!(c.syncsafe32(), Some(257));
        assert_eq!(Cursor::new(&[0x80, 0, 0, 0]).syncsafe32(), None);
        assert_eq!(Cursor::new(&[1, 0, 0, 0, 0, 0, 0, 0]).le64(), Some(1));
        assert_eq!(Cursor::new(&[1, 0, 0, 0]).le32(), Some(1));
    }

    #[test]
    fn hex_decoding() {
        assert_eq!(hex_decode("00fFa1"), Some(vec![0, 0xff, 0xa1]));
        assert_eq!(hex_decode(""), Some(vec![]));
        assert_eq!(hex_decode("abc"), None);
        assert_eq!(hex_decode("zz"), None);
    }

    #[test]
    fn decimal_parsing_is_strict() {
        assert_eq!(parse_u64(b"6400", 65535), Some(6400));
        for bad in [&b""[..], b"+1", b" 1", b"65536", b"99999999999999999999999"] {
            assert_eq!(parse_u64(bad, 65535), None);
        }
    }
}
