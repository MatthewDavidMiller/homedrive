//! Content-defined chunking and the object identifiers it produces.
//!
//! A file is cut into chunks wherever a rolling hash of its content says so
//! (FastCDC with normalised chunking, Xia et al. 2016/2020), not at fixed
//! offsets. An edit therefore moves only the boundaries near it, and every
//! chunk before and after an insertion keeps its bytes and so its ID. That
//! is what lets a new version of a large file cost only the chunks it
//! changed, and lets identical regions of different files share storage.
//!
//! A chunk's ID is the SHA-256 of its bytes. Nothing else names stored
//! data, so a chunk can always be checked against its own name.
//!
//! **These parameters and the gear table are a storage format.** The server
//! and every client must cut identically, or deduplication stops working
//! between them (nothing is lost, but everything is stored twice). The tests
//! pin the gear table and the cut points of a fixed input. Changing either
//! needs a new format version, not an edit.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::disallowed_methods))]

use std::fmt;
use std::io::{ErrorKind, Read};
use std::sync::OnceLock;

use hd_common::{Error, Result};
use hd_crypto::{SHA256_LEN, Sha256};

/// No chunk is smaller than this, except the last chunk of a file (and a
/// file shorter than this is a single chunk).
pub const MIN_CHUNK: usize = 256 * 1024;
/// The size chunks are normalised towards.
pub const AVG_CHUNK: usize = 1024 * 1024;
/// No chunk is larger than this.
pub const MAX_CHUNK: usize = 4 * 1024 * 1024;

/// Before the average size, a cut needs 22 zero bits (harder than average);
/// after it, 18 (easier). This is FastCDC's normalisation level 2 around a
/// 2^20 average. The mask selects the top bits because a gear hash's top
/// bits mix the most recent 64 bytes.
const MASK_HARD: u64 = !0 << (64 - 22);
const MASK_EASY: u64 = !0 << (64 - 18);

const GEAR_DOMAIN: &[u8] = b"homedrive/fastcdc/gear/v1";

static GEAR: OnceLock<[u64; 256]> = OnceLock::new();

/// The gear table: entry `i` is the first eight bytes, big-endian, of
/// SHA-256(`GEAR_DOMAIN` || `i`). Derived rather than listed so it can be
/// re-checked from its definition.
pub fn gear() -> Result<&'static [u64; 256]> {
    if let Some(table) = GEAR.get() {
        return Ok(table);
    }
    let mut table = [0_u64; 256];
    let mut input = GEAR_DOMAIN.to_vec();
    input.push(0);
    for (i, entry) in table.iter_mut().enumerate() {
        if let Some(last) = input.last_mut() {
            *last = u8::try_from(i).map_err(|_| Error::new("gear index out of range"))?;
        }
        let digest = hd_crypto::sha256(&input).map_err(|_| Error::new("SHA-256 failed"))?;
        let mut first = [0_u8; 8];
        first.copy_from_slice(&digest[..8]);
        *entry = u64::from_be_bytes(first);
    }
    let _ = GEAR.set(table);
    GEAR.get().ok_or_else(|| Error::new("gear table unavailable"))
}

/// Where the first chunk of `data` ends. The answer depends only on the
/// first `MAX_CHUNK` bytes, so a caller that holds fewer must know they are
/// the end of the input: a streaming caller only asks once it holds
/// `MAX_CHUNK` bytes or has reached end of file.
pub fn cut_point(gear: &[u64; 256], data: &[u8]) -> usize {
    let end = data.len().min(MAX_CHUNK);
    if end <= MIN_CHUNK {
        return end;
    }
    let normal = AVG_CHUNK.min(end);
    let mut hash: u64 = 0;
    let mut i = MIN_CHUNK;
    while i < normal {
        hash = (hash << 1).wrapping_add(gear[usize::from(data[i])]);
        if hash & MASK_HARD == 0 {
            return i + 1;
        }
        i += 1;
    }
    while i < end {
        hash = (hash << 1).wrapping_add(gear[usize::from(data[i])]);
        if hash & MASK_EASY == 0 {
            return i + 1;
        }
        i += 1;
    }
    end
}

/// The SHA-256 name of a stored object: a chunk, or a manifest.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectId(pub [u8; SHA256_LEN]);

impl ObjectId {
    /// The ID of `data`.
    pub fn of(data: &[u8]) -> Result<Self> {
        hd_crypto::sha256(data).map(Self).map_err(|_| Error::new("SHA-256 failed"))
    }

    /// Parses 64 lowercase hex digits. Uppercase is refused, so every ID has
    /// exactly one spelling (it is also a file name).
    pub fn parse(text: &str) -> Option<Self> {
        if text.len() != SHA256_LEN * 2 || text.bytes().any(|b| b.is_ascii_uppercase()) {
            return None;
        }
        let bytes = hd_common::buf::hex_decode(text)?;
        bytes.try_into().ok().map(Self)
    }

    pub fn hex(&self) -> String {
        hd_common::buf::hex(&self.0)
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex())
    }
}

impl fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectId({})", self.hex())
    }
}

/// One chunk of a stream.
#[derive(Debug)]
pub struct Chunk {
    /// Where the chunk starts in the stream.
    pub offset: u64,
    pub id: ObjectId,
    pub data: Vec<u8>,
}

/// What a whole stream turned out to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamSummary {
    pub len: u64,
    pub sha256: [u8; SHA256_LEN],
}

/// Cuts a stream into chunks while hashing the whole of it. Memory is
/// bounded by `MAX_CHUNK` plus the chunk being returned.
pub struct Chunker<R> {
    reader: R,
    gear: &'static [u64; 256],
    buf: Vec<u8>,
    eof: bool,
    offset: u64,
    whole: Sha256,
}

impl<R> fmt::Debug for Chunker<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Chunker(offset {}, buffered {})", self.offset, self.buf.len())
    }
}

impl<R: Read> Chunker<R> {
    pub fn new(reader: R) -> Result<Self> {
        Ok(Self {
            reader,
            gear: gear()?,
            buf: Vec::with_capacity(MAX_CHUNK),
            eof: false,
            offset: 0,
            whole: Sha256::new().map_err(|_| Error::new("SHA-256 failed"))?,
        })
    }

    /// Reads until `MAX_CHUNK` bytes are buffered or the stream ends.
    fn fill(&mut self) -> Result<()> {
        while !self.eof && self.buf.len() < MAX_CHUNK {
            // Read straight into the buffer's tail, then keep what arrived.
            let start = self.buf.len();
            self.buf.resize(MAX_CHUNK, 0);
            let read = self.reader.read(&mut self.buf[start..]);
            let got = *read.as_ref().unwrap_or(&0);
            self.buf.truncate(start + got);
            match read {
                Ok(0) => self.eof = true,
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    /// The next chunk, or `None` once the stream is exhausted.
    pub fn next_chunk(&mut self) -> Result<Option<Chunk>> {
        self.fill()?;
        if self.buf.is_empty() {
            return Ok(None);
        }
        let cut = cut_point(self.gear, &self.buf);
        let rest = self.buf.split_off(cut);
        let data = std::mem::replace(&mut self.buf, rest);
        self.buf.reserve(MAX_CHUNK.saturating_sub(self.buf.len()));
        self.whole.update(&data);
        let chunk = Chunk { offset: self.offset, id: ObjectId::of(&data)?, data };
        self.offset += chunk.data.len() as u64;
        Ok(Some(chunk))
    }

    /// The length and SHA-256 of everything read. Call after `next_chunk`
    /// has returned `None`; earlier, it reports only the chunks returned so
    /// far, and says so with an error.
    pub fn finish(self) -> Result<StreamSummary> {
        if !(self.eof && self.buf.is_empty()) {
            return Err(Error::new("the stream was not read to its end"));
        }
        let len = self.whole.len();
        let sha256 = self.whole.finish().map_err(|_| Error::new("SHA-256 failed"))?;
        Ok(StreamSummary { len, sha256 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// xorshift64*: a fixed, portable pseudo-random byte source, so the
    /// pinned cut points below are reproducible anywhere.
    fn noise(len: usize, mut seed: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            seed ^= seed >> 12;
            seed ^= seed << 25;
            seed ^= seed >> 27;
            out.extend_from_slice(&seed.wrapping_mul(0x2545_f491_4f6c_dd1d).to_le_bytes());
        }
        out.truncate(len);
        out
    }

    fn cuts(data: &[u8]) -> Vec<usize> {
        let g = gear().unwrap();
        let mut out = Vec::new();
        let mut at = 0;
        while at < data.len() {
            at += cut_point(g, &data[at..]);
            out.push(at);
        }
        out
    }

    fn chunk_all<R: Read>(r: R) -> (Vec<Chunk>, StreamSummary) {
        let mut c = Chunker::new(r).unwrap();
        let mut chunks = Vec::new();
        while let Some(chunk) = c.next_chunk().unwrap() {
            chunks.push(chunk);
        }
        (chunks, c.finish().unwrap())
    }

    /// A reader that hands out at most a few bytes at a time and is
    /// sometimes interrupted, as pipes and sockets are.
    struct Trickle<'a> {
        data: &'a [u8],
        step: usize,
    }

    impl Read for Trickle<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            self.step += 1;
            if self.step.is_multiple_of(7) {
                return Err(ErrorKind::Interrupted.into());
            }
            let n = (self.step % 5_000 + 1).min(out.len()).min(self.data.len());
            out[..n].copy_from_slice(&self.data[..n]);
            self.data = &self.data[n..];
            Ok(n)
        }
    }

    #[test]
    fn gear_table_is_pinned() {
        let table = gear().unwrap();
        let mut bytes = Vec::new();
        for v in table {
            bytes.extend_from_slice(&v.to_be_bytes());
        }
        assert_eq!(hd_crypto::hex(&hd_crypto::sha256(&bytes).unwrap()), GEAR_TABLE_SHA256);
        assert_eq!(table[0], GEAR_0);
    }

    #[test]
    fn cut_points_of_a_fixed_input_are_pinned() {
        let data = noise(12 * 1024 * 1024, 0x0123_4567_89ab_cdef);
        assert_eq!(cuts(&data), PINNED_CUTS);
    }

    #[test]
    fn every_chunk_is_within_bounds() {
        for data in [noise(9 * 1024 * 1024, 7), vec![0_u8; 9 * 1024 * 1024], vec![0xa5; 5_000_123]]
        {
            let c = cuts(&data);
            let mut prev = 0;
            for (i, &end) in c.iter().enumerate() {
                let len = end - prev;
                assert!(len <= MAX_CHUNK, "chunk {i} is {len} bytes");
                if i + 1 < c.len() {
                    assert!(len >= MIN_CHUNK, "chunk {i} is {len} bytes");
                }
                prev = end;
            }
            assert_eq!(prev, data.len());
        }
    }

    #[test]
    fn small_and_empty_inputs() {
        let (chunks, summary) = chunk_all(&b""[..]);
        assert!(chunks.is_empty());
        assert_eq!(summary.len, 0);
        assert_eq!(
            hd_crypto::hex(&summary.sha256),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let (chunks, summary) = chunk_all(&b"abc"[..]);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].data, b"abc");
        assert_eq!(chunks[0].id.0, summary.sha256);
        assert_eq!(chunks[0].id.0, hd_crypto::sha256(b"abc").unwrap());
    }

    #[test]
    fn streaming_matches_slicing_and_reassembles() {
        let data = noise(7 * 1024 * 1024 + 333, 99);
        let (chunks, summary) = chunk_all(Trickle { data: &data, step: 0 });
        let ends: Vec<usize> =
            chunks.iter().map(|c| usize::try_from(c.offset).unwrap() + c.data.len()).collect();
        assert_eq!(ends, cuts(&data));
        let mut joined = Vec::new();
        for c in &chunks {
            assert_eq!(usize::try_from(c.offset).unwrap(), joined.len());
            assert_eq!(c.id, ObjectId::of(&c.data).unwrap());
            joined.extend_from_slice(&c.data);
        }
        assert_eq!(joined, data);
        assert_eq!(summary.len, data.len() as u64);
        assert_eq!(summary.sha256, hd_crypto::sha256(&data).unwrap());
    }

    #[test]
    fn an_edit_moves_only_nearby_boundaries() {
        let original = noise(16 * 1024 * 1024, 4242);
        let ids = |d: &[u8]| -> Vec<ObjectId> {
            let mut prev = 0;
            cuts(d)
                .into_iter()
                .map(|end| {
                    let id = ObjectId::of(&d[prev..end]).unwrap();
                    prev = end;
                    id
                })
                .collect()
        };
        let before = ids(&original);
        let at = 8 * 1024 * 1024 + 17;
        for edited in [
            [&original[..at], b"an insertion of a few bytes", &original[at..]].concat(),
            [&original[..at], &original[at + 1000..]].concat(),
        ] {
            let after = ids(&edited);
            let shared = after.iter().filter(|id| before.contains(id)).count();
            // Only the chunk holding the edit, and at most the one after it
            // while the hash resynchronises, may differ.
            assert!(shared + 2 >= before.len(), "{shared} of {} chunks kept", before.len());
        }
    }

    #[test]
    fn finish_refuses_a_partly_read_stream() {
        let data = noise(6 * 1024 * 1024, 5);
        let mut c = Chunker::new(&data[..]).unwrap();
        assert!(c.next_chunk().unwrap().is_some());
        assert!(c.finish().is_err());
    }

    #[test]
    fn ids_have_one_spelling() {
        let id = ObjectId::of(b"abc").unwrap();
        let text = id.hex();
        assert_eq!(ObjectId::parse(&text), Some(id));
        assert_eq!(ObjectId::parse(&text.to_uppercase()), None);
        assert_eq!(ObjectId::parse(&text[1..]), None);
        assert_eq!(ObjectId::parse(&format!("{}g", &text[1..])), None);
        assert_eq!(format!("{id}"), text);
    }

    // Pinned on 2026-10-27 and reproduced independently from the definitions
    // above (Python's hashlib and a separate implementation of cut_point),
    // so they check the format, not just this code against itself.
    const GEAR_TABLE_SHA256: &str =
        "4640a30e66cb9aee1663a09ee9ef391044564c73bf14ae62794db5a0ee1e8350";
    const GEAR_0: u64 = 0xa364_8db9_7a75_19ac;
    const PINNED_CUTS: &[usize] = &[
        1_141_515, 2_516_293, 3_306_845, 4_432_207, 5_627_547, 7_001_755, 7_382_400, 8_470_267,
        8_838_820, 9_453_910, 10_582_004, 11_858_169, 12_429_263, 12_582_912,
    ];
}
