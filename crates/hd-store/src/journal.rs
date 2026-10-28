//! The journal: append-only files of operation records.
//!
//! ```text
//! meta/journal.<first seq, 20 digits>
//!
//! header  16 bytes  magic "HDJ1", format 1, three zero bytes,
//!                   the first record's sequence number (u64 LE)
//! record            len    u32 LE, the length of body
//!                   !len   the bitwise complement of len
//!                   body   seq (u64 LE) then the encoded operation
//!                   check  SHA-256(len || !len || body), 32 bytes
//! ```
//!
//! A record is acknowledged only after it has been fdatasynced, and
//! records are only ever appended, so after a crash a journal can end in at
//! most one record that was being written: the *torn tail*. Scanning
//! accepts a tail as torn only when its self-checking length says the
//! record runs past the end of the file (it cannot have been
//! acknowledged), or when it is all zero bytes (space the filesystem
//! allocated but the write never filled). The length is stored with its
//! complement so that a damaged length reads as corruption: otherwise one
//! flipped bit could make a complete, acknowledged record look torn and
//! get cut off. Anything else
//! that fails its check is corruption, and the store refuses to open
//! until an operator decides (`fsck --repair-tail`). Either way the bytes
//! are copied into quarantine before they are cut, never thrown away.

use hd_chunk::ObjectId;
use hd_common::{Error, Result};

use crate::codec::{Dec, Enc};
use crate::model::Op;

pub const MAGIC: &[u8; 4] = b"HDJ1";
pub const FORMAT: u8 = 1;
pub const HEADER_LEN: usize = 16;
/// The largest record body. Operations are small (a few paths and IDs).
pub const MAX_RECORD: usize = 1024 * 1024;
/// Length, complement, and checksum around each body.
const FRAME: usize = 8 + 32;

pub fn file_name(first_seq: u64) -> String {
    format!("journal.{first_seq:020}")
}

/// The first sequence number from a journal's file name.
pub fn parse_name(name: &str) -> Option<u64> {
    let digits = name.strip_prefix("journal.")?;
    (digits.len() == 20 && digits.bytes().all(|b| b.is_ascii_digit()))
        .then(|| digits.parse().ok())?
}

pub fn header(first_seq: u64) -> [u8; HEADER_LEN] {
    let mut h = [0_u8; HEADER_LEN];
    h[..4].copy_from_slice(MAGIC);
    h[4] = FORMAT;
    h[8..].copy_from_slice(&first_seq.to_le_bytes());
    h
}

/// Frames one record.
pub fn record(seq: u64, op: &Op) -> Result<Vec<u8>> {
    let mut body = Enc::new();
    body.u64(seq);
    op.encode(&mut body);
    let body = body.finish();
    if body.len() > MAX_RECORD {
        return Err(Error::new("operation is too large for a journal record"));
    }
    let len = u32::try_from(body.len()).map_err(|_| Error::new("record too large"))?;
    let mut out = Vec::with_capacity(body.len() + FRAME);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&(!len).to_le_bytes());
    out.extend_from_slice(&body);
    let check = ObjectId::of(&out)?;
    out.extend_from_slice(&check.0);
    Ok(out)
}

/// How a journal ends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tail {
    /// Every byte belongs to a good record.
    Clean,
    /// From `at` on is the remains of an unacknowledged write.
    Torn { at: u64 },
    /// From `at` on fails verification and is not a torn write.
    Corrupt { at: u64, reason: String },
}

/// What scanning a journal found.
#[derive(Debug)]
pub struct Scan {
    pub records: Vec<(u64, Op)>,
    /// Where each good record ends, in order: a prefix of the file that
    /// ends at one of these holds exactly that many records.
    pub ends: Vec<u64>,
    pub tail: Tail,
}

impl Scan {
    /// The length of the good prefix.
    pub fn good_len(&self) -> u64 {
        self.ends.last().copied().unwrap_or(HEADER_LEN as u64)
    }
}

/// Scans a journal's bytes. The header must be intact (the caller handles
/// a journal too short to have one); records must carry consecutive
/// sequence numbers from the header's.
pub fn scan(bytes: &[u8], first_seq: u64) -> Result<Scan> {
    if bytes.len() < HEADER_LEN {
        return Err(Error::new("journal is shorter than its header"));
    }
    if bytes[..HEADER_LEN] != header(first_seq) {
        return Err(Error::new("journal header does not match its name"));
    }
    let mut records = Vec::new();
    let mut ends = Vec::new();
    let mut pos = HEADER_LEN;
    let tail = loop {
        let rest = &bytes[pos..];
        let at = pos as u64;
        if rest.is_empty() {
            break Tail::Clean;
        }
        let all_zero = rest.iter().all(|&b| b == 0);
        // Longer than any single record: whatever it is, it is more than
        // one interrupted write.
        let could_be_one_record = rest.len() < MAX_RECORD + FRAME;
        if rest.len() < 8 {
            break if could_be_one_record { Tail::Torn { at } } else { corrupt(at, "bad length") };
        }
        let mut word = [0_u8; 4];
        word.copy_from_slice(&rest[..4]);
        let len = u32::from_le_bytes(word);
        word.copy_from_slice(&rest[4..8]);
        if u32::from_le_bytes(word) != !len {
            break if all_zero && could_be_one_record {
                Tail::Torn { at }
            } else {
                corrupt(at, "damaged record length")
            };
        }
        let len = len as usize;
        if len == 0 || len > MAX_RECORD {
            break corrupt(at, "impossible record length");
        }
        if rest.len() < len + FRAME {
            // An intact length says the record runs past the end of the
            // file: a write that was still in progress.
            break Tail::Torn { at };
        }
        let framed = &rest[..8 + len];
        let mut check = [0_u8; 32];
        check.copy_from_slice(&rest[8 + len..len + FRAME]);
        if ObjectId::of(framed)?.0 != check {
            break corrupt(at, "checksum mismatch");
        }
        let expected = first_seq + records.len() as u64;
        let mut d = Dec::new(&framed[8..]);
        let decoded = d.u64().and_then(|seq| {
            let op = Op::decode(&mut d)?;
            d.end()?;
            Ok((seq, op))
        });
        match decoded {
            Ok((seq, op)) if seq == expected => records.push((seq, op)),
            Ok((seq, _)) => {
                break corrupt(at, &format!("record {seq} where {expected} belongs"));
            }
            Err(_) => break corrupt(at, "record does not decode"),
        }
        pos += len + FRAME;
        ends.push(pos as u64);
    };
    Ok(Scan { records, ends, tail })
}

fn corrupt(at: u64, reason: &str) -> Tail {
    Tail::Corrupt { at, reason: reason.to_owned() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::tests::content;

    fn ops(n: u64) -> Vec<Op> {
        (0..n)
            .map(|i| Op::PutVersion {
                user: "u".into(),
                path: format!("f{i}"),
                content: content(&i.to_string()),
            })
            .collect()
    }

    fn journal(first: u64, ops: &[Op]) -> Vec<u8> {
        let mut out = header(first).to_vec();
        for (i, op) in ops.iter().enumerate() {
            out.extend(record(first + i as u64, op).unwrap());
        }
        out
    }

    #[test]
    fn names() {
        assert_eq!(file_name(7), "journal.00000000000000000007");
        assert_eq!(parse_name(&file_name(u64::MAX)), Some(u64::MAX));
        assert_eq!(parse_name("journal.7"), None);
        assert_eq!(parse_name("snapshot.00000000000000000007"), None);
    }

    #[test]
    fn every_prefix_is_a_clean_or_torn_journal_of_whole_records() {
        let ops = ops(5);
        let bytes = journal(10, &ops);
        let full = scan(&bytes, 10).unwrap();
        assert_eq!(full.tail, Tail::Clean);
        assert_eq!(full.records.len(), 5);
        for cut in HEADER_LEN..=bytes.len() {
            let s = scan(&bytes[..cut], 10).unwrap();
            let whole = full.ends.iter().filter(|&&e| e <= cut as u64).count();
            assert_eq!(s.records.len(), whole, "cut {cut}");
            assert_eq!(s.records[..], full.records[..whole]);
            if full.ends.contains(&(cut as u64)) || cut == HEADER_LEN {
                assert_eq!(s.tail, Tail::Clean, "cut {cut}");
            } else {
                assert_eq!(s.tail, Tail::Torn { at: s.good_len() }, "cut {cut}");
            }
        }
    }

    #[test]
    fn zeroed_space_after_the_last_record_is_torn() {
        let mut bytes = journal(1, &ops(2));
        let good = bytes.len() as u64;
        bytes.extend([0_u8; 4096]);
        assert_eq!(scan(&bytes, 1).unwrap().tail, Tail::Torn { at: good });
    }

    #[test]
    fn any_flipped_byte_in_a_record_is_corruption_not_a_torn_tail() {
        let bytes = journal(1, &ops(3));
        let full = scan(&bytes, 1).unwrap();
        for at in HEADER_LEN..bytes.len() {
            let mut bad = bytes.clone();
            bad[at] ^= 0x10;
            let s = scan(&bad, 1).unwrap();
            let damaged = full.ends.iter().filter(|&&e| e <= at as u64).count();
            assert_eq!(s.records.len(), damaged, "byte {at}");
            // Never read as torn: that would let recovery cut off records
            // that were acknowledged.
            assert!(matches!(s.tail, Tail::Corrupt { .. }), "byte {at}: {:?}", s.tail);
        }
    }

    #[test]
    fn headers_and_sequence_numbers_are_checked() {
        let bytes = journal(1, &ops(2));
        assert!(scan(&bytes, 2).is_err());
        assert!(scan(&bytes[..10], 1).is_err());
        // Records must continue the header's numbering.
        let mut out = header(1).to_vec();
        out.extend(record(1, &ops(1)[0]).unwrap());
        out.extend(record(3, &ops(1)[0]).unwrap());
        assert!(matches!(scan(&out, 1).unwrap().tail, Tail::Corrupt { .. }));
    }
}
