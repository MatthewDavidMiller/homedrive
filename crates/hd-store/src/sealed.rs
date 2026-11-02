//! Sealed files: how copies of the store kept off the server are
//! encrypted, when their owner asks for it.
//!
//! **Keys.** A passphrase is stretched with scrypt (N = 2^17, r = 8, p = 1:
//! 128 MiB and a good fraction of a second per guess) and a random salt
//! into two 256-bit keys: one encrypts, the other names. The parameters
//! and salt are kept beside the copy with a check value, so a wrong
//! passphrase is told apart from damage. Losing the passphrase loses the
//! copy; that is the point.
//!
//! **A sealed file** carries its name (its path in the store) and its
//! bytes, encrypted with AES-256-GCM in segments of 1 MiB, so a file of
//! any size is sealed and opened without holding it in memory:
//!
//! ```text
//! "HDE1"  12-byte random nonce  segment...
//! segment: up to 1 MiB of ciphertext, then a 16-byte tag
//! ```
//!
//! Segment `i` uses the nonce with `i` added into its last eight bytes,
//! and authenticates the file's sealed name and whether it is the last
//! segment. So a changed byte, a segment moved within the file or to
//! another, a file cut short at a segment boundary, or a file given
//! another's name, all fail to open.
//!
//! **Names.** On disk a sealed file is named by an HMAC of its store path
//! under the naming key (its sealed name), so a copy shows neither file
//! names nor which content it holds (objects are named by their content's
//! hash, which would otherwise confirm a guess). The store path is the
//! first thing inside, encrypted, and opening checks that it hashes to the
//! sealed name, so a sealed copy opens back into the store's layout.

use std::io::{self, Read, Write};

use hd_common::json::Value;
use hd_common::{Error, Result};
use hd_crypto::{GCM_KEY_LEN, GCM_NONCE_LEN, GCM_TAG_LEN};

pub const MAGIC: &[u8; 4] = b"HDE1";
const SEGMENT: usize = 1 << 20;
const LOG_N: u8 = 17;
const R: u32 = 8;
const P: u32 = 1;
const CHECK_LABEL: &[u8] = b"homedrive sealed copy key check";
/// The shortest passphrase accepted for a new copy.
pub const MIN_PASSPHRASE: usize = 12;

/// How the keys were derived, kept with the copy (none of it secret).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyParams {
    pub salt: [u8; 16],
    pub log_n: u8,
    pub r: u32,
    pub p: u32,
    /// HMAC of a fixed label under the naming key: tells a wrong
    /// passphrase from a damaged file.
    pub check: [u8; 32],
}

/// The two keys, wiped when dropped.
pub struct Keys {
    seal: [u8; GCM_KEY_LEN],
    names: [u8; 32],
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Keys(..)")
    }
}

impl Drop for Keys {
    fn drop(&mut self) {
        hd_crypto::cleanse(&mut self.seal);
        hd_crypto::cleanse(&mut self.names);
    }
}

fn crypto(e: hd_crypto::CryptoError) -> Error {
    Error::new(format!("encryption failed: {e:?}"))
}

fn derive(passphrase: &str, salt: &[u8], log_n: u8, r: u32, p: u32) -> Result<Keys> {
    if log_n > 22 || r > 32 || p > 4 {
        return Err(Error::new("the key parameters are out of range"));
    }
    let mut out = [0_u8; 64];
    hd_crypto::scrypt(
        passphrase.as_bytes(),
        salt,
        1 << log_n,
        u64::from(r),
        u64::from(p),
        &mut out,
    )
    .map_err(crypto)?;
    let mut keys = Keys { seal: [0; GCM_KEY_LEN], names: [0; 32] };
    keys.seal.copy_from_slice(&out[..32]);
    keys.names.copy_from_slice(&out[32..]);
    hd_crypto::cleanse(&mut out);
    Ok(keys)
}

impl Keys {
    /// New keys from a passphrase, with a fresh salt; the parameters to
    /// keep beside what they seal.
    pub fn create(passphrase: &str) -> Result<(Self, KeyParams)> {
        if passphrase.chars().count() < MIN_PASSPHRASE {
            return Err(Error::new(format!(
                "the passphrase must be at least {MIN_PASSPHRASE} characters"
            )));
        }
        let salt = hd_crypto::random_array::<16>().map_err(crypto)?;
        let keys = derive(passphrase, &salt, LOG_N, R, P)?;
        let check = hd_crypto::hmac_sha256(&keys.names, CHECK_LABEL).map_err(crypto)?;
        Ok((keys, KeyParams { salt, log_n: LOG_N, r: R, p: P, check }))
    }

    /// The keys for `params`, if `passphrase` is the one they were made
    /// with.
    pub fn open(passphrase: &str, params: &KeyParams) -> Result<Self> {
        let keys = derive(passphrase, &params.salt, params.log_n, params.r, params.p)?;
        let check = hd_crypto::hmac_sha256(&keys.names, CHECK_LABEL).map_err(crypto)?;
        if !hd_crypto::ct_equal(&check, &params.check) {
            return Err(Error::new("wrong passphrase"));
        }
        Ok(keys)
    }

    /// The name a sealed file of store path `name` has on disk.
    pub fn sealed_name(&self, name: &str) -> Result<String> {
        Ok(hd_crypto::hex(&hd_crypto::hmac_sha256(&self.names, name.as_bytes()).map_err(crypto)?))
    }
}

impl KeyParams {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"format\":1,\"kdf\":\"scrypt\",\"salt\":\"{}\",\"log_n\":{},\"r\":{},\"p\":{},\"check\":\"{}\"}}",
            hd_crypto::hex(&self.salt),
            self.log_n,
            self.r,
            self.p,
            hd_crypto::hex(&self.check)
        )
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let v = hd_common::json::parse(bytes)
            .map_err(|_| Error::new("the encryption parameters are damaged"))?;
        let bad = || Error::new("the encryption parameters are damaged");
        let text = |k: &str| v.get(k).and_then(Value::as_str).ok_or_else(bad);
        let num = |k: &str| v.get(k).and_then(Value::as_u64).ok_or_else(bad);
        if num("format")? != 1 || text("kdf")? != "scrypt" {
            return Err(Error::new("unknown encryption format"));
        }
        let unhex = |s: &str, out: &mut [u8]| -> Result<()> {
            if s.len() != out.len() * 2 {
                return Err(bad());
            }
            for (i, o) in out.iter_mut().enumerate() {
                *o = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| bad())?;
            }
            Ok(())
        };
        let mut salt = [0_u8; 16];
        unhex(text("salt")?, &mut salt)?;
        let mut check = [0_u8; 32];
        unhex(text("check")?, &mut check)?;
        Ok(Self {
            salt,
            log_n: u8::try_from(num("log_n")?).map_err(|_| bad())?,
            r: u32::try_from(num("r")?).map_err(|_| bad())?,
            p: u32::try_from(num("p")?).map_err(|_| bad())?,
            check,
        })
    }
}

fn segment_nonce(base: &[u8; GCM_NONCE_LEN], index: u64) -> [u8; GCM_NONCE_LEN] {
    let mut nonce = *base;
    let mut tail = [0_u8; 8];
    tail.copy_from_slice(&nonce[4..]);
    nonce[4..].copy_from_slice(&u64::from_be_bytes(tail).wrapping_add(index).to_be_bytes());
    nonce
}

fn segment_aad(name: &str, index: u64, last: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(name.len() + 9);
    aad.extend_from_slice(name.as_bytes());
    aad.extend_from_slice(&index.to_le_bytes());
    aad.push(u8::from(last));
    aad
}

/// Seals what is written to it into `out`; [`Sealer::finish`] writes the
/// last segment.
pub struct Sealer<'k, W: Write> {
    out: W,
    keys: &'k Keys,
    /// The sealed name, which every segment authenticates.
    label: String,
    nonce: [u8; GCM_NONCE_LEN],
    buf: Vec<u8>,
    index: u64,
    sealed: Vec<u8>,
}

impl<W: Write> std::fmt::Debug for Sealer<'_, W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sealer({}, segment {})", self.label, self.index)
    }
}

impl<'k, W: Write> Sealer<'k, W> {
    /// Starts sealing a file of store path `name`. Its first plaintext is
    /// the name itself, so the file can be opened back to it.
    pub fn new(mut out: W, keys: &'k Keys, name: &str) -> Result<Self> {
        let nonce = hd_crypto::random_array::<GCM_NONCE_LEN>().map_err(crypto)?;
        out.write_all(MAGIC)?;
        out.write_all(&nonce)?;
        let len = u16::try_from(name.len()).map_err(|_| Error::new("name too long"))?;
        let mut buf = Vec::with_capacity(SEGMENT);
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(name.as_bytes());
        let label = keys.sealed_name(name)?;
        Ok(Self { out, keys, label, nonce, buf, index: 0, sealed: Vec::new() })
    }

    fn seal_segment(&mut self, last: bool) -> io::Result<()> {
        self.sealed.clear();
        let aad = segment_aad(&self.label, self.index, last);
        hd_crypto::gcm_seal(
            &self.keys.seal,
            &segment_nonce(&self.nonce, self.index),
            &aad,
            &self.buf,
            &mut self.sealed,
        )
        .map_err(|_| io::Error::other("encryption failed"))?;
        hd_crypto::cleanse(&mut self.buf);
        self.buf.clear();
        self.out.write_all(&self.sealed)?;
        self.index += 1;
        Ok(())
    }

    /// Seals the rest and returns the writer.
    pub fn finish(mut self) -> Result<W> {
        self.seal_segment(true)?;
        self.out.flush()?;
        Ok(self.out)
    }
}

impl<W: Write> Write for Sealer<'_, W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let room = SEGMENT - self.buf.len();
        let n = data.len().min(room);
        self.buf.extend_from_slice(&data[..n]);
        if self.buf.len() == SEGMENT {
            self.seal_segment(false)?;
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// Reads exactly `buf.len()` bytes unless the input ends; returns how many.
fn fill(input: &mut dyn Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut got = 0;
    while got < buf.len() {
        match input.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(got)
}

/// Opens a sealed file whose sealed name (its name on disk) is
/// `sealed_name`: checks every segment and writes the plaintext to `out`,
/// and returns the store path inside, which must hash to that name.
/// Nothing unverified reaches `out`: each segment is checked before its
/// bytes are written, and a file cut short fails at the end (the caller
/// discards what was written).
pub fn open(
    input: &mut dyn Read,
    keys: &Keys,
    sealed_name: &str,
    out: &mut dyn Write,
) -> Result<String> {
    let damaged = || Error::new("a sealed file is damaged, or was sealed with another passphrase");
    let mut head = [0_u8; 4 + GCM_NONCE_LEN];
    if fill(input, &mut head)? != head.len() || &head[..4] != MAGIC {
        return Err(Error::new("not a sealed file"));
    }
    let mut nonce = [0_u8; GCM_NONCE_LEN];
    nonce.copy_from_slice(&head[4..]);
    let mut seg = vec![0_u8; SEGMENT + GCM_TAG_LEN];
    let mut next = vec![0_u8; SEGMENT + GCM_TAG_LEN];
    let mut have = fill(input, &mut seg)?;
    let mut plain = Vec::with_capacity(SEGMENT);
    let mut name = None;
    let mut index = 0_u64;
    loop {
        // Last if nothing follows it.
        let more = if have == seg.len() { fill(input, &mut next)? } else { 0 };
        let last = more == 0;
        plain.clear();
        hd_crypto::gcm_open(
            &keys.seal,
            &segment_nonce(&nonce, index),
            &segment_aad(sealed_name, index, last),
            &seg[..have],
            &mut plain,
        )
        .map_err(|_| damaged())?;
        let mut body = &plain[..];
        if index == 0 {
            if body.len() < 2 {
                return Err(damaged());
            }
            let len = usize::from(u16::from_le_bytes([body[0], body[1]]));
            let inner = body.get(2..2 + len).ok_or_else(damaged)?;
            let inner = String::from_utf8(inner.to_vec()).map_err(|_| damaged())?;
            if keys.sealed_name(&inner)? != sealed_name {
                return Err(damaged());
            }
            body = &body[2 + len..];
            name = Some(inner);
        }
        out.write_all(body)?;
        hd_crypto::cleanse(&mut plain);
        if last {
            break;
        }
        std::mem::swap(&mut seg, &mut next);
        have = more;
        index += 1;
    }
    name.ok_or_else(damaged)
}

/// A single sealed file that carries its own key parameters: the web
/// UI's encrypted download of the store.
///
/// ```text
/// "HDK1"  2-byte length  key parameters (JSON)  sealed file
/// ```
pub const STANDALONE_MAGIC: &[u8; 4] = b"HDK1";
/// The store path a standalone sealed download holds.
pub const STANDALONE_NAME: &str = "homedrive-store.tar";

/// Writes the head of a standalone sealed file; the sealed file follows.
pub fn write_standalone_head(out: &mut dyn Write, params: &KeyParams) -> Result<()> {
    let json = params.to_json();
    let len = u16::try_from(json.len()).map_err(|_| Error::new("parameters too long"))?;
    out.write_all(STANDALONE_MAGIC)?;
    out.write_all(&len.to_le_bytes())?;
    out.write_all(json.as_bytes())?;
    Ok(())
}

/// Reads the head of a standalone sealed file: its key parameters.
pub fn read_standalone_head(input: &mut dyn Read) -> Result<KeyParams> {
    let mut head = [0_u8; 6];
    if fill(input, &mut head)? != 6 || &head[..4] != STANDALONE_MAGIC {
        return Err(Error::new("not an encrypted homedrive download"));
    }
    let len = usize::from(u16::from_le_bytes([head[4], head[5]]));
    let mut json = vec![0_u8; len];
    if fill(input, &mut json)? != len {
        return Err(Error::new("the encrypted download is cut short"));
    }
    KeyParams::from_json(&json)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seal(keys: &Keys, name: &str, data: &[u8]) -> Vec<u8> {
        let mut s = Sealer::new(Vec::new(), keys, name).unwrap();
        s.write_all(data).unwrap();
        s.finish().unwrap()
    }

    #[test]
    fn sealed_files_round_trip_and_refuse_every_tampering() {
        let (keys, params) = Keys::create("correct horse battery").unwrap();
        assert!(Keys::create("short").is_err());
        let back = KeyParams::from_json(params.to_json().as_bytes()).unwrap();
        assert_eq!(back, params);
        assert!(
            Keys::open("wrong horse battery", &params).unwrap_err().message().contains("wrong")
        );
        let keys2 = Keys::open("correct horse battery", &params).unwrap();
        // Sizes around the segment boundary, and nothing at all.
        for len in [0, 1, SEGMENT - 1, SEGMENT, SEGMENT + 1, 3 * SEGMENT + 7] {
            let data: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect();
            let sealed = seal(&keys, "chunks/ab/cd/x", &data);
            let label = keys.sealed_name("chunks/ab/cd/x").unwrap();
            let mut out = Vec::new();
            let name = open(&mut &sealed[..], &keys2, &label, &mut out).unwrap();
            assert_eq!((name.as_str(), out == data), ("chunks/ab/cd/x", true), "{len}");
            // Cut short at the end of a whole segment: refused.
            if len > SEGMENT {
                let cut = &sealed[..4 + 12 + SEGMENT + 16];
                assert!(open(&mut &cut[..], &keys, &label, &mut Vec::new()).is_err(), "{len}");
            }
        }
        let sealed = seal(&keys, "meta/journal.1", b"records");
        let label = keys.sealed_name("meta/journal.1").unwrap();
        for i in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[i] ^= 0x20;
            assert!(open(&mut &bad[..], &keys, &label, &mut Vec::new()).is_err(), "byte {i}");
        }
        // Under another file's name, or another passphrase: refused.
        let other = keys.sealed_name("meta/journal.2").unwrap();
        assert!(open(&mut &sealed[..], &keys, &other, &mut Vec::new()).is_err());
        let (stranger, _) = Keys::create("another passphrase!").unwrap();
        assert!(open(&mut &sealed[..], &stranger, &label, &mut Vec::new()).is_err());
        // Sealed names hide the path and are stable under one key.
        assert_eq!(label.len(), 64);
        assert!(!label.contains("journal"));
        assert_eq!(label, keys2.sealed_name("meta/journal.1").unwrap());
        assert_ne!(label, stranger.sealed_name("meta/journal.1").unwrap());
        // A standalone file carries its own parameters.
        let mut file = Vec::new();
        write_standalone_head(&mut file, &params).unwrap();
        file.extend(seal(&keys, STANDALONE_NAME, b"tar bytes"));
        let mut input = &file[..];
        let read = read_standalone_head(&mut input).unwrap();
        let k = Keys::open("correct horse battery", &read).unwrap();
        let mut out = Vec::new();
        let label = k.sealed_name(STANDALONE_NAME).unwrap();
        assert_eq!(open(&mut input, &k, &label, &mut out).unwrap(), STANDALONE_NAME);
        assert_eq!(out, b"tar bytes");
    }
}
