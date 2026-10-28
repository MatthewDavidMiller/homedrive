//! The cryptographic primitives homedrive uses, all from OpenSSL's libcrypto.
//! Nothing here implements a primitive; it only adapts libcrypto to safe Rust.
//! HKDF is the RFC 5869 construction over libcrypto's HMAC, not a primitive
//! of its own.

#![forbid(unsafe_code)]

use std::fmt;

use hd_sys::crypto::safe;

pub use safe::SHA256_LEN;

/// libcrypto reported a failure, or an input was out of range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CryptoError;

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cryptographic operation failed")
    }
}

impl std::error::Error for CryptoError {}

pub type Result<T> = std::result::Result<T, CryptoError>;

pub fn sha256(data: &[u8]) -> Result<[u8; SHA256_LEN]> {
    safe::sha256(data).ok_or(CryptoError)
}

/// SHA-256 over input that arrives in pieces: a file being read, a request
/// body being received, a chunk sequence being reassembled.
#[derive(Debug)]
pub struct Sha256 {
    inner: safe::Sha256,
    len: u64,
}

impl Sha256 {
    pub fn new() -> Result<Self> {
        Ok(Self { inner: safe::Sha256::new().ok_or(CryptoError)?, len: 0 })
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
        self.len = self.len.saturating_add(data.len() as u64);
    }

    /// How many bytes have been fed in.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn finish(self) -> Result<[u8; SHA256_LEN]> {
        self.inner.finish().ok_or(CryptoError)
    }
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; SHA256_LEN]> {
    safe::hmac_sha256(key, data).ok_or(CryptoError)
}

/// HKDF-SHA256 (RFC 5869): extract with `salt`, then expand to fill `out`,
/// which may be at most 255 hash lengths.
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    if out.len() > 255 * SHA256_LEN {
        return Err(CryptoError);
    }
    let zero_salt = [0_u8; SHA256_LEN];
    let mut prk = hmac_sha256(if salt.is_empty() { &zero_salt } else { salt }, ikm)?;
    let mut block = [0_u8; SHA256_LEN];
    let mut input = Vec::with_capacity(SHA256_LEN + info.len() + 1);
    let mut result = Ok(());
    for (i, chunk) in out.chunks_mut(SHA256_LEN).enumerate() {
        input.clear();
        if i > 0 {
            input.extend_from_slice(&block);
        }
        input.extend_from_slice(info);
        // At most 255 blocks, checked above.
        input.push(u8::try_from(i + 1).unwrap_or(u8::MAX));
        match hmac_sha256(&prk, &input) {
            Ok(b) => block = b,
            Err(e) => {
                result = Err(e);
                break;
            }
        }
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
    cleanse(&mut prk);
    cleanse(&mut block);
    cleanse(&mut input);
    if result.is_err() {
        cleanse(out);
    }
    result
}

/// Fills `out` from libcrypto's CSPRNG.
pub fn random_bytes(out: &mut [u8]) -> Result<()> {
    safe::random_bytes(out).then_some(()).ok_or(CryptoError)
}

pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0_u8; N];
    random_bytes(&mut out)?;
    Ok(out)
}

/// Constant-time equality; different lengths compare unequal.
pub fn ct_equal(a: &[u8], b: &[u8]) -> bool {
    safe::ct_equal(a, b)
}

/// Zeroes `buf` in a way the optimiser cannot remove.
pub fn cleanse(buf: &mut [u8]) {
    safe::cleanse(buf);
}

/// Bytes that are cleansed when dropped. Debug output never shows them.
#[derive(Default)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        // Cleanse the whole allocation, spare capacity included.
        let cap = self.0.capacity();
        self.0.resize(cap, 0);
        cleanse(&mut self.0);
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes({} bytes)", self.0.len())
    }
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 15)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn sha256_fips_180_vectors() {
        assert_eq!(
            hex(&sha256(b"abc").unwrap()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(b"").unwrap()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn streaming_sha256_matches_one_shot_for_every_split() {
        let data: Vec<u8> = (0..=255_u8).cycle().take(5000).collect();
        let whole = sha256(&data).unwrap();
        for split in [0, 1, 63, 64, 65, 2500, 4999, 5000] {
            let mut h = Sha256::new().unwrap();
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.len(), 5000);
            assert_eq!(h.finish().unwrap(), whole, "split at {split}");
        }
        // One million 'a's: the FIPS 180-2 long-message vector, fed in pieces.
        let mut h = Sha256::new().unwrap();
        let block = [b'a'; 1000];
        for _ in 0..1000 {
            h.update(&block);
        }
        assert_eq!(
            hex(&h.finish().unwrap()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
        assert!(Sha256::new().unwrap().is_empty());
    }

    #[test]
    fn hmac_rfc_4231_case_2() {
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?").unwrap()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hkdf_rfc_5869_case_1() {
        let mut okm = [0_u8; 42];
        hkdf_sha256(
            &[0x0b; 22],
            &unhex("000102030405060708090a0b0c"),
            &unhex("f0f1f2f3f4f5f6f7f8f9"),
            &mut okm,
        )
        .unwrap();
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn hkdf_refuses_oversized_output() {
        let mut okm = vec![0_u8; 255 * 32 + 1];
        assert!(hkdf_sha256(b"k", b"", b"", &mut okm).is_err());
    }

    #[test]
    fn constant_time_compare() {
        assert!(ct_equal(b"abc", b"abc"));
        assert!(!ct_equal(b"abc", b"abd"));
        assert!(!ct_equal(b"abc", b"ab"));
        assert!(ct_equal(b"", b""));
    }

    #[test]
    fn randomness_varies() {
        assert_ne!(random_array::<32>().unwrap(), random_array::<32>().unwrap());
    }

    #[test]
    fn secret_debug_hides_contents() {
        assert_eq!(format!("{:?}", SecretBytes::new(b"hunter2".to_vec())), "SecretBytes(7 bytes)");
    }
}
