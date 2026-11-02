//! OpenSSL 3 libcrypto declarations and their safe wrappers: SHA-256 (one
//! shot and streaming), HMAC, the CSPRNG, constant-time comparison,
//! cleansing, and for encrypted copies of the store, scrypt and
//! AES-256-GCM.
//!
//! SHA-256 is the store's content address: every chunk, manifest, and
//! whole file is named and verified by it, so the streaming digest here is
//! on the path of every byte the server stores or serves.
//!
//! Every type is opaque: this crate only holds OpenSSL objects by pointer.

use std::ffi::{c_int, c_uint, c_void};

opaque!(EVP_MD, EVP_MD_CTX, ENGINE, EVP_CIPHER, EVP_CIPHER_CTX);

const EVP_CTRL_GCM_GET_TAG: c_int = 0x10;
const EVP_CTRL_GCM_SET_TAG: c_int = 0x11;

unsafe extern "C" {
    fn EVP_sha256() -> *const EVP_MD;
    fn EVP_Digest(
        data: *const c_void,
        count: usize,
        md: *mut u8,
        size: *mut c_uint,
        kind: *const EVP_MD,
        engine: *mut ENGINE,
    ) -> c_int;
    fn EVP_MD_CTX_new() -> *mut EVP_MD_CTX;
    fn EVP_MD_CTX_free(ctx: *mut EVP_MD_CTX);
    fn EVP_DigestInit_ex(ctx: *mut EVP_MD_CTX, kind: *const EVP_MD, engine: *mut ENGINE) -> c_int;
    fn EVP_DigestUpdate(ctx: *mut EVP_MD_CTX, data: *const c_void, count: usize) -> c_int;
    fn EVP_DigestFinal_ex(ctx: *mut EVP_MD_CTX, md: *mut u8, size: *mut c_uint) -> c_int;
    fn HMAC(
        md: *const EVP_MD,
        key: *const c_void,
        key_len: c_int,
        data: *const u8,
        data_len: usize,
        out: *mut u8,
        out_len: *mut c_uint,
    ) -> *mut u8;

    fn EVP_PBE_scrypt(
        pass: *const u8,
        pass_len: usize,
        salt: *const u8,
        salt_len: usize,
        n: u64,
        r: u64,
        p: u64,
        max_mem: u64,
        key: *mut u8,
        key_len: usize,
    ) -> c_int;
    fn EVP_aes_256_gcm() -> *const EVP_CIPHER;
    fn EVP_CIPHER_CTX_new() -> *mut EVP_CIPHER_CTX;
    fn EVP_CIPHER_CTX_free(ctx: *mut EVP_CIPHER_CTX);
    fn EVP_CIPHER_CTX_ctrl(
        ctx: *mut EVP_CIPHER_CTX,
        kind: c_int,
        arg: c_int,
        ptr: *mut c_void,
    ) -> c_int;
    fn EVP_EncryptInit_ex(
        ctx: *mut EVP_CIPHER_CTX,
        cipher: *const EVP_CIPHER,
        engine: *mut ENGINE,
        key: *const u8,
        iv: *const u8,
    ) -> c_int;
    fn EVP_EncryptUpdate(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut u8,
        out_len: *mut c_int,
        input: *const u8,
        in_len: c_int,
    ) -> c_int;
    fn EVP_EncryptFinal_ex(ctx: *mut EVP_CIPHER_CTX, out: *mut u8, out_len: *mut c_int) -> c_int;
    fn EVP_DecryptInit_ex(
        ctx: *mut EVP_CIPHER_CTX,
        cipher: *const EVP_CIPHER,
        engine: *mut ENGINE,
        key: *const u8,
        iv: *const u8,
    ) -> c_int;
    fn EVP_DecryptUpdate(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut u8,
        out_len: *mut c_int,
        input: *const u8,
        in_len: c_int,
    ) -> c_int;
    fn EVP_DecryptFinal_ex(ctx: *mut EVP_CIPHER_CTX, out: *mut u8, out_len: *mut c_int) -> c_int;

    fn RAND_bytes(buf: *mut u8, num: c_int) -> c_int;
    fn CRYPTO_memcmp(a: *const c_void, b: *const c_void, len: usize) -> c_int;
    fn OPENSSL_cleanse(ptr: *mut c_void, len: usize);
}

/// Safe wrappers over the declarations above. Each checks the lengths
/// OpenSSL's `int` parameters can carry and reports failure as `None` or
/// `false`; nothing here aborts.
pub mod safe {
    use super::{
        CRYPTO_memcmp, EVP_CIPHER_CTX, EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_free,
        EVP_CIPHER_CTX_new, EVP_CTRL_GCM_GET_TAG, EVP_CTRL_GCM_SET_TAG, EVP_DecryptFinal_ex,
        EVP_DecryptInit_ex, EVP_DecryptUpdate, EVP_Digest, EVP_DigestFinal_ex, EVP_DigestInit_ex,
        EVP_DigestUpdate, EVP_EncryptFinal_ex, EVP_EncryptInit_ex, EVP_EncryptUpdate, EVP_MD_CTX,
        EVP_MD_CTX_free, EVP_MD_CTX_new, EVP_PBE_scrypt, EVP_aes_256_gcm, EVP_sha256, HMAC,
        OPENSSL_cleanse, RAND_bytes,
    };
    use std::ffi::{c_int, c_uint};
    use std::ptr::{self, NonNull};

    pub const SHA256_LEN: usize = 32;

    fn c_len(len: usize) -> Option<c_int> {
        c_int::try_from(len).ok()
    }

    fn md_sha256() -> *const super::EVP_MD {
        // SAFETY: the getter takes no arguments and returns a static object.
        unsafe { EVP_sha256() }
    }

    pub fn sha256(data: &[u8]) -> Option<[u8; SHA256_LEN]> {
        let md = md_sha256();
        if md.is_null() {
            return None;
        }
        let mut out = [0_u8; SHA256_LEN];
        let mut n: c_uint = 0;
        // SAFETY: `data` is readable for its length; `out` holds a SHA-256
        // digest.
        let ok = unsafe {
            EVP_Digest(
                data.as_ptr().cast(),
                data.len(),
                out.as_mut_ptr(),
                &raw mut n,
                md,
                ptr::null_mut(),
            )
        };
        (ok == 1 && n as usize == SHA256_LEN).then_some(out)
    }

    /// A SHA-256 computation fed in pieces. A failed update poisons it, so
    /// `finish` then reports failure rather than a digest of part of the
    /// input.
    #[derive(Debug)]
    pub struct Sha256 {
        ctx: NonNull<EVP_MD_CTX>,
        failed: bool,
    }

    // SAFETY: the context is owned exclusively by this value, and OpenSSL
    // digest contexts carry no thread affinity; moving one between threads
    // is allowed as long as it is never used from two at once, which `&mut`
    // guarantees.
    unsafe impl Send for Sha256 {}

    impl Drop for Sha256 {
        fn drop(&mut self) {
            // SAFETY: created by EVP_MD_CTX_new and freed once.
            unsafe { EVP_MD_CTX_free(self.ctx.as_ptr()) };
        }
    }

    impl Sha256 {
        pub fn new() -> Option<Self> {
            // SAFETY: no preconditions.
            let ctx = NonNull::new(unsafe { EVP_MD_CTX_new() })?;
            let this = Self { ctx, failed: false };
            let md = md_sha256();
            if md.is_null() {
                return None;
            }
            // SAFETY: the context is live and `md` is a static digest.
            let ok = unsafe { EVP_DigestInit_ex(this.ctx.as_ptr(), md, ptr::null_mut()) };
            (ok == 1).then_some(this)
        }

        pub fn update(&mut self, data: &[u8]) {
            if self.failed || data.is_empty() {
                return;
            }
            // SAFETY: the context is live and initialised; `data` is readable
            // for its length.
            let ok =
                unsafe { EVP_DigestUpdate(self.ctx.as_ptr(), data.as_ptr().cast(), data.len()) };
            if ok != 1 {
                self.failed = true;
            }
        }

        pub fn finish(self) -> Option<[u8; SHA256_LEN]> {
            if self.failed {
                return None;
            }
            let mut out = [0_u8; SHA256_LEN];
            let mut n: c_uint = 0;
            // SAFETY: the context is live and initialised; `out` holds a
            // SHA-256 digest.
            let ok = unsafe { EVP_DigestFinal_ex(self.ctx.as_ptr(), out.as_mut_ptr(), &raw mut n) };
            (ok == 1 && n as usize == SHA256_LEN).then_some(out)
        }
    }

    pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Option<[u8; SHA256_LEN]> {
        let key_len = c_len(key.len())?;
        let mut out = [0_u8; SHA256_LEN];
        let mut n: c_uint = 0;
        // SAFETY: key and data are readable for their lengths; `out` holds a
        // SHA-256 digest.
        let ret = unsafe {
            HMAC(
                md_sha256(),
                key.as_ptr().cast(),
                key_len,
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
                &raw mut n,
            )
        };
        (!ret.is_null() && n as usize == SHA256_LEN).then_some(out)
    }

    /// Fills `buf` from OpenSSL's CSPRNG.
    pub fn random_bytes(buf: &mut [u8]) -> bool {
        let Some(n) = c_len(buf.len()) else { return false };
        // SAFETY: `buf` is writable for `n` bytes.
        unsafe { RAND_bytes(buf.as_mut_ptr(), n) == 1 }
    }

    /// Constant-time equality of two slices; slices of different lengths are
    /// unequal (the length itself is not secret).
    pub fn ct_equal(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        if a.is_empty() {
            return true;
        }
        // SAFETY: both slices are readable for `a.len()` bytes.
        unsafe { CRYPTO_memcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) == 0 }
    }

    pub const GCM_KEY_LEN: usize = 32;
    pub const GCM_NONCE_LEN: usize = 12;
    pub const GCM_TAG_LEN: usize = 16;

    /// scrypt: fills `out` with a key derived from `pass` and `salt`, with
    /// cost `n` (a power of two), block size `r` and parallelism `p`, using
    /// at most `max_mem` bytes.
    pub fn scrypt(
        pass: &[u8],
        salt: &[u8],
        n: u64,
        r: u64,
        p: u64,
        max_mem: u64,
        out: &mut [u8],
    ) -> bool {
        // SAFETY: the inputs are readable and `out` writable for their
        // lengths; OpenSSL checks the parameters.
        unsafe {
            EVP_PBE_scrypt(
                pass.as_ptr(),
                pass.len(),
                salt.as_ptr(),
                salt.len(),
                n,
                r,
                p,
                max_mem,
                out.as_mut_ptr(),
                out.len(),
            ) == 1
        }
    }

    /// A cipher context, freed when dropped.
    struct CipherCtx(NonNull<EVP_CIPHER_CTX>);

    impl Drop for CipherCtx {
        fn drop(&mut self) {
            // SAFETY: created by EVP_CIPHER_CTX_new and freed once; freeing
            // also clears the key schedule.
            unsafe { EVP_CIPHER_CTX_free(self.0.as_ptr()) };
        }
    }

    impl CipherCtx {
        fn new() -> Option<Self> {
            // SAFETY: no preconditions.
            NonNull::new(unsafe { EVP_CIPHER_CTX_new() }).map(Self)
        }
    }

    fn gcm() -> *const super::EVP_CIPHER {
        // SAFETY: the getter takes no arguments and returns a static object.
        unsafe { EVP_aes_256_gcm() }
    }

    /// AES-256-GCM: appends `plain` encrypted, then its 16-byte tag, to
    /// `out`. `aad` is authenticated but not encrypted.
    pub fn gcm_seal(
        key: &[u8; GCM_KEY_LEN],
        nonce: &[u8; GCM_NONCE_LEN],
        aad: &[u8],
        plain: &[u8],
        out: &mut Vec<u8>,
    ) -> bool {
        let start = out.len();
        let ok = seal_into(key, nonce, aad, plain, out, start);
        if !ok {
            out.truncate(start);
        }
        ok
    }

    fn seal_into(
        key: &[u8; GCM_KEY_LEN],
        nonce: &[u8; GCM_NONCE_LEN],
        aad: &[u8],
        plain: &[u8],
        out: &mut Vec<u8>,
        start: usize,
    ) -> bool {
        let (Some(aad_len), Some(plain_len)) = (c_len(aad.len()), c_len(plain.len())) else {
            return false;
        };
        let Some(ctx) = CipherCtx::new() else { return false };
        let c = ctx.0.as_ptr();
        let cipher = gcm();
        if cipher.is_null() {
            return false;
        }
        out.resize(start + plain.len() + GCM_TAG_LEN, 0);
        let mut n: c_int = 0;
        // SAFETY: the context is live; the key and nonce have the lengths
        // AES-256-GCM takes (its default nonce is 12 bytes).
        if unsafe { EVP_EncryptInit_ex(c, cipher, ptr::null_mut(), key.as_ptr(), nonce.as_ptr()) }
            != 1
        {
            return false;
        }
        if !aad.is_empty() {
            // SAFETY: `aad` is readable for its length; a null output feeds
            // it as additional data.
            let fed =
                unsafe { EVP_EncryptUpdate(c, ptr::null_mut(), &raw mut n, aad.as_ptr(), aad_len) };
            if fed != 1 {
                return false;
            }
        }
        let body = out[start..].as_mut_ptr();
        // SAFETY: `body` has room for the ciphertext, which GCM makes as
        // long as the input.
        if unsafe { EVP_EncryptUpdate(c, body, &raw mut n, plain.as_ptr(), plain_len) } != 1
            || n != plain_len
        {
            return false;
        }
        let tail = out[start + plain.len()..].as_mut_ptr();
        // SAFETY: GCM writes nothing at the end; `tail` has room regardless.
        if unsafe { EVP_EncryptFinal_ex(c, tail, &raw mut n) } != 1 || n != 0 {
            return false;
        }
        // SAFETY: `tail` holds the 16-byte tag.
        let got = unsafe {
            EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN as c_int, tail.cast())
        };
        got == 1
    }

    /// AES-256-GCM: checks `sealed` (ciphertext, then tag) against `aad`
    /// and appends the plaintext to `out`. `false`, with nothing appended,
    /// for anything altered, a wrong key, or the wrong `aad`.
    pub fn gcm_open(
        key: &[u8; GCM_KEY_LEN],
        nonce: &[u8; GCM_NONCE_LEN],
        aad: &[u8],
        sealed: &[u8],
        out: &mut Vec<u8>,
    ) -> bool {
        let start = out.len();
        let ok = open_into(key, nonce, aad, sealed, out, start);
        if ok {
            out.truncate(start + sealed.len() - GCM_TAG_LEN);
        } else {
            if out.len() > start {
                cleanse(&mut out[start..]);
            }
            out.truncate(start);
        }
        ok
    }

    fn open_into(
        key: &[u8; GCM_KEY_LEN],
        nonce: &[u8; GCM_NONCE_LEN],
        aad: &[u8],
        sealed: &[u8],
        out: &mut Vec<u8>,
        start: usize,
    ) -> bool {
        if sealed.len() < GCM_TAG_LEN {
            return false;
        }
        let (body, tag) = sealed.split_at(sealed.len() - GCM_TAG_LEN);
        let (Some(aad_len), Some(body_len)) = (c_len(aad.len()), c_len(body.len())) else {
            return false;
        };
        let Some(ctx) = CipherCtx::new() else { return false };
        let c = ctx.0.as_ptr();
        let cipher = gcm();
        if cipher.is_null() {
            return false;
        }
        out.resize(start + body.len() + GCM_TAG_LEN, 0);
        let mut tag = <[u8; GCM_TAG_LEN]>::try_from(tag).unwrap_or([0; GCM_TAG_LEN]);
        let mut n: c_int = 0;
        // SAFETY: as in `seal_into`.
        if unsafe { EVP_DecryptInit_ex(c, cipher, ptr::null_mut(), key.as_ptr(), nonce.as_ptr()) }
            != 1
        {
            return false;
        }
        if !aad.is_empty() {
            // SAFETY: `aad` is readable for its length; a null output feeds
            // it as additional data.
            let fed =
                unsafe { EVP_DecryptUpdate(c, ptr::null_mut(), &raw mut n, aad.as_ptr(), aad_len) };
            if fed != 1 {
                return false;
            }
        }
        let plain = out[start..].as_mut_ptr();
        // SAFETY: `plain` has room for the plaintext, as long as the body.
        if unsafe { EVP_DecryptUpdate(c, plain, &raw mut n, body.as_ptr(), body_len) } != 1
            || n != body_len
        {
            return false;
        }
        let tag_ptr = tag.as_mut_ptr().cast();
        // SAFETY: the tag buffer is the 16 bytes the call reads.
        let set =
            unsafe { EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN as c_int, tag_ptr) };
        if set != 1 {
            return false;
        }
        let tail = out[start + body.len()..].as_mut_ptr();
        // SAFETY: GCM writes nothing at the end; the call checks the tag.
        unsafe { EVP_DecryptFinal_ex(c, tail, &raw mut n) == 1 }
    }

    /// Overwrites `buf` with zeroes in a way the optimiser cannot remove.
    pub fn cleanse(buf: &mut [u8]) {
        if !buf.is_empty() {
            // SAFETY: `buf` is writable for its length.
            unsafe { OPENSSL_cleanse(buf.as_mut_ptr().cast(), buf.len()) }
        }
    }
}
