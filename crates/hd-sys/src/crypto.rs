//! OpenSSL 3 libcrypto declarations and their safe wrappers: SHA-256 (one
//! shot and streaming), HMAC, the CSPRNG, constant-time comparison, and
//! cleansing.
//!
//! SHA-256 is the store's content address: every chunk, manifest, and
//! whole file is named and verified by it, so the streaming digest here is
//! on the path of every byte the server stores or serves.
//!
//! Every type is opaque: this crate only holds OpenSSL objects by pointer.

use std::ffi::{c_int, c_uint, c_void};

opaque!(EVP_MD, EVP_MD_CTX, ENGINE);

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

    fn RAND_bytes(buf: *mut u8, num: c_int) -> c_int;
    fn CRYPTO_memcmp(a: *const c_void, b: *const c_void, len: usize) -> c_int;
    fn OPENSSL_cleanse(ptr: *mut c_void, len: usize);
}

/// Safe wrappers over the declarations above. Each checks the lengths
/// OpenSSL's `int` parameters can carry and reports failure as `None` or
/// `false`; nothing here aborts.
pub mod safe {
    use super::{
        CRYPTO_memcmp, EVP_Digest, EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate,
        EVP_MD_CTX, EVP_MD_CTX_free, EVP_MD_CTX_new, EVP_sha256, HMAC, OPENSSL_cleanse, RAND_bytes,
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

    /// Overwrites `buf` with zeroes in a way the optimiser cannot remove.
    pub fn cleanse(buf: &mut [u8]) {
        if !buf.is_empty() {
            // SAFETY: `buf` is writable for its length.
            unsafe { OPENSSL_cleanse(buf.as_mut_ptr().cast(), buf.len()) }
        }
    }
}
