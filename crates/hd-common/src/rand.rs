//! Operating-system randomness from getrandom(2). There is no fallback; a
//! failure is reported, never papered over.

use crate::Result;

/// Fills `out` with fresh randomness.
pub fn fill(out: &mut [u8]) -> Result<()> {
    #[cfg(unix)]
    hd_sys::posix::fill_random(out)?;
    #[cfg(not(unix))]
    if !hd_sys::crypto::safe::random_bytes(out) {
        return Err(crate::Error::new("the system's randomness is unavailable"));
    }
    Ok(())
}

/// `bytes` random bytes as `2 * bytes` lowercase hex characters.
pub fn random_hex(bytes: usize) -> Result<String> {
    let mut raw = vec![0_u8; bytes];
    fill(&mut raw)?;
    let text = crate::buf::hex(&raw);
    crate::buf::wipe_vec(&mut raw);
    Ok(text)
}

/// A random array.
pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0_u8; N];
    fill(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn hex_has_the_requested_width_and_varies() {
        let a = super::random_hex(16).unwrap();
        let b = super::random_hex(16).unwrap();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
