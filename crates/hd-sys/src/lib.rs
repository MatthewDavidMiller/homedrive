//! Hand-written foreign declarations: OpenSSL's libcrypto and the few C
//! library calls the standard library does not wrap.
//!
//! This is the only crate allowed `unsafe`. Code outside it calls the safe
//! wrappers, never the raw items.

#![allow(non_camel_case_types, non_snake_case)]
// Converting between Rust sizes and the C ABI's `int` fields is this crate's
// job; every such conversion is of a small constant or a checked length.
#![allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]

/// Declares types C code only ever hands out by pointer: zero-sized,
/// unconstructible, and neither `Send`, `Sync`, nor `Unpin`.
macro_rules! opaque {
    ($($name:ident),* $(,)?) => {$(
        #[repr(C)]
        #[derive(Debug)]
        pub struct $name {
            _data: [u8; 0],
            _marker: std::marker::PhantomData<(*mut u8, std::marker::PhantomPinned)>,
        }
    )*};
}

pub mod crypto;
#[cfg(unix)]
pub mod posix;
#[cfg(feature = "tls")]
pub mod ssl;
pub mod watch;
#[cfg(windows)]
pub mod windows;
