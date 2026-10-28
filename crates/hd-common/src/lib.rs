//! Helpers every crate shares: errors, bounded buffers and wiping, bounded
//! file IO and atomic writes, strict JSON, operating-system randomness, and
//! UTC calendar arithmetic.
//!
//! Every reader here takes an explicit ceiling. Unbounded input handling is a
//! defect in this project even where growth looks impossible.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::disallowed_methods))]

pub mod base64;
pub mod buf;
pub mod error;
pub mod fsio;
pub mod json;
pub mod rand;
pub mod timefmt;

pub use error::{Error, Result};

/// The build's version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
