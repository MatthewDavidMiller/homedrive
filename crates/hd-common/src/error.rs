//! The project's error: one human-readable message.
//!
//! Failures here are reported to an operator, never matched on, so a
//! message is all an error carries. An operating-system error displays the
//! way `std::io::Error` does -- "<description> (os error <n>)" -- which is
//! the text the status files and the Web frontend have always shown.

use std::fmt;
use std::io;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(String);

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    /// The message for a raw operating-system error number.
    pub fn os(code: i32) -> Self {
        Self(io::Error::from_raw_os_error(code).to_string())
    }

    pub fn message(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self(err.to_string())
    }
}
