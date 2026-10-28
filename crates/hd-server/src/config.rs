//! Runtime configuration, read once from the environment at startup. A value
//! that is set but invalid stops the server rather than being replaced by a
//! default.
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `HD_LISTEN` | `127.0.0.1:8080` | Address the HTTP listener binds |
//! | `HD_DATA_DIR` | `/var/lib/homedrive` | The store: chunks, manifests, and the metadata journal (back this up) |
//! | `HD_MIN_FREE_GB` | `1` | Free space below which the store refuses writes, 0-100000 |
//!
//! The rest of the table in docs/PLAN.md arrives with the milestones that
//! use each variable.

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

use hd_common::{Error, Result};

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    /// Bytes.
    pub min_free: u64,
}

fn var(name: &str) -> Option<String> {
    env::var(name).ok().map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
}

fn number(name: &str, default: u64, min: u64, max: u64) -> Result<u64> {
    match var(name) {
        None => Ok(default),
        Some(v) => {
            hd_common::buf::parse_u64(v.as_bytes(), max).filter(|&n| n >= min).ok_or_else(|| {
                Error::new(format!("{name} must be a whole number from {min} to {max}"))
            })
        }
    }
}

fn path(name: &str, default: &str) -> Result<PathBuf> {
    let p = PathBuf::from(var(name).unwrap_or_else(|| default.to_owned()));
    if p.is_absolute() {
        Ok(p)
    } else {
        Err(Error::new(format!("{name} must be an absolute path")))
    }
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let listen = var("HD_LISTEN")
            .unwrap_or_else(|| "127.0.0.1:8080".to_owned())
            .parse()
            .map_err(|_| Error::new("HD_LISTEN must be an address such as 0.0.0.0:8080"))?;
        Ok(Self {
            listen,
            data_dir: path("HD_DATA_DIR", "/var/lib/homedrive")?,
            min_free: number("HD_MIN_FREE_GB", 1, 0, 100_000)? * 1024 * 1024 * 1024,
        })
    }
}
