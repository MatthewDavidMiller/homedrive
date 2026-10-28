//! Runtime configuration, read once from the environment at startup. A value
//! that is set but invalid stops the server rather than being replaced by a
//! default.
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `HD_LISTEN` | `127.0.0.1:8080` | Address the HTTP listener binds |
//! | `HD_DATA_DIR` | `/var/lib/homedrive` | The store (back this up) |
//! | `HD_USERS_FILE` | `/run/secrets/homedrive_users` | The accounts, as JSON |
//! | `HD_TRUSTED_PROXIES` | unset | Comma-separated proxy IPs whose `X-Forwarded-For` is believed |
//! | `HD_SECURE_COOKIES` | `true` | `false` only for plain-HTTP development |
//! | `HD_MIN_FREE_GB` | `1` | Free space below which the store refuses writes, 0-100000 |
//! | `HD_MAX_FILE_GB` | `1024` | The largest file accepted, 1-100000 |
//! | `HD_KEEP_ALL_DAYS` | `30` | Keep every old version this long, 0-36500 |
//! | `HD_TRASH_DAYS` | `90` | Keep deleted files this long, 1-36500 |
//! | `HD_MAINTENANCE_HOURS` | `24` | Retention and GC run this often; `0` turns them off |
//! | `HD_SCRUB_DAYS` | `30` | Re-verify every object this often; `0` turns scrubbing off |
//! | `HD_SCRUB_MBPS` | `50` | Scrub read rate ceiling, MB/s |

use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use hd_common::{Error, Result};

const DAY_MS: i64 = 86_400_000;

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    pub users_file: PathBuf,
    pub trusted_proxies: Vec<IpAddr>,
    pub secure_cookies: bool,
    /// Bytes.
    pub min_free: u64,
    /// Bytes.
    pub max_file: u64,
    pub retention: hd_store::retention::Policy,
    pub maintenance_every: Option<Duration>,
    pub scrub_every: Option<Duration>,
    pub scrub_bytes_per_sec: u64,
}

impl Config {
    /// Settings for tests and development: loopback, no maintenance.
    pub fn for_test(data_dir: PathBuf, users_file: PathBuf) -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            data_dir,
            users_file,
            trusted_proxies: Vec::new(),
            secure_cookies: false,
            min_free: 0,
            max_file: 1 << 40,
            retention: hd_store::retention::Policy::default(),
            maintenance_every: None,
            scrub_every: None,
            scrub_bytes_per_sec: 0,
        }
    }
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

fn flag(name: &str, default: bool) -> Result<bool> {
    match var(name).as_deref() {
        None => Ok(default),
        Some("true" | "1") => Ok(true),
        Some("false" | "0") => Ok(false),
        Some(_) => Err(Error::new(format!("{name} must be true or false"))),
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

fn days_ms(days: u64) -> i64 {
    i64::try_from(days).unwrap_or(i64::MAX).saturating_mul(DAY_MS)
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let listen = var("HD_LISTEN")
            .unwrap_or_else(|| "127.0.0.1:8080".to_owned())
            .parse()
            .map_err(|_| Error::new("HD_LISTEN must be an address such as 0.0.0.0:8080"))?;
        let trusted_proxies = match var("HD_TRUSTED_PROXIES") {
            None => Vec::new(),
            Some(list) => list
                .split(',')
                .map(|ip| ip.trim().parse())
                .collect::<std::result::Result<_, _>>()
                .map_err(|_| Error::new("HD_TRUSTED_PROXIES must list IP addresses"))?,
        };
        let keep_all = number("HD_KEEP_ALL_DAYS", 30, 0, 36_500)?;
        let defaults = hd_store::retention::Policy::default();
        let retention = hd_store::retention::Policy {
            keep_all_ms: days_ms(keep_all),
            daily_until_ms: defaults.daily_until_ms.max(days_ms(keep_all)),
            weekly_until_ms: defaults.weekly_until_ms.max(days_ms(keep_all)),
            trash_ms: days_ms(number("HD_TRASH_DAYS", 90, 1, 36_500)?),
        };
        let hours = number("HD_MAINTENANCE_HOURS", 24, 0, 24 * 365)?;
        let scrub_days = number("HD_SCRUB_DAYS", 30, 0, 3650)?;
        Ok(Self {
            listen,
            data_dir: path("HD_DATA_DIR", "/var/lib/homedrive")?,
            users_file: path("HD_USERS_FILE", "/run/secrets/homedrive_users")?,
            trusted_proxies,
            secure_cookies: flag("HD_SECURE_COOKIES", true)?,
            min_free: number("HD_MIN_FREE_GB", 1, 0, 100_000)? << 30,
            max_file: number("HD_MAX_FILE_GB", 1024, 1, 100_000)? << 30,
            retention,
            maintenance_every: (hours > 0).then(|| Duration::from_secs(hours * 3600)),
            scrub_every: (scrub_days > 0).then(|| Duration::from_secs(scrub_days * 86_400)),
            scrub_bytes_per_sec: number("HD_SCRUB_MBPS", 50, 1, 100_000)? * 1_000_000,
        })
    }
}
