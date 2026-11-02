//! The client's configuration: `$XDG_CONFIG_HOME/homedrive/config.json`
//! (default `~/.config/homedrive/config.json`; on Windows
//! `%APPDATA%\homedrive\config.json`).
//!
//! ```json
//! {"server": "https://drive.example", "user": "alice",
//!  "ca_file": null,
//!  "folders": [{"local": "/home/alice/Drive", "remote": "", "ignore": ["*.tmp"]}]}
//! ```
//!
//! The device token is kept beside it in `token`, mode 0600, never in the
//! configuration. Each folder's sync state lives under
//! `$XDG_STATE_HOME/homedrive/<hash of the local path>/`.

use std::path::{Path, PathBuf};

use hd_api::{J, s};
use hd_common::{Error, Result, fsio};

use crate::engine::{Engine, Folder};
use crate::scan::SENTINEL;

const MAX_CONFIG: usize = 1024 * 1024;
/// ISRG Root X1 and X2, as Mozilla's root program distributes them.
const ISRG_ROOTS: &str = include_str!("isrg-roots.pem");

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FolderConfig {
    pub local: PathBuf,
    pub remote: String,
    pub ignore: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub server: String,
    pub user: String,
    pub ca_file: Option<PathBuf>,
    pub folders: Vec<FolderConfig>,
}

#[cfg(not(windows))]
fn env_dir(var: &str, fallback: &str) -> Result<PathBuf> {
    if let Some(v) = std::env::var_os(var).filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(v));
    }
    let home = std::env::var_os("HOME").ok_or_else(|| Error::new("HOME is not set"))?;
    Ok(PathBuf::from(home).join(fallback))
}

#[cfg(not(windows))]
pub fn config_dir() -> Result<PathBuf> {
    Ok(env_dir("XDG_CONFIG_HOME", ".config")?.join("homedrive"))
}

#[cfg(not(windows))]
pub fn state_root() -> Result<PathBuf> {
    Ok(env_dir("XDG_STATE_HOME", ".local/state")?.join("homedrive"))
}

#[cfg(windows)]
fn windows_dir(var: &str) -> Result<PathBuf> {
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| Error::new(format!("{var} is not set")))
}

#[cfg(windows)]
pub fn config_dir() -> Result<PathBuf> {
    Ok(windows_dir("APPDATA")?.join("homedrive"))
}

#[cfg(windows)]
pub fn state_root() -> Result<PathBuf> {
    Ok(windows_dir("LOCALAPPDATA")?.join("homedrive").join("state"))
}

impl Config {
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join("config.json");
        let text = fsio::read_bounded(&path, MAX_CONFIG)?.ok_or_else(|| {
            Error::new(format!(
                "no configuration at {}; run `homedrive login` first",
                path.display()
            ))
        })?;
        let v = hd_api::parse(&text)?;
        let mut folders = Vec::new();
        for f in hd_api::get_array(&v, "folders")? {
            let ignore = hd_api::get_array(f, "ignore")?
                .iter()
                .map(|p| {
                    p.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| Error::new("ignore patterns are strings"))
                })
                .collect::<Result<_>>()?;
            folders.push(FolderConfig {
                local: PathBuf::from(hd_api::get_str(f, "local")?),
                remote: hd_api::get_str(f, "remote")?,
                ignore,
            });
        }
        Ok(Self {
            server: hd_api::get_str(&v, "server")?,
            user: hd_api::get_str(&v, "user")?,
            ca_file: v.get("ca_file").and_then(|c| c.as_str()).map(PathBuf::from),
            folders,
        })
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        fsio::mkdir_durable(dir, 0o700)?;
        let folders = self
            .folders
            .iter()
            .map(|f| {
                J::O(vec![
                    ("local", s(f.local.to_string_lossy())),
                    ("remote", s(&*f.remote)),
                    ("ignore", J::A(f.ignore.iter().map(|p| s(&**p)).collect())),
                ])
            })
            .collect();
        let text = J::O(vec![
            ("server", s(&*self.server)),
            ("user", s(&*self.user)),
            ("ca_file", self.ca_file.as_ref().map_or(J::Null, |p| s(p.to_string_lossy()))),
            ("folders", J::A(folders)),
        ])
        .render();
        fsio::atomic_replace(dir.join("config.json"), text.as_bytes(), MAX_CONFIG)
    }

    /// Refuses folders inside one another: both would sync the inner one's
    /// files, from two places, and each one's trash and staging would look
    /// like changes to the other.
    pub fn check_folders(&self) -> Result<()> {
        for (i, a) in self.folders.iter().enumerate() {
            for b in &self.folders[i + 1..] {
                if a.local.starts_with(&b.local) || b.local.starts_with(&a.local) {
                    return Err(Error::new(format!(
                        "the synced folders {} and {} overlap; each folder may be synced only \
                         once, and not inside another",
                        a.local.display(),
                        b.local.display()
                    )));
                }
            }
        }
        Ok(())
    }

    /// The engine's view of a configured folder.
    pub fn folder(&self, f: &FolderConfig) -> Result<Folder> {
        let key = hd_crypto::sha256(f.local.as_os_str().as_encoded_bytes())
            .map_err(|_| Error::new("SHA-256 failed"))?;
        Ok(Folder {
            local: f.local.clone(),
            remote: f.remote.clone(),
            ignore: f.ignore.clone(),
            state_dir: state_root()?.join(&hd_crypto::hex(&key)[..16]),
        })
    }
}

/// Adds a folder to the configuration and marks it as synced, or restores
/// the marker of one already there. Returns whether it was already there.
/// The one way in for the `add-folder` command and the GUI, so both keep the
/// rules on overlapping folders.
pub fn add_folder(dir: &Path, local: &Path, remote: &str, ignore: Vec<String>) -> Result<bool> {
    hd_common::pathname::validate(remote)?;
    let mut cfg = Config::load(dir)?;
    if cfg.folders.iter().any(|f| f.local == local) {
        // Re-marking an existing folder (after its marker went missing).
        Engine::mark_root(local)
            .or_else(|e| if local.join(SENTINEL).exists() { Ok(()) } else { Err(e) })?;
        return Ok(true);
    }
    cfg.folders.push(FolderConfig { local: local.to_owned(), remote: remote.to_owned(), ignore });
    cfg.check_folders()?;
    if !local.join(SENTINEL).exists() {
        Engine::mark_root(local)?;
    }
    cfg.save(dir)?;
    Ok(false)
}

/// This computer's name, for naming the device.
pub fn device_name() -> String {
    let name = if cfg!(windows) {
        std::env::var("COMPUTERNAME").unwrap_or_default()
    } else {
        fsio::read_text("/etc/hostname", 256)
            .ok()
            .flatten()
            .map(|h| h.trim().to_owned())
            .unwrap_or_default()
    };
    if name.is_empty() { "computer".into() } else { name }
}

/// The user's home folder, where choosing a folder starts.
pub fn home_dir() -> PathBuf {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map_or_else(|| PathBuf::from("/"), PathBuf::from)
}

/// The disks to choose a folder from, where a system has several.
pub fn drive_roots() -> Vec<PathBuf> {
    if !cfg!(windows) {
        return Vec::new();
    }
    (b'C'..=b'Z')
        .map(|letter| PathBuf::from(format!("{}:\\", char::from(letter))))
        .filter(|root| root.is_dir())
        .collect()
}

/// Where a daemon with no console keeps its output, started afresh once it
/// has grown large.
#[cfg(windows)]
pub fn daemon_log() -> Result<PathBuf> {
    const MAX_LOG: u64 = 10 * 1024 * 1024;
    let dir = state_root()?;
    fsio::mkdir_durable(&dir, 0o700)?;
    let path = dir.join("daemon.log");
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > MAX_LOG) {
        crate::trash::remove_own_file(&path)?;
    }
    Ok(path)
}

/// The certificate authorities a server's certificate is checked against
/// when no `ca_file` is set. Linux has a system store. OpenSSL finds none on
/// Windows, so the Let's Encrypt roots are built in and written out for it.
pub fn default_ca_file() -> Result<Option<PathBuf>> {
    if !cfg!(windows) {
        return Ok(None);
    }
    let dir = config_dir()?;
    fsio::mkdir_durable(&dir, 0o700)?;
    let path = dir.join("isrg-roots.pem");
    fsio::atomic_replace(&path, ISRG_ROOTS.as_bytes(), ISRG_ROOTS.len())?;
    Ok(Some(path))
}

pub fn save_token(dir: &Path, token: &str) -> Result<()> {
    fsio::mkdir_durable(dir, 0o700)?;
    fsio::atomic_replace(dir.join("token"), token.as_bytes(), 4096)
}

/// Remembers which device this is, so signing out can revoke it.
pub fn save_device_id(dir: &Path, id: u64) -> Result<()> {
    fsio::atomic_replace(dir.join("device"), id.to_string().as_bytes(), 64)
}

pub fn load_device_id(dir: &Path) -> Option<u64> {
    fsio::read_text(dir.join("device"), 64).ok().flatten()?.trim().parse().ok()
}

/// Forgets the device token and which device this was.
pub fn clear_sign_in(dir: &Path) -> Result<()> {
    crate::trash::remove_own_file(&dir.join("token"))?;
    crate::trash::remove_own_file(&dir.join("device"))
}

pub fn load_token(dir: &Path) -> Result<String> {
    let t = fsio::read_text(dir.join("token"), 4096)?
        .ok_or_else(|| Error::new("no device token; run `homedrive login` first"))?;
    Ok(t.trim().to_owned())
}
