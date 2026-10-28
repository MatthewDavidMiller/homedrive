//! The client's configuration: `$XDG_CONFIG_HOME/homedrive/config.json`
//! (default `~/.config/homedrive/config.json`).
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

use crate::engine::Folder;

const MAX_CONFIG: usize = 1024 * 1024;

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

fn env_dir(var: &str, fallback: &str) -> Result<PathBuf> {
    if let Some(v) = std::env::var_os(var).filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(v));
    }
    let home = std::env::var_os("HOME").ok_or_else(|| Error::new("HOME is not set"))?;
    Ok(PathBuf::from(home).join(fallback))
}

pub fn config_dir() -> Result<PathBuf> {
    Ok(env_dir("XDG_CONFIG_HOME", ".config")?.join("homedrive"))
}

pub fn state_root() -> Result<PathBuf> {
    Ok(env_dir("XDG_STATE_HOME", ".local/state")?.join("homedrive"))
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

pub fn save_token(dir: &Path, token: &str) -> Result<()> {
    fsio::mkdir_durable(dir, 0o700)?;
    fsio::atomic_replace(dir.join("token"), token.as_bytes(), 4096)
}

pub fn load_token(dir: &Path) -> Result<String> {
    let t = fsio::read_text(dir.join("token"), 4096)?
        .ok_or_else(|| Error::new("no device token; run `homedrive login` first"))?;
    Ok(t.trim().to_owned())
}
