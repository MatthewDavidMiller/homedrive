//! Exports: plain-file copies of parts of a drive, for programs that read
//! files rather than speak to homedrive (music-server reads a Music
//! export).
//!
//! `HD_EXPORTS=alice:Music=>music` keeps `HD_EXPORT_DIR/music/` equal to
//! the current versions under alice's `Music`. The worker reconciles at
//! start and after every commit:
//! - a changed file is written beside its target from the verified store
//!   content, fsynced, and renamed into place;
//! - a removed file is removed;
//! - files the export did not write are never touched. Before replacing or
//!   removing a file, the export checks that it still holds exactly the
//!   content the export wrote there. A file someone else put or changed in
//!   the export is left alone and reported. A file already holding the
//!   wanted content is adopted, which also recovers from a lost record.
//!
//! What the export holds is recorded in `HD_EXPORT_DIR/.homedrive-<name>`,
//! one "version sha256 path" line per file, so an unchanged file is not
//! rewritten after a restart. An export is a derived view: deleting it
//! entirely loses nothing, and the next reconcile rebuilds it.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use hd_common::{Error, Result, fsio, pathname};
use hd_store::model::Node;

use crate::App;

const STAGING_PREFIX: &str = ".homedrive-tmp-";
const MAX_RECORD: usize = 256 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Export {
    pub user: String,
    /// The folder in the user's drive ("" for all of it).
    pub path: String,
    /// The directory name under the export directory.
    pub name: String,
}

/// Parses `user:path=>name[,user:path=>name...]`.
pub fn parse(spec: &str) -> Result<Vec<Export>> {
    let mut out = Vec::new();
    for item in spec.split(',').map(str::trim).filter(|i| !i.is_empty()) {
        let bad = || Error::new(format!("HD_EXPORTS: {item:?} is not user:path=>name"));
        let (from, name) = item.split_once("=>").ok_or_else(bad)?;
        let (user, path) = from.split_once(':').ok_or_else(bad)?;
        let path = path.trim().trim_matches('/').to_owned();
        let name = name.trim().to_owned();
        hd_store::model::validate_user(user.trim()).map_err(|_| bad())?;
        pathname::validate(&path).map_err(|_| bad())?;
        if name.is_empty()
            || name.starts_with('.')
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(bad());
        }
        if out.iter().any(|e: &Export| e.name == name) {
            return Err(Error::new(format!("HD_EXPORTS names {name} twice")));
        }
        out.push(Export { user: user.trim().to_owned(), path, name });
    }
    Ok(out)
}

fn record_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!(".homedrive-{name}"))
}

/// What the export wrote at a path: the version, and its SHA-256.
type Written = (u64, [u8; 32]);

fn load_record(path: &Path) -> BTreeMap<String, Written> {
    let mut out = BTreeMap::new();
    if let Ok(Some(text)) = fsio::read_text(path, MAX_RECORD) {
        for line in text.lines() {
            let mut parts = line.splitn(3, ' ');
            if let (Some(v), Some(h), Some(p)) = (parts.next(), parts.next(), parts.next())
                && let Ok(v) = v.parse()
                && let Some(h) = hd_common::buf::hex_decode(h)
                && let Ok(h) = <[u8; 32]>::try_from(h)
            {
                out.insert(p.to_owned(), (v, h));
            }
        }
    }
    out
}

fn save_record(path: &Path, record: &BTreeMap<String, Written>) -> Result<()> {
    let mut text = String::new();
    for (p, (v, h)) in record {
        let _ = writeln!(text, "{v} {} {p}", hd_common::buf::hex(h));
    }
    fsio::atomic_replace(path, text.as_bytes(), MAX_RECORD)
}

/// The SHA-256 of the regular file at `path`; `None` if nothing is there.
/// Anything else at the path (a folder, a link) is an error: it is not
/// the export's to touch.
fn content_hash(path: &Path) -> Result<Option<[u8; 32]>> {
    let mut f = match fsio::open_nofollow(path) {
        Ok(f) => f,
        Err(_) if fs_absent(path) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if !f.metadata()?.is_file() {
        return Err(Error::new("something other than a file is in the way"));
    }
    let mut h = hd_crypto::Sha256::new().map_err(|_| Error::new("SHA-256 failed"))?;
    let mut buf = vec![0_u8; 256 * 1024];
    loop {
        let n = match f.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(Some(h.finish().map_err(|_| Error::new("SHA-256 failed"))?))
}

fn fs_absent(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
}

/// What one reconcile did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ExportReport {
    pub written: usize,
    /// Files already holding the wanted content, recorded without writing.
    pub adopted: usize,
    pub removed: usize,
    pub errors: Vec<String>,
}

/// Brings one export up to date.
pub fn reconcile(app: &App, export: &Export, dir: &Path) -> Result<ExportReport> {
    let root = dir.join(&export.name);
    fsio::mkdir_durable(&root, 0o755)?;
    let want: BTreeMap<String, (u64, hd_chunk::ObjectId, i64, [u8; 32])> = app.store.read(|st| {
        let mut out = BTreeMap::new();
        if let Some(ns) = st.user(&export.user) {
            for (p, e) in ns.subtree(&export.path) {
                if let Node::File { versions, .. } = &e.node
                    && let Some(v) = versions.last()
                    && let Some(rel) = pathname::rebase(p, &export.path, "")
                {
                    let rel = rel.trim_start_matches('/').to_owned();
                    if !rel.is_empty() {
                        out.insert(rel, (v.id, v.manifest, v.mtime_ms, v.sha256));
                    }
                }
            }
        }
        out
    });
    let record_file = record_path(dir, &export.name);
    let mut have = load_record(&record_file);
    let mut report = ExportReport::default();
    for (rel, (version, manifest, mtime_ms, sha256)) in &want {
        let target = root.join(rel);
        if have.get(rel).is_some_and(|(v, _)| v == version) && target.is_file() {
            continue;
        }
        let result = (|| -> Result<bool> {
            match content_hash(&target)? {
                None => {}
                Some(h) if h == *sha256 => return Ok(false),
                Some(h) if have.get(rel).is_some_and(|(_, wrote)| *wrote == h) => {}
                Some(_) => {
                    return Err(Error::new(
                        "a file the export did not write is in the way; it was left alone",
                    ));
                }
            }
            let parent = target.parent().ok_or_else(|| Error::new("no parent"))?;
            fsio::mkdir_durable(parent, 0o755)?;
            let mut staged = fsio::Staged::create_in(parent, STAGING_PREFIX)?;
            let mut reader = app.store.open_content(manifest)?;
            io::copy(&mut reader, &mut staged)?;
            let modified = u64::try_from(*mtime_ms)
                .ok()
                .map(|ms| std::time::UNIX_EPOCH + Duration::from_millis(ms));
            staged.finish(modified, 0o644)?;
            staged.commit_replace(&target)?;
            Ok(true)
        })();
        match result {
            Ok(wrote) => {
                have.insert(rel.clone(), (*version, *sha256));
                if wrote {
                    report.written += 1;
                } else {
                    report.adopted += 1;
                }
            }
            Err(e) => report.errors.push(format!("{rel}: {e}")),
        }
    }
    let gone: Vec<String> = have.keys().filter(|k| !want.contains_key(*k)).cloned().collect();
    for rel in gone {
        let target = root.join(&rel);
        let wrote = have.get(&rel).map(|(_, h)| *h);
        let removal = match content_hash(&target) {
            Ok(Some(h)) if Some(h) == wrote => fsio::remove_derived_file(&target),
            Ok(None) => Ok(()),
            Ok(Some(_)) => {
                // Changed by someone else since: theirs now, so it stays.
                have.remove(&rel);
                report.errors.push(format!("{rel}: changed since it was exported; left alone"));
                continue;
            }
            Err(e) => Err(e),
        };
        match removal {
            Ok(()) => {
                have.remove(&rel);
                report.removed += 1;
                // Folders the removal emptied go too, up to the export root.
                let mut dir = target.parent().map(Path::to_path_buf);
                while let Some(d) = dir {
                    if d == root || !fsio::remove_empty_dir(&d).unwrap_or(false) {
                        break;
                    }
                    dir = d.parent().map(Path::to_path_buf);
                }
            }
            Err(e) => report.errors.push(format!("{rel}: {e}")),
        }
    }
    if report.written + report.removed + report.adopted > 0
        || !report.errors.is_empty()
        || !record_file.exists()
    {
        save_record(&record_file, &have)?;
    }
    Ok(report)
}

/// Starts the export worker, if any exports are configured.
pub fn start(app: &Arc<App>) -> Result<()> {
    if app.config.exports.is_empty() {
        return Ok(());
    }
    fsio::mkdir_durable(&app.config.export_dir, 0o755)?;
    let app = Arc::clone(app);
    std::thread::Builder::new()
        .name("exports".into())
        .stack_size(512 * 1024)
        .spawn(move || {
            loop {
                let seq = app.store.read(|s| s.seq);
                for export in &app.config.exports {
                    match reconcile(&app, export, &app.config.export_dir) {
                        Ok(r) => {
                            if r.written + r.removed > 0 {
                                eprintln!(
                                    "hd-server: export {}: {} written, {} removed",
                                    export.name, r.written, r.removed
                                );
                            }
                            for e in r.errors {
                                eprintln!("hd-server: export {}: {e}", export.name);
                            }
                        }
                        Err(e) => eprintln!("hd-server: export {} failed: {e}", export.name),
                    }
                }
                app.store.wait_for_change(seq, Duration::from_hours(1));
                // Let a burst of commits finish before copying.
                std::thread::sleep(Duration::from_secs(2));
            }
        })
        .map_err(|e| Error::new(format!("cannot start the export worker: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specs() {
        assert_eq!(
            parse("alice:Music=>music, bob:/Photos/2024/=>photos").unwrap(),
            vec![
                Export { user: "alice".into(), path: "Music".into(), name: "music".into() },
                Export { user: "bob".into(), path: "Photos/2024".into(), name: "photos".into() },
            ]
        );
        assert!(parse("").unwrap().is_empty());
        for bad in [
            "alice:Music",
            "alice=>m",
            "al ice:x=>m",
            "alice:../x=>m",
            "alice:x=>.hidden",
            "a:x=>m,b:y=>m",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }
}
