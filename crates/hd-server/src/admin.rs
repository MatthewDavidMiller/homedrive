//! The admin socket, `<data>/admin.sock` (mode 0600), for commands run in
//! the container with `podman exec` while the server is running.
//!
//! A request is one JSON line. `import` then sends the file's bytes until
//! it shuts down its write side. The answer is one JSON line.
//!
//! | `cmd` | Fields | Does |
//! |---|---|---|
//! | `import` | `user`, `path`, `absent`, `mtime_ms`, `created_ms` | Stores the bytes as a new version |
//! | `stat` | `user`, `path` | The current version's size and SHA-256 |
//! | `checkpoint` | | Writes a metadata snapshot (before a backup) |
//! | `fsck` | `deep` | Checks every version can be read back |
//! | `gc` | `dry_run` | One garbage collection |
//! | `scrub` | | Re-verifies every object |
//!
//! The client half (`call`, `import_tree`, `verify_tree`) is what the
//! `hd-server` subcommands use.

use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use hd_api::{J, s};
use hd_common::json::Value;
use hd_common::{Error, Result, fsio, pathname, timefmt};
use hd_store::model::{Node, Origin};
use hd_store::{Base, Provenance};

use crate::App;

pub const SOCKET: &str = "admin.sock";
const MAX_REQUEST: u64 = 64 * 1024;
const MAX_REPLY: u64 = 16 * 1024 * 1024;

pub fn socket_path(data_dir: &Path) -> PathBuf {
    data_dir.join(SOCKET)
}

/// Starts listening on the admin socket.
pub fn start(app: &Arc<App>) -> Result<()> {
    let path = socket_path(&app.config.data_dir);
    // The store's lock is held, so any socket file here is a leftover.
    fsio::remove_stale_socket(&path)?;
    let listener = UnixListener::bind(&path)
        .map_err(|e| Error::new(format!("cannot open the admin socket {}: {e}", path.display())))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    let app = Arc::clone(app);
    std::thread::Builder::new()
        .name("admin".into())
        .stack_size(256 * 1024)
        .spawn(move || {
            for conn in listener.incoming() {
                let Ok(conn) = conn else { continue };
                let app = Arc::clone(&app);
                let _ = std::thread::Builder::new()
                    .name("admin-conn".into())
                    .stack_size(512 * 1024)
                    .spawn(move || {
                        let mut reader = BufReader::new(&conn);
                        let reply = match handle(&app, &mut reader) {
                            Ok(v) => v,
                            Err(e) => J::O(vec![("ok", J::Bool(false)), ("error", s(e.message()))]),
                        };
                        let mut out = &conn;
                        let _ = out.write_all(format!("{}\n", reply.render()).as_bytes());
                    });
            }
        })
        .map_err(|e| Error::new(format!("cannot start the admin socket: {e}")))?;
    Ok(())
}

fn read_line(r: &mut dyn BufRead) -> Result<Value> {
    let mut line = Vec::new();
    r.take(MAX_REQUEST).read_until(b'\n', &mut line)?;
    if line.last() != Some(&b'\n') {
        return Err(Error::new("the request line is missing or too long"));
    }
    hd_api::parse(&line)
}

fn ok(mut fields: Vec<(&'static str, J)>) -> J {
    fields.insert(0, ("ok", J::Bool(true)));
    J::O(fields)
}

fn handle(app: &App, reader: &mut BufReader<&UnixStream>) -> Result<J> {
    let req = read_line(reader)?;
    let cmd = hd_api::get_str(&req, "cmd")?;
    let user = || -> Result<String> {
        let u = hd_api::get_str(&req, "user")?;
        if app.accounts.get(&u).is_none() {
            return Err(Error::new(format!("{u} is not in the users file")));
        }
        Ok(u)
    };
    match cmd.as_str() {
        "import" => {
            let user = user()?;
            let path = hd_api::get_str(&req, "path")?;
            let absent = req.get("absent").and_then(Value::as_bool).unwrap_or(false);
            let now = timefmt::unix_ms();
            let provenance = Provenance {
                device: "import".into(),
                mtime_ms: req.get("mtime_ms").and_then(Value::as_i64).unwrap_or(now),
                origin: Origin::Import,
                created_ms: req.get("created_ms").and_then(Value::as_i64),
            };
            let base = if absent { Base::Absent } else { Base::Any };
            let c = app.store.write_file(
                &user,
                &path,
                base,
                reader,
                app.config.max_file,
                &provenance,
            )?;
            Ok(ok(vec![
                ("path", s(c.path)),
                ("version", J::U(c.version)),
                ("conflict", J::Bool(c.conflict)),
                ("unchanged", J::Bool(c.unchanged)),
            ]))
        }
        "stat" => {
            let user = user()?;
            let path = hd_api::get_str(&req, "path")?;
            let found = app.store.read(|st| {
                match st.user(&user).and_then(|ns| ns.get(&path)).map(|e| &e.node) {
                    Some(Node::File { versions, .. }) => {
                        versions.last().map(|v| (v.size, v.sha256, versions.len()))
                    }
                    _ => None,
                }
            });
            Ok(match found {
                Some((size, sha, n)) => ok(vec![
                    ("exists", J::Bool(true)),
                    ("size", J::U(size)),
                    ("sha256", s(hd_api::hex(&sha))),
                    ("versions", J::U(n as u64)),
                ]),
                None => ok(vec![("exists", J::Bool(false))]),
            })
        }
        "checkpoint" => Ok(ok(vec![("seq", J::U(app.store.checkpoint()?))])),
        "fsck" => {
            let deep = req.get("deep").and_then(Value::as_bool).unwrap_or(false);
            let r = app.store.fsck(deep)?;
            Ok(ok(vec![
                ("versions", J::U(r.versions as u64)),
                ("manifests", J::U(r.manifests as u64)),
                ("chunks", J::U(r.chunks as u64)),
                ("problems", J::A(r.problems.into_iter().map(s).collect())),
            ]))
        }
        "gc" => {
            let dry_run = req.get("dry_run").and_then(Value::as_bool).unwrap_or(false);
            let options = hd_store::gc::GcOptions { dry_run, ..Default::default() };
            let r = app.store.collect_garbage(timefmt::unix_ms(), &options)?;
            Ok(ok(vec![("report", s(format!("{r:?}")))]))
        }
        "scrub" => {
            let r = app.store.scrub(0, &AtomicBool::new(false))?;
            crate::maintenance::check_references(app);
            Ok(ok(vec![
                ("checked", J::U(r.checked as u64)),
                ("bytes", J::U(r.bytes)),
                ("quarantined", J::U((r.quarantined.len() + r.failed.len()) as u64)),
            ]))
        }
        "repair" => {
            let sources: Vec<std::path::PathBuf> = req
                .get("from")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).map(std::path::PathBuf::from).collect())
                .unwrap_or_default();
            let r = app.store.repair_from(&sources)?;
            crate::maintenance::check_references(app);
            Ok(ok(vec![
                ("versions", J::U(r.versions as u64)),
                ("restored", J::U(r.restored as u64)),
                ("still_damaged", J::A(r.still_damaged.into_iter().map(s).collect())),
            ]))
        }
        other => Err(Error::new(format!("unknown command {other}"))),
    }
}

/// Sends one request (and, for `import`, a body) to the running server.
pub fn call(data_dir: &Path, request: &J, body: Option<&mut dyn Read>) -> Result<Value> {
    let path = socket_path(data_dir);
    let mut conn = UnixStream::connect(&path).map_err(|e| {
        Error::new(format!("cannot reach the server's admin socket {}: {e}", path.display()))
    })?;
    conn.write_all(format!("{}\n", request.render()).as_bytes())?;
    if let Some(b) = body {
        io::copy(b, &mut conn)?;
    }
    conn.shutdown(std::net::Shutdown::Write)?;
    let mut reader = BufReader::new(&conn);
    let mut line = Vec::new();
    (&mut reader).take(MAX_REPLY).read_until(b'\n', &mut line)?;
    let v = hd_api::parse(&line)?;
    if v.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(v)
    } else {
        Err(Error::new(
            v.get("error").and_then(Value::as_str).unwrap_or("the server refused").to_owned(),
        ))
    }
}

/// Whether a server is answering on the admin socket.
pub fn server_running(data_dir: &Path) -> bool {
    UnixStream::connect(socket_path(data_dir)).is_ok()
}

/// Every regular file under `src`, relative, sorted. Symbolic links and
/// other specials are listed separately as skipped.
fn walk(src: &Path) -> Result<(Vec<String>, Vec<String>)> {
    fn go(dir: &Path, rel: &str, files: &mut Vec<String>, skipped: &mut Vec<String>) -> Result<()> {
        let mut names: Vec<_> =
            fs::read_dir(dir)?.map(|e| e.map(|e| e.file_name())).collect::<io::Result<_>>()?;
        names.sort();
        for n in names {
            let Some(name) = n.to_str() else {
                skipped.push(format!("{rel}/{}", n.to_string_lossy()));
                continue;
            };
            let child = pathname::join(rel, name);
            let meta = fs::symlink_metadata(dir.join(name))?;
            if meta.file_type().is_dir() {
                go(&dir.join(name), &child, files, skipped)?;
            } else if meta.file_type().is_file() && pathname::validate(&child).is_ok() {
                files.push(child);
            } else {
                skipped.push(child);
            }
        }
        Ok(())
    }
    let (mut files, mut skipped) = (Vec::new(), Vec::new());
    go(src, "", &mut files, &mut skipped)?;
    Ok((files, skipped))
}

fn hash_file(path: &Path) -> Result<([u8; 32], u64)> {
    let mut f = fsio::open_nofollow(path)?;
    let mut h = hd_crypto::Sha256::new().map_err(|_| Error::new("SHA-256 failed"))?;
    let mut buf = vec![0_u8; 256 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    let len = h.len();
    Ok((h.finish().map_err(|_| Error::new("SHA-256 failed"))?, len))
}

fn mtime_ms(path: &Path) -> Option<i64> {
    fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
}

fn stat(data_dir: &Path, user: &str, path: &str) -> Result<Option<([u8; 32], u64)>> {
    let v = call(
        data_dir,
        &J::O(vec![("cmd", s("stat")), ("user", s(user)), ("path", s(path))]),
        None,
    )?;
    if v.get("exists").and_then(Value::as_bool) != Some(true) {
        return Ok(None);
    }
    Ok(Some((hd_api::get_hash(&v, "sha256")?, hd_api::get_u64(&v, "size")?)))
}

fn import_one(
    data_dir: &Path,
    user: &str,
    path: &str,
    file: &Path,
    mtime_ms: Option<i64>,
    created_ms: Option<i64>,
) -> Result<Value> {
    let mut fields = vec![("cmd", s("import")), ("user", s(user)), ("path", s(path))];
    if let Some(m) = mtime_ms {
        fields.push(("mtime_ms", J::I(m)));
    }
    if let Some(c) = created_ms {
        fields.push(("created_ms", J::I(c)));
    }
    let mut f = fsio::open_nofollow(file)?;
    call(data_dir, &J::O(fields), Some(&mut f))
}

#[derive(Debug, Default)]
pub struct ImportReport {
    pub imported: usize,
    pub versions: usize,
    pub unchanged: usize,
    pub skipped: Vec<String>,
}

/// Loads every file under `src` into `user`'s drive under `dest`. With
/// `versions`, files named `<path>.v<unix seconds>` in that tree become
/// older versions of `<path>`, oldest first, keeping their dates. A file
/// whose current content is already stored is left alone, so re-running
/// after an interruption continues where it stopped. `log` gets one line
/// per file: its SHA-256, size, and path.
pub fn import_tree(
    data_dir: &Path,
    user: &str,
    src: &Path,
    dest: &str,
    versions: Option<&Path>,
    log: &mut dyn Write,
) -> Result<ImportReport> {
    pathname::validate(dest)?;
    let (files, skipped) = walk(src)?;
    let mut report = ImportReport { skipped, ..ImportReport::default() };
    for rel in files {
        let abs = src.join(&rel);
        let target = pathname::join(dest, &rel);
        let (sha, size) = hash_file(&abs)?;
        if stat(data_dir, user, &target)?.is_some_and(|(h, _)| h == sha) {
            report.unchanged += 1;
            continue;
        }
        if let Some(vdir) = versions {
            let dir = vdir.join(pathname::parent(&rel));
            let prefix = format!("{}.v", pathname::name(&rel));
            let mut old: Vec<(i64, PathBuf)> = fs::read_dir(&dir)
                .map(|entries| {
                    entries
                        .filter_map(std::result::Result::ok)
                        .filter_map(|e| {
                            let name = e.file_name().into_string().ok()?;
                            let secs = name.strip_prefix(&prefix)?.parse::<i64>().ok()?;
                            e.file_type().ok()?.is_file().then(|| (secs, e.path()))
                        })
                        .collect()
                })
                .unwrap_or_default();
            old.sort();
            for (secs, p) in old {
                let ms = secs.saturating_mul(1000);
                import_one(data_dir, user, &target, &p, Some(ms), Some(ms))?;
                report.versions += 1;
            }
        }
        import_one(data_dir, user, &target, &abs, mtime_ms(&abs), None)?;
        report.imported += 1;
        writeln!(log, "{}\t{size}\t{target}", hd_api::hex(&sha))?;
    }
    Ok(report)
}

#[derive(Debug, Default)]
pub struct VerifyReport {
    pub checked: usize,
    pub missing: Vec<String>,
    pub mismatched: Vec<String>,
    pub skipped: Vec<String>,
}

impl VerifyReport {
    pub fn is_clean(&self) -> bool {
        self.missing.is_empty() && self.mismatched.is_empty()
    }
}

/// Checks that every file under `src` is the current version of the same
/// path under `dest`, byte for byte (by SHA-256 and size).
pub fn verify_tree(data_dir: &Path, user: &str, src: &Path, dest: &str) -> Result<VerifyReport> {
    pathname::validate(dest)?;
    let (files, skipped) = walk(src)?;
    let mut report = VerifyReport { skipped, ..VerifyReport::default() };
    for rel in files {
        let target = pathname::join(dest, &rel);
        let (sha, size) = hash_file(&src.join(&rel))?;
        report.checked += 1;
        match stat(data_dir, user, &target)? {
            None => report.missing.push(target),
            Some((h, n)) if h == sha && n == size => {}
            Some(_) => report.mismatched.push(target),
        }
    }
    Ok(report)
}
