//! The homedrive sync client.
//!
//! ```text
//! homedrive login --server URL --user NAME [--device NAME] [--ca-file PEM]
//!         Register this computer as a device (the account password is read
//!         from HOMEDRIVE_PASSWORD or the first line of standard input) and
//!         keep its token in ~/.config/homedrive/token.
//! homedrive add-folder LOCAL [--remote PATH] [--ignore PATTERN]...
//!         Sync LOCAL with PATH in the drive ("" for all of it). Creates
//!         LOCAL/.homedrive-root, the marker that proves it is the right
//!         folder before anything is synced.
//! homedrive sync
//!         One round for every folder the daemon is not syncing, then exit.
//! homedrive confirm
//!         Approve the deletions and changes held back as unusually many
//!         (or as looking like encryption): the daemon carries them out on
//!         its next round, or this does at once if no daemon is running.
//! homedrive verify
//!         Re-read every synced file now and compare it with what was
//!         synced; files damaged on this computer's disk are replaced with
//!         the server's copy (the damaged copy is kept in .homedrive/damaged).
//! homedrive rewind PATH (--hours N | --days N) [--apply]
//!         Put PATH in the drive ("" for all of it) back as it was N hours
//!         or days ago: after ransomware, or a mistake across many files.
//!         Shows what it would do; --apply does it. Nothing is removed.
//! homedrive daemon
//!         Keep syncing: on local changes (inotify on Linux, change
//!         notifications on Windows) and every 15 seconds. What needs the
//!         user (deletions held back, conflicts, files that did not sync, a
//!         sync that has stopped, a restored or damaged server) is shown as
//!         a desktop notification on Linux, and always written to the log.
//! homedrive status    Show the folders, what is known about them, and
//!                     what their last round held back or could not do.
//! homedrive test-notification
//!         Show a desktop notification, to check they reach the desktop.
//! homedrive version
//! ```

#![forbid(unsafe_code)]

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use hd_client::config::{self, Config, FolderConfig};
use hd_client::control::{Request, Status};
use hd_client::engine::{Engine, Options, Report};
use hd_client::notify::{Notice, Notifier};
use hd_client::remote::Remote;
use hd_common::{Error, Result};

const POLL: Duration = Duration::from_secs(15);
const TRASH_DAYS: u64 = 30;
/// How often the daemon asks the server whether its store is healthy.
const HEALTH_EVERY: Duration = Duration::from_mins(10);

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn arg_values(args: &[String], name: &str) -> Vec<String> {
    args.windows(2).filter(|w| w[0] == name).map(|w| w[1].clone()).collect()
}

fn read_password() -> Result<String> {
    if let Ok(p) = std::env::var("HOMEDRIVE_PASSWORD") {
        return Ok(p);
    }
    eprint!("Password: ");
    let mut buf = Vec::new();
    let mut byte = [0_u8; 1];
    let mut stdin = std::io::stdin().lock();
    while buf.len() < 1024 {
        match stdin.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => buf.push(byte[0]),
            Err(e) => return Err(e.into()),
        }
    }
    String::from_utf8(buf)
        .map(|s| s.trim_end_matches('\r').to_owned())
        .map_err(|_| Error::new("the password is not UTF-8"))
}

fn login(args: &[String]) -> Result<()> {
    let server = arg_value(args, "--server").ok_or_else(|| Error::new("--server is required"))?;
    let user = arg_value(args, "--user").ok_or_else(|| Error::new("--user is required"))?;
    let host = if cfg!(windows) {
        std::env::var("COMPUTERNAME").unwrap_or_default()
    } else {
        hd_common::fsio::read_text("/etc/hostname", 256)
            .ok()
            .flatten()
            .map(|h| h.trim().to_owned())
            .unwrap_or_default()
    };
    let device = arg_value(args, "--device")
        .unwrap_or_else(|| if host.is_empty() { "computer".into() } else { host });
    let ca_file = arg_value(args, "--ca-file").map(PathBuf::from);
    let password = read_password()?;
    let token = Remote::register(&server, ca_file.as_deref(), &user, &password, &device)?;
    let dir = config::config_dir()?;
    config::save_token(&dir, &token.token)?;
    let mut cfg = Config::load(&dir).unwrap_or(Config {
        server: server.clone(),
        user: user.clone(),
        ca_file: None,
        folders: Vec::new(),
    });
    cfg.server = server;
    cfg.user = user;
    cfg.ca_file = ca_file;
    cfg.save(&dir)?;
    println!("Registered this computer as device {} ({device}).", token.device_id);
    Ok(())
}

fn add_folder(args: &[String]) -> Result<()> {
    let local = args
        .get(2)
        .filter(|a| !a.starts_with("--"))
        .ok_or_else(|| Error::new("usage: homedrive add-folder LOCAL [--remote PATH]"))?;
    let local = std::path::absolute(local)?;
    let remote = arg_value(args, "--remote").unwrap_or_default().trim_matches('/').to_owned();
    hd_common::pathname::validate(&remote)?;
    let dir = config::config_dir()?;
    let mut cfg = Config::load(&dir)?;
    if !cfg.folders.iter().any(|f| f.local == local) {
        let mut with = cfg.clone();
        with.folders.push(FolderConfig {
            local: local.clone(),
            remote: String::new(),
            ignore: vec![],
        });
        with.check_folders()?;
    }
    if cfg.folders.iter().any(|f| f.local == local) {
        // Re-marking an existing folder (after its marker went missing).
        Engine::mark_root(&local).or_else(|e| {
            if local.join(hd_client::scan::SENTINEL).exists() { Ok(()) } else { Err(e) }
        })?;
        println!("{} is already configured; its marker is in place.", local.display());
        return Ok(());
    }
    Engine::mark_root(&local)?;
    cfg.folders.push(FolderConfig {
        local: local.clone(),
        remote: remote.clone(),
        ignore: arg_values(args, "--ignore"),
    });
    cfg.save(&dir)?;
    println!("{} will sync with /{remote}.", local.display());
    Ok(())
}

fn load_config() -> Result<Config> {
    let cfg = Config::load(&config::config_dir()?)?;
    if cfg.folders.is_empty() {
        return Err(Error::new("no folders configured; run `homedrive add-folder` first"));
    }
    cfg.check_folders()?;
    Ok(cfg)
}

fn remote(cfg: &Config) -> Result<Remote> {
    Remote::new(&cfg.server, cfg.ca_file.as_deref(), &config::load_token(&config::config_dir()?)?)
}

/// Each folder, with its engine, or `None` where another process (the
/// daemon) is syncing it.
fn engines(cfg: &Config) -> Result<Vec<(hd_client::engine::Folder, Option<Engine>)>> {
    let mut out = Vec::new();
    for f in &cfg.folders {
        let folder = cfg.folder(f)?;
        let engine = Engine::try_open(folder.clone(), remote(cfg)?, Options::default())?;
        out.push((folder, engine));
    }
    Ok(out)
}

fn print_report(local: &std::path::Path, r: &Report) {
    let n = |v: &Vec<String>| v.len();
    if r.changed_anything() {
        println!(
            "{}: {} up, {} down, {} deleted here, {} deleted on the server, {} conflict(s)",
            local.display(),
            n(&r.uploaded),
            n(&r.downloaded),
            n(&r.deleted_local),
            n(&r.deleted_remote),
            n(&r.conflicts)
        );
    }
    for c in &r.conflicts {
        println!("  conflict: your copy is now {c}");
    }
    for (p, why) in &r.errors {
        eprintln!("  {p}: {why}");
    }
    for (p, why) in &r.skipped {
        eprintln!("  not synced: {p}: {why}");
    }
    if r.ransomware_suspected {
        eprintln!(
            "  WARNING: changes in this folder look like encryption (ransomware?); every \
             change and deletion is held back. If you did not expect this, disconnect this \
             computer and use `homedrive rewind` or the web UI's Rewind to put things back"
        );
    }
    if let Some(n) = r.held_changes {
        eprintln!(
            "  held back {n} change(s) as unusually many{}; if they are intended, run \
             `homedrive confirm`",
            if r.suspicious > 0 {
                format!(", {} of them looking like encryption", r.suspicious)
            } else {
                String::new()
            }
        );
    }
    if let Some(n) = r.held_deletes {
        eprintln!("  held back {n} deletion(s); if they are intended, run `homedrive confirm`");
    }
    for p in &r.repaired_local {
        eprintln!(
            "  {p} was damaged on this computer's disk and was replaced with the server's \
             copy; the damaged copy is in .homedrive/damaged"
        );
    }
    if r.verified_all {
        println!("  checked every file against what was synced");
    }
}

fn round(local: &std::path::Path, e: &mut Engine) -> bool {
    let ok = match e.sync(0) {
        Ok(r) => {
            print_report(local, &r);
            r.errors.is_empty()
        }
        Err(err) => {
            eprintln!("{}: {err}", local.display());
            false
        }
    };
    let _ = hd_client::trash::expire(local, TRASH_DAYS);
    ok
}

fn busy(local: &std::path::Path) {
    println!(
        "{}: the daemon is syncing this folder; `homedrive status` shows what it held back or \
         could not do",
        local.display()
    );
}

fn sync(args: &[String]) -> Result<()> {
    if args.iter().any(|a| a == "--confirm-deletes") {
        return confirm();
    }
    let mut failed = false;
    for (folder, engine) in engines(&load_config()?)? {
        match engine {
            Some(mut e) => failed |= !round(&folder.local, &mut e),
            None => busy(&folder.local),
        }
    }
    if failed { Err(Error::new("some paths did not sync")) } else { Ok(()) }
}

/// Leaves `request` for each folder that `wanted` says needs one, and
/// carries it out at once where no daemon is syncing.
fn request_each(wanted: impl Fn(&std::path::Path, &Status) -> Option<Request>) -> Result<()> {
    let cfg = load_config()?;
    let mut failed = false;
    for f in &cfg.folders {
        let folder = cfg.folder(f)?;
        let status = Status::read(&folder.state_dir).unwrap_or_default();
        let Some(request) = wanted(&folder.local, &status) else { continue };
        request.write(&folder.state_dir)?;
        match Engine::try_open(folder.clone(), remote(&cfg)?, Options::default())? {
            Some(mut e) => failed |= !round(&folder.local, &mut e),
            None => println!(
                "{}: the daemon will do it on its next round, within a minute",
                folder.local.display()
            ),
        }
    }
    if failed { Err(Error::new("some paths did not sync")) } else { Ok(()) }
}

fn confirm() -> Result<()> {
    request_each(|local, st| {
        if st.held_deletes.is_none() && st.held_changes.is_none() {
            println!("{}: nothing is waiting", local.display());
            return None;
        }
        let deletes = st.held_deletes.unwrap_or(0);
        let changes = st.held_changes.unwrap_or(0);
        println!(
            "{}: confirming {deletes} deletion(s) and {changes} change(s){}",
            local.display(),
            if st.ransomware_suspected { ", although they looked like encryption" } else { "" }
        );
        Some(Request { at_ms: hd_common::timefmt::unix_ms(), deletes, changes, verify: false })
    })
}

fn verify() -> Result<()> {
    request_each(|local, _| {
        println!("{}: checking every file", local.display());
        Some(Request { at_ms: hd_common::timefmt::unix_ms(), verify: true, ..Request::default() })
    })
}

fn rewind(args: &[String]) -> Result<()> {
    let usage = "usage: homedrive rewind PATH (--hours N | --days N) [--apply]";
    let path = args.get(2).filter(|a| !a.starts_with("--")).ok_or_else(|| Error::new(usage))?;
    let path = path.trim_matches('/').to_owned();
    let (n, unit) = match (arg_value(args, "--hours"), arg_value(args, "--days")) {
        (Some(h), None) => (h, 3_600_000),
        (None, Some(d)) => (d, 86_400_000),
        _ => return Err(Error::new(usage)),
    };
    let n: i64 =
        n.parse().ok().filter(|n| (1..=3650).contains(n)).ok_or_else(|| Error::new(usage))?;
    let apply = args.iter().any(|a| a == "--apply");
    let at = hd_common::timefmt::unix_ms() - n * unit;
    let mut remote = remote(&load_config()?)?;
    let r = remote.rewind(&path, at, apply)?;
    let count = |k: &str| hd_api::get_u64(&r, &format!("{k}_count")).unwrap_or(0);
    let list = |k: &str| -> Vec<String> {
        hd_api::get_array(&r, k)
            .map(|a| {
                a.iter()
                    .filter_map(|v| {
                        v.as_str().map(str::to_owned).or_else(|| {
                            let from = hd_api::get_str(v, "from").ok()?;
                            let to = hd_api::get_str(v, "to").ok()?;
                            Some(if from == to { from } else { format!("{from} (as {to})") })
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    let place = if path.is_empty() { "the whole drive".to_owned() } else { format!("/{path}") };
    println!(
        "{} {place} to {}:",
        if apply { "Rewound" } else { "Rewinding would put" },
        hd_common::timefmt::rfc3339_millis(at / 1000, 0)
    );
    for (label, key) in [
        ("earlier content", "reverted"),
        ("back from the trash", "undeleted"),
        ("made since, kept as they are", "newer"),
    ] {
        println!("  {} file(s) {label}", count(key));
        for p in list(key).iter().take(50) {
            println!("    {p}");
        }
    }
    for p in list("skipped") {
        println!("  changed meanwhile, left alone: {p}");
    }
    if apply {
        println!("Nothing was removed: every version since is still in each file's history.");
    } else {
        println!("Nothing has changed yet. Run again with --apply to do it.");
    }
    Ok(())
}

fn daemon() -> Result<()> {
    let mut list = Vec::new();
    for (folder, engine) in engines(&load_config()?)? {
        list.push(engine.ok_or_else(|| {
            Error::new(format!(
                "{} is already being synced by another homedrive process; is the daemon \
                 running already?",
                folder.local.display()
            ))
        })?);
    }
    let notifier = Arc::new(Mutex::new(Notifier::desktop()));
    let mut handles = Vec::new();
    {
        let dir = config::config_dir()?;
        let cfg = Config::load(&dir)?;
        let mut remote =
            Remote::new(&cfg.server, cfg.ca_file.as_deref(), &config::load_token(&dir)?)?;
        let notifier = Arc::clone(&notifier);
        handles.push(
            std::thread::Builder::new()
                .name("health".into())
                .stack_size(256 * 1024)
                .spawn(move || {
                    loop {
                        // Unreachable is reported by the folders' rounds.
                        if let Ok(problems) = remote.server_problems() {
                            notifier
                                .lock()
                                .unwrap_or_else(PoisonError::into_inner)
                                .server(&problems);
                        }
                        std::thread::sleep(HEALTH_EVERY);
                    }
                })
                .map_err(|e| Error::new(format!("cannot start the health thread: {e}")))?,
        );
    }
    for mut e in list {
        let notifier = Arc::clone(&notifier);
        handles.push(
            std::thread::Builder::new()
                .name("folder".into())
                .stack_size(1024 * 1024)
                .spawn(move || {
                    let local = e.folder().local.clone();
                    let mut watcher = hd_sys::watch::Watcher::new().ok();
                    let mut last_expiry = Instant::now();
                    loop {
                        let result = e.sync(0);
                        match &result {
                            Ok(r) => print_report(&local, r),
                            Err(err) => eprintln!("{}: {err}", local.display()),
                        }
                        notifier
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .round(&local, result.as_ref().map_err(Error::message));
                        if last_expiry.elapsed() > Duration::from_hours(1) {
                            let _ = hd_client::trash::expire(&local, TRASH_DAYS);
                            last_expiry = Instant::now();
                        }
                        // Watch every folder (watching one already watched
                        // is harmless), then wait for a change or the poll.
                        if let Some(w) = &mut watcher {
                            let _ = w.watch_dir(&local);
                            let per_dir = !w.recursive();
                            if let Some(scan) = per_dir
                                .then(|| hd_client::scan::scan(&local, &e.folder().ignore).ok())
                                .flatten()
                            {
                                for (rel, entry) in &scan.entries {
                                    if entry.kind == hd_client::state::Kind::Dir {
                                        let _ = w.watch_dir(&local.join(rel));
                                    }
                                }
                            }
                            let deadline = Instant::now() + POLL;
                            while Instant::now() < deadline {
                                let left = deadline.saturating_duration_since(Instant::now());
                                if w.wait(u32::try_from(left.as_millis()).unwrap_or(u32::MAX))
                                    .unwrap_or(false)
                                {
                                    // Let a burst of writes settle first.
                                    std::thread::sleep(Duration::from_secs(2));
                                    break;
                                }
                            }
                        } else {
                            std::thread::sleep(POLL);
                        }
                    }
                })
                .map_err(|e| Error::new(format!("cannot start a folder thread: {e}")))?,
        );
    }
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

fn status() -> Result<()> {
    let dir = config::config_dir()?;
    let cfg = Config::load(&dir)?;
    println!("server: {} (as {})", cfg.server, cfg.user);
    for f in &cfg.folders {
        let folder = cfg.folder(f)?;
        // Read only: the daemon may be syncing it.
        let state = hd_client::state::Persisted::peek(&folder.state_dir)?;
        println!(
            "{} <-> /{}: {} synced, {} on the server, cursor {}",
            f.local.display(),
            f.remote,
            state.synced.len(),
            state.remote.len(),
            state.cursor
        );
        let Some(st) = Status::read(&folder.state_dir) else { continue };
        println!("  last round: {}", hd_common::timefmt::rfc3339_millis(st.at_ms / 1000, 0));
        if st.ransomware_suspected {
            println!("  WARNING: recent changes look like encryption (ransomware?); holding back");
        }
        if let Some(n) = st.held_changes {
            println!("  {n} change(s) held back; `homedrive confirm` if intended");
        }
        if let Some(n) = st.held_deletes {
            println!("  {n} deletion(s) held back; `homedrive confirm` if intended");
        }
        for p in &st.repaired_local {
            println!("  repaired from the server (was damaged on this disk): {p}");
        }
        for (p, why) in &st.errors {
            println!("  did not sync: {p}: {why}");
        }
        for (p, why) in &st.skipped {
            println!("  not synced: {p}: {why}");
        }
    }
    Ok(())
}

fn test_notification() -> Result<()> {
    let notice = Notice {
        key: None,
        title: "homedrive notifications work".into(),
        body: "This is how homedrive will tell you when something needs you.".into(),
        urgent: false,
    };
    #[cfg(target_os = "linux")]
    {
        let id = hd_client::notify::dbus::notify(&notice.title, &notice.body, notice.urgent)?;
        println!("Sent notification {id}.");
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = notice;
        Err(Error::new("desktop notifications are Linux-only for now; the daemon's log has them"))
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("login") => login(&args),
        Some("add-folder") => add_folder(&args),
        Some("sync") => sync(&args),
        Some("confirm") => confirm(),
        Some("verify") => verify(),
        Some("rewind") => rewind(&args),
        Some("daemon") => daemon(),
        Some("status") => status(),
        Some("test-notification") => test_notification(),
        Some("version" | "--version") => {
            println!("homedrive {}", hd_common::VERSION);
            Ok(())
        }
        _ => Err(Error::new(
            "usage: homedrive \
             [login|add-folder|sync|confirm|verify|rewind|daemon|status|test-notification|version]",
        )),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("homedrive: {e}");
            ExitCode::FAILURE
        }
    }
}
