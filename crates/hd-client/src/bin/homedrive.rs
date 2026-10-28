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
//! homedrive sync [--confirm-deletes]
//!         One round for every folder, then exit.
//! homedrive daemon
//!         Keep syncing: on local changes (inotify on Linux, change
//!         notifications on Windows) and every 15 seconds.
//! homedrive status    Show the folders and what is known about them.
//! homedrive version
//! ```

#![forbid(unsafe_code)]

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use hd_client::config::{self, Config, FolderConfig};
use hd_client::engine::{Engine, Options, Report};
use hd_client::remote::Remote;
use hd_common::{Error, Result};

const POLL: Duration = Duration::from_secs(15);
const TRASH_DAYS: u64 = 30;

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

fn engines(confirm_deletes: bool) -> Result<Vec<Engine>> {
    let dir = config::config_dir()?;
    let cfg = Config::load(&dir)?;
    let token = config::load_token(&dir)?;
    if cfg.folders.is_empty() {
        return Err(Error::new("no folders configured; run `homedrive add-folder` first"));
    }
    let mut out = Vec::new();
    for f in &cfg.folders {
        let remote = Remote::new(&cfg.server, cfg.ca_file.as_deref(), &token)?;
        let options = Options { confirm_deletes, ..Options::default() };
        out.push(Engine::open(cfg.folder(f)?, remote, options)?);
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
    if let Some(n) = r.held_deletes {
        eprintln!(
            "  held back {n} deletion(s) as unusually many; if they are intended, run \
             `homedrive sync --confirm-deletes`"
        );
    }
}

fn sync(args: &[String]) -> Result<()> {
    let confirm = args.iter().any(|a| a == "--confirm-deletes");
    let mut failed = false;
    for mut e in engines(confirm)? {
        let local = e.folder().local.clone();
        match e.sync(0) {
            Ok(r) => {
                print_report(&local, &r);
                failed |= !r.errors.is_empty();
            }
            Err(err) => {
                eprintln!("{}: {err}", local.display());
                failed = true;
            }
        }
        let _ = hd_client::trash::expire(&local, TRASH_DAYS);
    }
    if failed { Err(Error::new("some paths did not sync")) } else { Ok(()) }
}

fn daemon() -> Result<()> {
    let list = engines(false)?;
    let mut handles = Vec::new();
    for mut e in list {
        handles.push(
            std::thread::Builder::new()
                .name("folder".into())
                .stack_size(1024 * 1024)
                .spawn(move || {
                    let local = e.folder().local.clone();
                    let mut watcher = hd_sys::watch::Watcher::new().ok();
                    let mut last_expiry = Instant::now();
                    loop {
                        match e.sync(0) {
                            Ok(r) => print_report(&local, &r),
                            Err(err) => eprintln!("{}: {err}", local.display()),
                        }
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
        let state = hd_client::state::Persisted::open(&folder.state_dir)?;
        println!(
            "{} <-> /{}: {} synced, {} on the server, cursor {}",
            f.local.display(),
            f.remote,
            state.state.synced.len(),
            state.state.remote.len(),
            state.state.cursor
        );
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("login") => login(&args),
        Some("add-folder") => add_folder(&args),
        Some("sync") => sync(&args),
        Some("daemon") => daemon(),
        Some("status") => status(),
        Some("version" | "--version") => {
            println!("homedrive {}", hd_common::VERSION);
            Ok(())
        }
        _ => Err(Error::new("usage: homedrive [login|add-folder|sync|daemon|status|version]")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("homedrive: {e}");
            ExitCode::FAILURE
        }
    }
}
