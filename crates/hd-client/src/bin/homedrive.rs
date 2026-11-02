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
//! homedrive restore PATH --to DIR
//!         Download PATH in the drive ("" for all of it) into DIR, a new
//!         directory outside any synced folder, as plain files, each
//!         verified; the manifest goes to DIR.sha256
//! homedrive check-files DIR MANIFEST
//!         Check every file MANIFEST lists (a restore's, or the server's
//!         restore drill's) under DIR; exits 1 on any missing or different
//! homedrive backup-store DIR [--encrypt]
//!         (administrators) Keep DIR a copy of the whole store, every drive
//!         with its history and trash: the backup off the server that
//!         nothing there can reach. Fetches only what changed; reports to
//!         the server, which reminds the administrators after eight days
//!         without one. Unencrypted unless --encrypt starts a new copy
//!         encrypted under a passphrase (HOMEDRIVE_COPY_PASSPHRASE, or asked
//!         for); an encrypted copy always needs it after that. The
//!         metadata a run replaces is kept as a generation, named by when
//!         it was fetched, so the copy can be opened as it was at any
//!         earlier run (--generation G below)
//! homedrive store-copy-check DIR [--generation G]
//!         Read every version in a plain copy back; for an encrypted copy,
//!         check every file authenticates and every object is intact.
//!         Exits 1 on any damage. Lists the earlier generations
//! homedrive store-copy-decrypt DIR --to PLAIN [--generation G]
//!         Open an encrypted copy into a plain one at PLAIN
//! homedrive store-copy-restore DIR --user U --to OUT [--path P] [--generation G]
//!         Write U's files (under P) from a plain copy to OUT as plain
//!         files, verified, with a manifest at OUT.sha256
//! homedrive decrypt-file IN --to OUT
//!         Open an encrypted download of the store from the web UI into
//!         the plain .tar it holds
//! homedrive gui    (or no arguments at all)
//!         Open the GUI in the browser: a wizard the first time, then the
//!         state of each folder. Starts the daemon if it is not running.
//! homedrive daemon [--no-gui]
//!         Keep syncing, and serve the GUI on this computer: on local changes (inotify on Linux, change
//!         notifications on Windows), on news from the server (asked every
//!         15 seconds), and at least every 5 minutes. What needs the
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
use std::sync::Arc;

use hd_client::config::{self, Config};
use hd_client::control::{Request, Status};
use hd_client::engine::{Engine, Options, Report};
use hd_client::gui::{self, Gui};
use hd_client::notify::Notice;
use hd_client::remote::Remote;
use hd_client::service::{Service, TRASH_DAYS};
use hd_common::{Error, Result};

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn arg_values(args: &[String], name: &str) -> Vec<String> {
    args.windows(2).filter(|w| w[0] == name).map(|w| w[1].clone()).collect()
}

fn read_password() -> Result<String> {
    read_secret("HOMEDRIVE_PASSWORD", "Password")
}

/// A secret from the environment variable `var`, or else a line of
/// standard input after `prompt`.
fn read_secret(var: &str, prompt: &str) -> Result<String> {
    if let Ok(p) = std::env::var(var) {
        return Ok(p);
    }
    eprint!("{prompt}: ");
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
    let device = arg_value(args, "--device").unwrap_or_else(config::device_name);
    let ca_file = arg_value(args, "--ca-file").map(PathBuf::from);
    let password = read_password()?;
    let token = Remote::register(&server, ca_file.as_deref(), &user, &password, &device)?;
    let dir = config::config_dir()?;
    config::save_token(&dir, &token.token)?;
    config::save_device_id(&dir, token.device_id)?;
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
    if config::add_folder(&dir, &local, &remote, arg_values(args, "--ignore"))? {
        println!("{} is already configured; its marker is in place.", local.display());
    } else {
        println!("{} will sync with /{remote}.", local.display());
    }
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

/// `println!` for the daemon's reports, ignoring a failed write: reports are
/// for a reader who may not be there, and never worth ending the program.
macro_rules! report {
    ($($arg:tt)*) => {{
        let _ = ::std::io::Write::write_fmt(
            &mut ::std::io::stdout(),
            ::std::format_args!("{}\n", ::std::format_args!($($arg)*)),
        );
    }};
}

fn print_report(local: &std::path::Path, r: &Report) {
    let n = |v: &Vec<String>| v.len();
    if r.changed_anything() {
        report!(
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
        report!("  conflict: your copy is now {c}");
    }
    for (p, why) in &r.errors {
        hd_client::say!("  {p}: {why}");
    }
    for (p, why) in &r.skipped {
        hd_client::say!("  not synced: {p}: {why}");
    }
    if r.ransomware_suspected {
        hd_client::say!(
            "  WARNING: changes in this folder look like encryption (ransomware?); every \
             change and deletion is held back. If you did not expect this, disconnect this \
             computer and use `homedrive rewind` or the web UI's Rewind to put things back"
        );
    }
    if let Some(n) = r.held_changes {
        hd_client::say!(
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
        hd_client::say!(
            "  held back {n} deletion(s); if they are intended, run `homedrive confirm`"
        );
    }
    for p in &r.repaired_local {
        hd_client::say!(
            "  {p} was damaged on this computer's disk and was replaced with the server's \
             copy; the damaged copy is in .homedrive/damaged"
        );
    }
    if r.verified_all {
        report!("  checked every file against what was synced");
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

fn restore(args: &[String]) -> Result<()> {
    let usage = "usage: homedrive restore PATH --to DIR";
    let path = args.get(2).filter(|a| !a.starts_with("--")).ok_or_else(|| Error::new(usage))?;
    let to = PathBuf::from(arg_value(args, "--to").ok_or_else(|| Error::new(usage))?);
    let to = std::path::absolute(to)?;
    let cfg = Config::load(&config::config_dir()?)?;
    if cfg.folders.iter().any(|f| to.starts_with(&f.local)) {
        return Err(Error::new(
            "restore into a directory outside the synced folders, so the restore is not synced \
             back",
        ));
    }
    let mut manifest = to.clone().into_os_string();
    manifest.push(".sha256");
    let manifest = PathBuf::from(manifest);
    let r =
        hd_client::restore::restore(&mut remote(&cfg)?, path.trim_matches('/'), &to, &manifest)?;
    println!(
        "restored {} file(s), {} bytes, to {}, each verified; the manifest is {}",
        r.files,
        r.bytes,
        to.display(),
        manifest.display()
    );
    Ok(())
}

fn check_files(args: &[String]) -> Result<()> {
    let usage = "usage: homedrive check-files DIR MANIFEST";
    let dir = PathBuf::from(args.get(2).ok_or_else(|| Error::new(usage))?);
    let manifest = args.get(3).ok_or_else(|| Error::new(usage))?;
    let text = hd_common::fsio::read_text(manifest, 1 << 30)?
        .ok_or_else(|| Error::new(format!("{manifest} does not exist")))?;
    let r = hd_client::restore::check_files(&dir, &text)?;
    for p in &r.missing {
        println!("MISSING {p}");
    }
    for p in &r.different {
        println!("DIFFERENT {p}");
    }
    println!(
        "{} file(s) match; {} missing, {} different",
        r.matched,
        r.missing.len(),
        r.different.len()
    );
    if r.is_clean() { Ok(()) } else { Err(Error::new("the files do not match the manifest")) }
}

fn backup_store(args: &[String]) -> Result<()> {
    let dir =
        PathBuf::from(args.get(2).ok_or_else(|| Error::new("usage: homedrive backup-store DIR"))?);
    let cfg = load_config()?;
    let dir = std::path::absolute(dir)?;
    if cfg.folders.iter().any(|f| dir.starts_with(&f.local) || f.local.starts_with(&dir)) {
        return Err(Error::new("keep the store copy outside the synced folders"));
    }
    let mut remote = remote(&cfg)?;
    let keys = if hd_client::copy::key_params(&dir)?.is_some() {
        Some(copy_keys(&dir)?)
    } else if args.iter().any(|a| a == "--encrypt") {
        let pass = read_secret("HOMEDRIVE_COPY_PASSPHRASE", "New passphrase for the copy")?;
        if std::env::var("HOMEDRIVE_COPY_PASSPHRASE").is_err()
            && read_secret("HOMEDRIVE_COPY_PASSPHRASE", "The same passphrase again")? != pass
        {
            return Err(Error::new("the passphrases differ; nothing was changed"));
        }
        let keys = hd_client::copy::start_encrypted(&dir, &pass)?;
        println!(
            "{} is an encrypted copy. Keep the passphrase somewhere other than the copy: without \
             it the copy cannot be read.",
            dir.display()
        );
        Some(keys)
    } else {
        None
    };
    let result = hd_client::copy::backup_store(&mut remote, &dir, keys.as_ref());
    let device = hd_common::fsio::read_text("/etc/hostname", 256)
        .ok()
        .flatten()
        .map(|h| h.trim().to_owned())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "a client".into());
    match result {
        Ok(r) => {
            println!(
                "{}: {} object(s) fetched ({} bytes); the copy holds {} object(s) and {} metadata \
                 file(s)",
                dir.display(),
                r.fetched,
                r.bytes,
                r.objects,
                r.meta_files
            );
            if let Some(g) = &r.generation {
                println!(
                    "the metadata it replaced is kept as generation {g}; open the copy as it was \
                     then with --generation {g}"
                );
            }
            let message = format!("copied to {device}: {} new object(s)", r.fetched);
            if let Err(e) = remote.backup_report("client-copy", true, &message) {
                eprintln!("homedrive: the copy is done, but reporting it failed: {e}");
            }
            Ok(())
        }
        Err(e) => {
            let _ = remote.backup_report("client-copy", false, &format!("on {device}: {e}"));
            Err(e)
        }
    }
}

/// The keys of the encrypted copy at `dir`, from its passphrase.
fn copy_keys(dir: &std::path::Path) -> Result<hd_store::sealed::Keys> {
    let params = hd_client::copy::key_params(dir)?
        .ok_or_else(|| Error::new(format!("{} is not an encrypted copy", dir.display())))?;
    let pass = read_secret("HOMEDRIVE_COPY_PASSPHRASE", "Passphrase for the copy")?;
    hd_store::sealed::Keys::open(&pass, &params)
}

fn store_copy_check(args: &[String]) -> Result<()> {
    let usage = "usage: homedrive store-copy-check DIR [--generation G]";
    let dir = PathBuf::from(
        args.get(2).filter(|a| !a.starts_with("--")).ok_or_else(|| Error::new(usage))?,
    );
    let generation = arg_value(args, "--generation");
    let earlier = hd_client::copy::generations(&dir)?;
    if let (None, Some(oldest)) = (&generation, earlier.first()) {
        println!(
            "{} earlier generation(s), from {oldest}; check one with --generation",
            earlier.len()
        );
    }
    if hd_client::copy::key_params(&dir)?.is_some() {
        let keys = copy_keys(&dir)?;
        let r = hd_client::copy::open_sealed(&dir, &keys, None, generation.as_deref())?;
        println!(
            "{} file(s) authenticate under the passphrase, {} object(s) intact. For a check that \
             every version can be read back, decrypt it (store-copy-decrypt) and check the plain \
             copy.",
            r.files, r.objects
        );
        return Ok(());
    }
    let store = hd_client::copy::open_copy(&dir, generation.as_deref())?;
    let r = store.fsck(true)?;
    for p in &r.problems {
        println!("PROBLEM {p}");
    }
    println!("{} version(s) read back", r.versions);
    if r.problems.is_empty() {
        println!("clean");
        Ok(())
    } else {
        Err(Error::new(format!("{} damaged version(s) in the copy", r.problems.len())))
    }
}

fn store_copy_restore(args: &[String]) -> Result<()> {
    let usage =
        "usage: homedrive store-copy-restore DIR --user U --to OUT [--path P] [--generation G]";
    let dir = PathBuf::from(
        args.get(2).filter(|a| !a.starts_with("--")).ok_or_else(|| Error::new(usage))?,
    );
    let user = arg_value(args, "--user").ok_or_else(|| Error::new(usage))?;
    let to = PathBuf::from(arg_value(args, "--to").ok_or_else(|| Error::new(usage))?);
    let path = arg_value(args, "--path").unwrap_or_default().trim_matches('/').to_owned();
    let mut manifest = to.clone().into_os_string();
    manifest.push(".sha256");
    if hd_client::copy::key_params(&dir)?.is_some() {
        return Err(Error::new(
            "this copy is encrypted: open it first with `homedrive store-copy-decrypt DIR --to \
             PLAIN`, then restore from PLAIN",
        ));
    }
    let store = hd_client::copy::open_copy(&dir, arg_value(args, "--generation").as_deref())?;
    let r = hd_store::restore::restore_tree(&store, &user, &path, &to, &PathBuf::from(&manifest))?;
    println!(
        "restored {} file(s), {} bytes, to {}, each verified; the manifest is {}",
        r.files,
        r.bytes,
        to.display(),
        PathBuf::from(manifest).display()
    );
    Ok(())
}

fn store_copy_decrypt(args: &[String]) -> Result<()> {
    let usage = "usage: homedrive store-copy-decrypt DIR --to PLAIN [--generation G]";
    let dir = PathBuf::from(
        args.get(2).filter(|a| !a.starts_with("--")).ok_or_else(|| Error::new(usage))?,
    );
    let to = PathBuf::from(arg_value(args, "--to").ok_or_else(|| Error::new(usage))?);
    let keys = copy_keys(&dir)?;
    let generation = arg_value(args, "--generation");
    let r = hd_client::copy::open_sealed(&dir, &keys, Some(&to), generation.as_deref())?;
    println!(
        "opened {} file(s) ({} object(s), each verified) into {}; check it with `homedrive \
         store-copy-check {}`",
        r.files,
        r.objects,
        to.display(),
        to.display()
    );
    Ok(())
}

fn decrypt_file(args: &[String]) -> Result<()> {
    let usage = "usage: homedrive decrypt-file IN --to OUT";
    let input = PathBuf::from(
        args.get(2).filter(|a| !a.starts_with("--")).ok_or_else(|| Error::new(usage))?,
    );
    let to = PathBuf::from(arg_value(args, "--to").ok_or_else(|| Error::new(usage))?);
    let mut file = hd_common::fsio::open_nofollow(&input)?;
    let params = hd_store::sealed::read_standalone_head(&mut file)?;
    let pass = read_secret("HOMEDRIVE_COPY_PASSPHRASE", "Passphrase for the download")?;
    let keys = hd_store::sealed::Keys::open(&pass, &params)?;
    let to = std::path::absolute(&to)?;
    let parent = to.parent().ok_or_else(|| Error::new("no parent folder"))?;
    // Staged beside the target: nothing takes its name unless every
    // segment authenticated, to the end.
    let mut staged = hd_common::fsio::Staged::create_in(parent, ".homedrive-decrypt-")?;
    let label = keys.sealed_name(hd_store::sealed::STANDALONE_NAME)?;
    hd_store::sealed::open(&mut file, &keys, &label, &mut staged)?;
    staged.finish(None, 0o600)?;
    staged.commit_new(&to)?;
    println!("decrypted to {}; it unpacks with tar into a store copy", to.display());
    Ok(())
}

/// Syncs what is configured, and serves the GUI and the tray icon, until
/// stopped. With nothing configured yet it waits for the GUI's wizard.
fn daemon(args: &[String], open_browser: bool) -> Result<()> {
    let dir = config::config_dir()?;
    let with_gui = !args.iter().any(|a| a == "--no-gui");
    if with_gui && gui::running_url(&dir).is_some() {
        return Err(Error::new("homedrive is already running; `homedrive gui` shows it"));
    }
    // Started at sign-in, a console is only a window in the way.
    #[cfg(windows)]
    hd_sys::windows::leave_own_console(&config::daemon_log()?);
    // Before any thread starts, so that they all run this way: a sync must
    // not cost a game a frame. A sync that cannot do this still syncs.
    match hd_sys::background::enter() {
        Ok(()) if hd_sys::background::active() => {
            hd_client::say!("homedrive: running behind everything else on this computer");
        }
        Ok(()) => hd_client::say!("homedrive: could not confirm running in the background"),
        Err(e) => hd_client::say!("homedrive: could not run in the background: {e}"),
    }
    if let Err(e) = hd_client::autostart::refresh() {
        hd_client::say!("homedrive: could not update starting at sign-in: {e}");
    }
    let service = Arc::new(Service::new(print_report));
    if with_gui {
        match Gui::start(dir.clone(), Arc::clone(&service)) {
            Ok(url) => {
                if open_browser {
                    show(&url);
                }
                let quit = || {
                    hd_client::tray::remove();
                    std::process::exit(0);
                };
                hd_client::tray::start(Arc::clone(&service), move || show(&url), quit);
            }
            // Syncing does not depend on the GUI.
            Err(e) => hd_client::say!("homedrive: the GUI did not start: {e}"),
        }
    }
    if let Ok(cfg) = Config::load(&dir) {
        cfg.check_folders()?;
        if !cfg.folders.is_empty() {
            service.start_health(&cfg)?;
        }
        for f in &cfg.folders {
            if !service.start_folder(&cfg, f)? {
                return Err(Error::new(format!(
                    "{} is already being synced by another homedrive process; is the daemon \
                     running already?",
                    f.local.display()
                )));
            }
        }
    }
    loop {
        std::thread::park();
    }
}

/// Opens the GUI in the browser, or says where it is.
fn show(url: &str) {
    if std::env::var_os("HOMEDRIVE_NO_BROWSER").is_some() {
        hd_client::say!("homedrive: asked to open the GUI");
        return;
    }
    #[cfg(target_os = "linux")]
    let opened = hd_client::notify::dbus::open_uri(url);
    #[cfg(windows)]
    let opened = hd_sys::windows::open_url(url).map_err(Error::from);
    if let Err(e) = opened {
        hd_client::say!("homedrive: could not open a browser ({e}); open this address:\n{url}");
    }
}

/// The GUI: brings up the one already running, or starts the daemon with it.
fn gui(args: &[String]) -> Result<()> {
    if let Some(url) = gui::running_url(&config::config_dir()?) {
        show(&url);
        return Ok(());
    }
    daemon(args, true)
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
    #[cfg(windows)]
    {
        hd_sys::windows::notify::show(&notice.title, &notice.body, notice.urgent)?;
        // The balloon is shown from a thread; give it time before exiting.
        std::thread::sleep(std::time::Duration::from_secs(10));
        println!("Sent the notification.");
        Ok(())
    }
}

/// Ends the way a bug would, to prove the reason is kept.
#[allow(clippy::panic)]
fn test_crash() -> Result<()> {
    panic!("a test of the crash log")
}

fn main() -> ExitCode {
    hd_client::crash::install();
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("login") => login(&args),
        Some("add-folder") => add_folder(&args),
        Some("sync") => sync(&args),
        Some("confirm") => confirm(),
        Some("verify") => verify(),
        Some("rewind") => rewind(&args),
        Some("restore") => restore(&args),
        Some("check-files") => check_files(&args),
        Some("backup-store") => backup_store(&args),
        Some("store-copy-check") => store_copy_check(&args),
        Some("store-copy-restore") => store_copy_restore(&args),
        Some("store-copy-decrypt") => store_copy_decrypt(&args),
        Some("decrypt-file") => decrypt_file(&args),
        Some("daemon") => daemon(&args, false),
        Some("gui") | None => gui(&args),
        Some("test-crash-log") => test_crash(),
        Some("status") => status(),
        Some("test-notification") => test_notification(),
        Some("version" | "--version") => {
            println!("homedrive {}", hd_common::VERSION);
            Ok(())
        }
        _ => Err(Error::new(
            "usage: homedrive \
             [login|add-folder|sync|confirm|verify|rewind|restore|check-files|backup-store|\
             store-copy-check|store-copy-decrypt|store-copy-restore|decrypt-file|gui|daemon|status|\
             test-notification|version]",
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
