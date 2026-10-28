//! The homedrive server entry point.
//!
//! ```text
//! hd-server [serve]      Run the server (the container's command); it
//!                        refuses to start unless HD_DATA_DIR is a store
//! hd-server init         Make HD_DATA_DIR a new, empty store (it must be
//!                        empty; this never adopts an existing tree)
//! hd-server healthcheck  Exit 0 when the local server answers /healthz
//! hd-server version      Print the version
//!
//! While the server runs (through its admin socket):
//! hd-server import --user U --dest PATH [--absent] < FILE
//!                        Store standard input as a new version of PATH
//! hd-server import-tree --user U --src DIR [--dest PATH] [--versions DIR]
//!                        Load a plain directory tree, with old versions
//!                        named <file>.v<unix seconds> from --versions;
//!                        prints "sha256 size path" for each file
//! hd-server verify-tree --user U --src DIR [--dest PATH] [--accept-skipped]
//!                        Check every file under DIR is stored, byte for
//!                        byte; exits 1 on any difference, and on any file
//!                        skipped (not stored at all) unless
//!                        --accept-skipped says the listed ones may go
//!
//! Maintenance (through the socket if the server runs, else directly):
//! hd-server fsck [--deep] [--repair-tail]
//!                        Check that every version can be read back;
//!                        --deep reads and hashes every chunk; exits 1 on
//!                        any problem. --repair-tail sets a damaged final
//!                        journal record aside in quarantine.
//! hd-server gc [--dry-run]
//!                        Collect unreferenced objects (48 h grace, 7 day
//!                        hold in gc-trash/)
//! hd-server scrub        Re-verify every object and metadata file;
//!                        quarantine damage
//! hd-server repair [--from DIR]...
//!                        Replace every missing, damaged or unreadable
//!                        object with a verified copy from another copy of
//!                        the store (a mounted backup) or from quarantine;
//!                        exits 1 if any version is still damaged
//! hd-server checkpoint   Write a metadata snapshot now
//!
//! Backups and restores:
//! hd-server restore-tree --user U --to DIR [--path P] [--manifest FILE]
//!                        Write U's current files (under P) to DIR as plain
//!                        files, each verified, and a sha256sum manifest
//!                        (default DIR.sha256). Runs on a store the server
//!                        is not using: a backup extracted with borg, or
//!                        with the server stopped
//! hd-server restore-drill --to DIR
//!                        On a store extracted from a backup: read every
//!                        version back (fsck --deep) and restore every
//!                        drive to DIR/<user>/ with DIR/<user>.sha256;
//!                        prints the time the backup was taken; exits 1
//!                        on any problem
//! hd-server drill-compare --user U --taken-ms T < MANIFEST
//!                        (running server) Check a restored backup's
//!                        manifest against the live drive: every file the
//!                        drive had at T is in it, and nothing unknown is;
//!                        exits 1 otherwise
//! hd-server report-backup --kind K (--ok | --failed) [--message TEXT]
//!                        (running server) Record a backup or drill run;
//!                        failures and silence reach the admins
//! ```
//!
//! Configuration comes from the environment; see `hd_server::config`.

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::ExitCode;
use std::sync::Arc;

use hd_api::{J, s};
use hd_common::{Error, Result};
use hd_server::config::Config;
use hd_server::{App, admin};

fn serve() -> Result<()> {
    // As PID 1 in a container an unhandled SIGTERM is ignored, so `podman
    // stop` would wait and then SIGKILL. The signals are blocked before any
    // thread starts, and one thread takes them and exits. Every write the
    // server acknowledges is already durable, so stopping needs no flush.
    let signals = hd_sys::posix::TerminationSignals::new()?;
    signals.block()?;
    let config = Config::from_env()?;
    let listen = config.listen;
    let app = Arc::new(App::open(config)?);
    eprintln!("hd-server: opened store {} at {}", app.store.id(), app.store.root().display());
    hd_server::maintenance::start(&app)?;
    hd_server::admin::start(&app)?;
    hd_server::export::start(&app)?;
    std::thread::Builder::new()
        .name("signals".to_owned())
        .stack_size(64 * 1024)
        .spawn(move || {
            if let Ok(sig) = signals.wait() {
                eprintln!("hd-server: signal {sig}; stopping");
                std::process::exit(0);
            }
        })
        .map_err(|e| Error::new(format!("cannot start the signal thread: {e}")))?;
    let listener = TcpListener::bind(listen)
        .map_err(|e| Error::new(format!("cannot listen on {listen}: {e}")))?;
    eprintln!("hd-server {} listening on {listen}", hd_common::VERSION);
    hd_http::serve(&listener, &app);
    Ok(())
}

fn open_for_maintenance(repair_tail: bool) -> Result<hd_store::Store> {
    let config = Config::from_env()?;
    let mut options = hd_store::StoreOptions { min_free: config.min_free, ..Default::default() };
    options.meta.repair_tail = repair_tail;
    let store = hd_store::Store::open(&config.data_dir, &options)?;
    let r = store.recovery();
    println!(
        "opened store {}: {} journal record(s) replayed, {} torn byte(s) and {} repaired byte(s) \
         set aside, {} bad snapshot(s)",
        store.id(),
        r.records_replayed,
        r.torn_bytes,
        r.repaired_bytes,
        r.bad_snapshots.len()
    );
    Ok(store)
}

fn flags(allowed: &[&str]) -> Result<Vec<String>> {
    let given: Vec<String> = std::env::args().skip(2).collect();
    for f in &given {
        if !allowed.contains(&f.as_str()) {
            return Err(Error::new(format!("unknown option {f}")));
        }
    }
    Ok(given)
}

fn arg(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn required(name: &str) -> Result<String> {
    arg(name).ok_or_else(|| Error::new(format!("{name} is required")))
}

fn import() -> Result<()> {
    let config = Config::from_env()?;
    let absent = std::env::args().any(|a| a == "--absent");
    let req = J::O(vec![
        ("cmd", s("import")),
        ("user", s(required("--user")?)),
        ("path", s(required("--dest")?.trim_matches('/'))),
        ("absent", J::Bool(absent)),
    ]);
    let mut stdin = std::io::stdin().lock();
    let v = admin::call(&config.data_dir, &req, Some(&mut stdin))?;
    println!(
        "stored {} as version {}{}",
        hd_api::get_str(&v, "path")?,
        hd_api::get_u64(&v, "version")?,
        if hd_api::get_bool(&v, "unchanged")? { " (unchanged)" } else { "" }
    );
    Ok(())
}

fn import_tree() -> Result<()> {
    let config = Config::from_env()?;
    let user = required("--user")?;
    let src = std::path::PathBuf::from(required("--src")?);
    let dest = arg("--dest").unwrap_or_default().trim_matches('/').to_owned();
    let versions = arg("--versions").map(std::path::PathBuf::from);
    let mut out = std::io::stdout().lock();
    let r =
        admin::import_tree(&config.data_dir, &user, &src, &dest, versions.as_deref(), &mut out)?;
    eprintln!(
        "imported {} file(s) and {} old version(s); {} already stored; {} skipped",
        r.imported,
        r.versions,
        r.unchanged,
        r.skipped.len()
    );
    for p in &r.skipped {
        eprintln!("SKIPPED {p} (not a regular file, or not a valid name)");
    }
    Ok(())
}

fn verify_tree() -> Result<()> {
    let config = Config::from_env()?;
    let user = required("--user")?;
    let src = std::path::PathBuf::from(required("--src")?);
    let dest = arg("--dest").unwrap_or_default().trim_matches('/').to_owned();
    let r = admin::verify_tree(&config.data_dir, &user, &src, &dest)?;
    for p in &r.missing {
        println!("MISSING {p}");
    }
    for p in &r.mismatched {
        println!("DIFFERENT {p}");
    }
    for p in &r.skipped {
        println!("SKIPPED {p}");
    }
    println!(
        "{} file(s) checked: {} missing, {} different, {} skipped",
        r.checked,
        r.missing.len(),
        r.mismatched.len(),
        r.skipped.len()
    );
    let accept = std::env::args().any(|a| a == "--accept-skipped");
    if r.is_clean() || (accept && r.is_clean_accepting_skipped()) {
        Ok(())
    } else if r.is_clean_accepting_skipped() {
        Err(Error::new(
            "some files were skipped and exist only in the source; rename or copy them so they \
             can be stored, or rerun with --accept-skipped once you have saved them elsewhere",
        ))
    } else {
        Err(Error::new("the tree is not fully stored"))
    }
}

/// Runs a maintenance command through the running server, if there is
/// one; `None` means no server answered.
fn via_socket(req: &J) -> Result<Option<hd_common::json::Value>> {
    let config = Config::from_env()?;
    if !admin::server_running(&config.data_dir) {
        return Ok(None);
    }
    admin::call(&config.data_dir, req, None).map(Some)
}

fn fsck() -> Result<()> {
    let given = flags(&["--deep", "--repair-tail"])?;
    if !given.iter().any(|f| f == "--repair-tail")
        && let Some(v) = via_socket(&J::O(vec![
            ("cmd", s("fsck")),
            ("deep", J::Bool(given.iter().any(|f| f == "--deep"))),
        ]))?
    {
        let problems = hd_api::get_array(&v, "problems")?;
        for p in problems {
            println!("PROBLEM {}", p.as_str().unwrap_or(""));
        }
        println!("{} version(s) checked", hd_api::get_u64(&v, "versions")?);
        return if problems.is_empty() {
            println!("clean");
            Ok(())
        } else {
            Err(Error::new(format!("{} damaged version(s)", problems.len())))
        };
    }
    let store = open_for_maintenance(given.iter().any(|f| f == "--repair-tail"))?;
    let deep = given.iter().any(|f| f == "--deep");
    let report = store.fsck(deep)?;
    println!(
        "{} version(s), {} manifest(s), {} chunk reference(s) checked{}",
        report.versions,
        report.manifests,
        report.chunks,
        if deep { " (deep)" } else { "" }
    );
    for p in &report.problems {
        println!("PROBLEM {p}");
    }
    if report.is_clean() {
        println!("clean");
        Ok(())
    } else {
        Err(Error::new(format!("{} damaged version(s)", report.problems.len())))
    }
}

fn gc() -> Result<()> {
    let given = flags(&["--dry-run"])?;
    if let Some(v) = via_socket(&J::O(vec![
        ("cmd", s("gc")),
        ("dry_run", J::Bool(given.iter().any(|f| f == "--dry-run"))),
    ]))? {
        println!("{}", hd_api::get_str(&v, "report")?);
        return Ok(());
    }
    let store = open_for_maintenance(false)?;
    let options = hd_store::gc::GcOptions {
        dry_run: given.iter().any(|f| f == "--dry-run"),
        ..Default::default()
    };
    let r = store.collect_garbage(hd_common::timefmt::unix_ms(), &options)?;
    println!(
        "{}live {}, young {}, moved to gc-trash {} ({} bytes), deleted {} ({} bytes), restored {}",
        if options.dry_run { "[dry run] " } else { "" },
        r.live,
        r.young,
        r.moved,
        r.moved_bytes,
        r.deleted,
        r.deleted_bytes,
        r.restored
    );
    Ok(())
}

fn scrub() -> Result<()> {
    flags(&[])?;
    if let Some(v) = via_socket(&J::O(vec![("cmd", s("scrub"))]))? {
        let q = hd_api::get_u64(&v, "quarantined")?;
        println!("{} object(s) verified, {q} quarantined", hd_api::get_u64(&v, "checked")?);
        return if q == 0 {
            Ok(())
        } else {
            Err(Error::new("damaged objects were found; run fsck"))
        };
    }
    let store = open_for_maintenance(false)?;
    let r = store.scrub(0, &std::sync::atomic::AtomicBool::new(false))?;
    println!("{} object(s), {} bytes verified", r.checked, r.bytes);
    for (kind, id) in &r.quarantined {
        println!("QUARANTINED {} {id}", kind.name());
    }
    for f in &r.failed {
        println!("UNREADABLE {f}");
    }
    for m in &r.metadata_damaged {
        println!("METADATA REPAIRED {m}");
    }
    if r.quarantined.is_empty() && r.failed.is_empty() {
        Ok(())
    } else {
        Err(Error::new("damaged objects were found; run fsck to see which files they affect"))
    }
}

fn repair() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(2).collect();
    let mut sources = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match (a.as_str(), it.next()) {
            ("--from", Some(dir)) => sources.push(std::path::PathBuf::from(dir)),
            _ => return Err(Error::new("usage: hd-server repair [--from DIR]...")),
        }
    }
    let still: Vec<String> = if let Some(v) = via_socket(&J::O(vec![
        ("cmd", s("repair")),
        ("from", J::A(sources.iter().map(|p| s(p.display().to_string())).collect())),
    ]))? {
        println!(
            "{} version(s) checked, {} object(s) restored",
            hd_api::get_u64(&v, "versions")?,
            hd_api::get_u64(&v, "restored")?
        );
        hd_api::get_array(&v, "still_damaged")?
            .iter()
            .map(|p| p.as_str().unwrap_or("").to_owned())
            .collect()
    } else {
        let store = open_for_maintenance(false)?;
        let r = store.repair_from(&sources)?;
        println!("{} version(s) checked, {} object(s) restored", r.versions, r.restored);
        r.still_damaged
    };
    for p in &still {
        println!("STILL DAMAGED {p}");
    }
    if still.is_empty() {
        println!("every version reads back intact");
        Ok(())
    } else {
        Err(Error::new(format!(
            "{} version(s) have no good copy in the sources given",
            still.len()
        )))
    }
}

fn restore_tree() -> Result<()> {
    let user = required("--user")?;
    let to = std::path::PathBuf::from(required("--to")?);
    let path = arg("--path").unwrap_or_default().trim_matches('/').to_owned();
    let manifest = arg("--manifest").map_or_else(
        || {
            let mut m = to.clone().into_os_string();
            m.push(".sha256");
            std::path::PathBuf::from(m)
        },
        std::path::PathBuf::from,
    );
    let store = open_for_maintenance(false)?;
    let r = hd_server::drill::restore_tree(&store, &user, &path, &to, &manifest)?;
    println!(
        "restored {} file(s), {} bytes, to {}; check them anywhere with: sha256sum -c {}",
        r.files,
        r.bytes,
        to.display(),
        manifest.display()
    );
    Ok(())
}

fn restore_drill() -> Result<()> {
    let to = std::path::PathBuf::from(required("--to")?);
    let store = open_for_maintenance(false)?;
    let r = hd_server::drill::drill(&store, &to)?;
    for p in &r.problems {
        println!("PROBLEM {p}");
    }
    for (user, files, bytes) in &r.users {
        println!("USER {user} {files} {bytes}");
    }
    println!("TAKEN_MS {}", r.taken_ms);
    println!("{}", hd_server::drill::summary(&r));
    if r.problems.is_empty() {
        Ok(())
    } else {
        Err(Error::new(format!("{} problem(s) in the backup", r.problems.len())))
    }
}

fn drill_compare() -> Result<()> {
    let config = Config::from_env()?;
    let user = required("--user")?;
    let taken_ms: i64 = required("--taken-ms")?
        .parse()
        .map_err(|_| Error::new("--taken-ms is a time in Unix milliseconds"))?;
    let req =
        J::O(vec![("cmd", s("drill-compare")), ("user", s(&*user)), ("taken_ms", J::I(taken_ms))]);
    let mut stdin = std::io::stdin().lock();
    let v = admin::call(&config.data_dir, &req, Some(&mut stdin))?;
    let missing = hd_api::get_array(&v, "missing")?;
    let unknown = hd_api::get_array(&v, "unknown")?;
    for p in missing {
        println!("MISSING {}", p.as_str().unwrap_or(""));
    }
    for p in unknown {
        println!("UNKNOWN {}", p.as_str().unwrap_or(""));
    }
    println!(
        "{user}: {} file(s) in the backup; {} the drive had are missing, {} unknown",
        hd_api::get_u64(&v, "files")?,
        missing.len(),
        unknown.len()
    );
    if missing.is_empty() && unknown.is_empty() {
        Ok(())
    } else {
        Err(Error::new(format!("{user}'s backup does not match the drive")))
    }
}

fn report_backup() -> Result<()> {
    let config = Config::from_env()?;
    let good = std::env::args().any(|a| a == "--ok");
    let failed = std::env::args().any(|a| a == "--failed");
    if good == failed {
        return Err(Error::new("give one of --ok and --failed"));
    }
    let req = J::O(vec![
        ("cmd", s("report")),
        ("kind", s(required("--kind")?)),
        ("ok", J::Bool(good)),
        ("message", s(arg("--message").unwrap_or_default())),
    ]);
    admin::call(&config.data_dir, &req, None)?;
    Ok(())
}

fn checkpoint() -> Result<()> {
    flags(&[])?;
    if let Some(v) = via_socket(&J::O(vec![("cmd", s("checkpoint"))]))? {
        println!("snapshot {} written", hd_api::get_u64(&v, "seq")?);
        return Ok(());
    }
    let store = open_for_maintenance(false)?;
    println!("snapshot {} written", store.checkpoint()?);
    Ok(())
}

fn init() -> Result<()> {
    let config = Config::from_env()?;
    if hd_store::is_store(&config.data_dir) {
        return Err(Error::new(format!(
            "{} is already a store; nothing was changed",
            config.data_dir.display()
        )));
    }
    let id = hd_store::Store::init(&config.data_dir)?;
    eprintln!("hd-server: created store {id} at {}", config.data_dir.display());
    Ok(())
}

/// GET /healthz on the configured listener (loopback for a wildcard).
fn healthcheck() -> Result<()> {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
    use std::time::Duration;
    let config = Config::from_env()?;
    let mut addr = config.listen;
    if addr.ip().is_unspecified() {
        addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port());
    }
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
    let mut head = [0_u8; 12];
    stream.read_exact(&mut head)?;
    if &head == b"HTTP/1.1 200" { Ok(()) } else { Err(Error::new("unhealthy")) }
}

fn main() -> ExitCode {
    let command = std::env::args().nth(1).unwrap_or_else(|| "serve".to_owned());
    let result = match command.as_str() {
        "serve" => serve(),
        "init" => init(),
        "import" => import(),
        "import-tree" => import_tree(),
        "verify-tree" => verify_tree(),
        "fsck" => fsck(),
        "gc" => gc(),
        "scrub" => scrub(),
        "repair" => repair(),
        "checkpoint" => checkpoint(),
        "restore-tree" => restore_tree(),
        "restore-drill" => restore_drill(),
        "drill-compare" => drill_compare(),
        "report-backup" => report_backup(),
        "healthcheck" => healthcheck(),
        "version" | "--version" => {
            println!("hd-server {}", hd_common::VERSION);
            Ok(())
        }
        _ => Err(Error::new(
            "usage: hd-server [serve|init|import|import-tree|verify-tree|fsck|gc|scrub|repair|checkpoint|restore-tree|restore-drill|drill-compare|report-backup|healthcheck|version]",
        )),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hd-server: {e}");
            ExitCode::FAILURE
        }
    }
}
