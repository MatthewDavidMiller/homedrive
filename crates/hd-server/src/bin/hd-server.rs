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
//! Maintenance, with the server stopped (the store admits one process):
//! hd-server fsck [--deep] [--repair-tail]
//!                        Check that every version can be read back;
//!                        --deep reads and hashes every chunk; exits 1 on
//!                        any problem. --repair-tail sets a damaged final
//!                        journal record aside in quarantine.
//! hd-server gc [--dry-run]
//!                        Collect unreferenced objects (48 h grace, 7 day
//!                        hold in gc-trash/)
//! hd-server scrub        Re-verify every object; quarantine damage
//! hd-server checkpoint   Write a metadata snapshot now
//! ```
//!
//! Configuration comes from the environment; see `hd_server::config`.

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::ExitCode;
use std::sync::Arc;

use hd_common::{Error, Result};
use hd_server::App;
use hd_server::config::Config;

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

fn fsck() -> Result<()> {
    let given = flags(&["--deep", "--repair-tail"])?;
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
    let store = open_for_maintenance(false)?;
    let r = store.scrub(0, &std::sync::atomic::AtomicBool::new(false))?;
    println!("{} object(s), {} bytes verified", r.checked, r.bytes);
    for (kind, id) in &r.quarantined {
        println!("QUARANTINED {} {id}", kind.name());
    }
    if r.quarantined.is_empty() {
        Ok(())
    } else {
        Err(Error::new("damaged objects were found; run fsck to see which files they affect"))
    }
}

fn checkpoint() -> Result<()> {
    flags(&[])?;
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
        "fsck" => fsck(),
        "gc" => gc(),
        "scrub" => scrub(),
        "checkpoint" => checkpoint(),
        "healthcheck" => healthcheck(),
        "version" | "--version" => {
            println!("hd-server {}", hd_common::VERSION);
            Ok(())
        }
        _ => Err(Error::new(
            "usage: hd-server [serve|init|fsck|gc|scrub|checkpoint|healthcheck|version]",
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
