//! Interoperability with a real WebDAV client: rclone, from the toolbox.
//!
//! The toolbox sets HD_REQUIRE_RCLONE=1, so there a missing rclone fails
//! the test rather than skipping it.

#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

mod common;

use std::fs;
use std::path::Path;
use std::process::Command;

use common::{ALICE_PW, basic, request, start};

fn rclone_available() -> bool {
    let found = Command::new("rclone").arg("version").output().is_ok_and(|o| o.status.success());
    assert!(
        found || std::env::var("HD_REQUIRE_RCLONE").ok().is_none_or(|v| v != "1"),
        "rclone is required here (HD_REQUIRE_RCLONE=1) but is not installed"
    );
    found
}

struct Remote {
    url: String,
    pass: String,
    config: std::path::PathBuf,
}

impl Remote {
    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new("rclone")
            .args(args)
            .args([
                "--config",
                self.config.to_str().unwrap(),
                "--webdav-url",
                &self.url,
                "--webdav-vendor",
                "other",
                "--webdav-user",
                "alice",
                "--webdav-pass",
                &self.pass,
                "--retries",
                "1",
                "--low-level-retries",
                "1",
            ])
            .output()
            .unwrap()
    }

    fn ok(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "rclone {args:?} failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

fn write(path: &Path, data: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, data).unwrap();
}

#[test]
fn rclone_copies_syncs_checks_and_moves() {
    if !rclone_available() {
        eprintln!("rclone not installed; skipping");
        return;
    }
    let s = start("rclone");
    // rclone stores a device token as its password, never the account's.
    let r = request(
        s.addr,
        "POST",
        "/api/v1/devices",
        &[("Authorization", &basic("alice", ALICE_PW))],
        br#"{"name":"rclone"}"#,
    );
    let token = hd_api::DeviceToken::from_json(&r.json()).unwrap().token;
    let obscured = Command::new("rclone").args(["obscure", &token]).output().unwrap();
    let remote = Remote {
        url: format!("http://{}/dav/alice", s.addr),
        pass: String::from_utf8(obscured.stdout).unwrap().trim().to_owned(),
        config: s.dir.join("rclone.conf"),
    };
    let local = s.dir.join("local");
    let big: Vec<u8> = (0..6_000_000_u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13).to_le_bytes()[0])
        .collect();
    write(&local.join("empty.txt"), b"");
    write(&local.join("notes/hello world.txt"), b"hello\n");
    write(&local.join("notes/ünïcødé ✓.md"), "# title\n".as_bytes());
    write(&local.join("media/big.bin"), &big);
    write(&local.join("a/b/c/deep.txt"), b"deep");

    let src = local.to_str().unwrap();
    remote.ok(&["copy", src, ":webdav:backup"]);
    remote.ok(&["check", src, ":webdav:backup", "--download"]);
    let listing = remote.ok(&["lsf", "-R", ":webdav:backup"]);
    for name in [
        "empty.txt",
        "notes/hello world.txt",
        "notes/ünïcødé ✓.md",
        "media/big.bin",
        "a/b/c/deep.txt",
    ] {
        assert!(listing.lines().any(|l| l == name), "{name} missing from:\n{listing}");
    }

    // Change one file, delete another, add a third; sync makes the remote
    // match, and the old content survives as a version or in the trash.
    write(&local.join("notes/hello world.txt"), b"hello again\n");
    fs::remove_file(local.join("empty.txt")).unwrap();
    write(&local.join("new.txt"), b"new");
    remote.ok(&["sync", src, ":webdav:backup"]);
    remote.ok(&["check", src, ":webdav:backup", "--download"]);
    let versions = s.app.store.read(|st| {
        match &st.user("alice").unwrap().get("backup/notes/hello world.txt").unwrap().node {
            hd_store::model::Node::File { versions, .. } => versions.len(),
            hd_store::model::Node::Dir => 0,
        }
    });
    assert_eq!(versions, 2, "the overwritten text is kept as an old version");
    let trashed = s
        .app
        .store
        .read(|st| st.user("alice").unwrap().trash.values().any(|t| t.path == "backup/empty.txt"));
    assert!(trashed, "the deleted file is in the trash");

    // Server-side moves and copies.
    remote.ok(&["moveto", ":webdav:backup/new.txt", ":webdav:moved/renamed.txt"]);
    remote.ok(&["copyto", ":webdav:backup/media/big.bin", ":webdav:copies/big.bin"]);
    let got = remote.ok(&["cat", ":webdav:moved/renamed.txt"]);
    assert_eq!(got, "new");
    let out = remote.run(&["cat", ":webdav:copies/big.bin"]);
    assert!(out.stdout == big, "copied content differs");
    remote.ok(&["purge", ":webdav:moved"]);
    let listing = remote.ok(&["lsf", ":webdav:"]);
    assert!(!listing.lines().any(|l| l == "moved/"), "{listing}");
    assert!(s.app.store.fsck(true).unwrap().is_clean());
}
