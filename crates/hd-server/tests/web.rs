//! The web UI end to end: sign-in, browsing, upload, history, trash,
//! devices, and the admin page, as a browser drives them.

#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::manual_assert_eq,
    clippy::map_unwrap_or
)]

mod common;

use std::net::SocketAddr;

use common::{ALICE_PW, BOB_PW, Reply, request};

fn cookie(r: &Reply, name: &str) -> String {
    r.head
        .split("\r\n")
        .filter_map(|l| l.strip_prefix("Set-Cookie: "))
        .find_map(|c| c.strip_prefix(&format!("{name}=")))
        .map(|c| c.split(';').next().unwrap().to_owned())
        .unwrap_or_else(|| panic!("no {name} cookie in {}", r.head))
}

fn csrf(r: &Reply) -> String {
    let html = r.text();
    let at =
        html.find("name=\"csrf_token\" value=\"").unwrap_or_else(|| panic!("no token in {html}"))
            + 25;
    html[at..at + html[at..].find('"').unwrap()].to_owned()
}

fn login(addr: SocketAddr, user: &str, pw: &str) -> String {
    let form = request(addr, "GET", "/login", &[], b"");
    let nonce = cookie(&form, "hd_login");
    let token = csrf(&form);
    let body =
        format!("csrf_token={token}&username={user}&password={}", hd_http::percent_encode(pw));
    let r = request(
        addr,
        "POST",
        "/login",
        &[
            ("Cookie", &format!("hd_login={nonce}")),
            ("Content-Type", "application/x-www-form-urlencoded"),
        ],
        body.as_bytes(),
    );
    assert_eq!(r.status, 303, "{}", r.text());
    cookie(&r, "hd_session")
}

fn get(addr: SocketAddr, session: &str, target: &str) -> Reply {
    request(addr, "GET", target, &[("Cookie", &format!("hd_session={session}"))], b"")
}

fn post(addr: SocketAddr, session: &str, target: &str, body: &str) -> Reply {
    request(
        addr,
        "POST",
        target,
        &[
            ("Cookie", &format!("hd_session={session}")),
            ("Content-Type", "application/x-www-form-urlencoded"),
        ],
        body.as_bytes(),
    )
}

fn upload(
    addr: SocketAddr,
    session: &str,
    token: &str,
    dir: &str,
    files: &[(&str, &[u8])],
) -> Reply {
    let mut body = Vec::new();
    let b = "----hdtestboundary";
    body.extend_from_slice(
        format!("--{b}\r\nContent-Disposition: form-data; name=\"csrf_token\"\r\n\r\n{token}\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(
        format!("--{b}\r\nContent-Disposition: form-data; name=\"dir\"\r\n\r\n{dir}\r\n")
            .as_bytes(),
    );
    for (name, data) in files {
        body.extend_from_slice(format!("--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes());
        body.extend_from_slice(data);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{b}--\r\n").as_bytes());
    request(
        addr,
        "POST",
        "/upload",
        &[
            ("Cookie", &format!("hd_session={session}")),
            ("Content-Type", &format!("multipart/form-data; boundary={b}")),
        ],
        &body,
    )
}

#[test]
fn a_browser_session_end_to_end() {
    let s = common::start("web");
    let addr = s.addr;
    assert_eq!(request(addr, "GET", "/", &[], b"").header("Location").as_deref(), Some("/login"));
    assert_eq!(request(addr, "GET", "/files", &[], b"").status, 303);
    assert_eq!(request(addr, "GET", "/static/style.css", &[], b"").status, 200);
    let alice = login(addr, "alice", ALICE_PW);
    let page = get(addr, &alice, "/files");
    assert_eq!(page.status, 200);
    assert!(page.text().contains("This folder is empty."));
    let token = csrf(&page);

    // Upload two files, one of them large, into a new folder.
    assert!(
        post(addr, &alice, "/mkdir", &format!("csrf_token={token}&dir=&name=Photos"))
            .text()
            .contains("Created folder Photos.")
    );
    let big: Vec<u8> = (0..3_000_000_u32).map(|i| (i % 253).to_le_bytes()[0]).collect();
    let r = upload(addr, &alice, &token, "Photos", &[("a.txt", b"first"), ("big.bin", &big)]);
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(r.text().contains("Uploaded a.txt.") && r.text().contains("Uploaded big.bin."));
    let listing = get(addr, &alice, "/files?path=Photos").text();
    assert!(listing.contains(">a.txt</a>") && listing.contains("2.8 MiB"), "{listing}");
    let dl = get(addr, &alice, "/download?path=Photos/big.bin");
    assert!(dl.body == big);
    assert!(dl.header("Content-Disposition").unwrap().contains("big.bin"));

    // A second upload over a.txt keeps history; restoring adds a version.
    upload(addr, &alice, &token, "Photos", &[("a.txt", b"second")]);
    let history = get(addr, &alice, "/versions?path=Photos/a.txt");
    assert!(history.text().contains("current"));
    let v1 =
        s.app.store.read(|st| match &st.user("alice").unwrap().get("Photos/a.txt").unwrap().node {
            hd_store::model::Node::File { versions, .. } => versions[0].id,
            hd_store::model::Node::Dir => 0,
        });
    let r = post(
        addr,
        &alice,
        "/restore-version",
        &format!("csrf_token={token}&path=Photos/a.txt&version={v1}"),
    );
    assert!(r.text().contains("now the newest"), "{}", r.text());
    assert_eq!(get(addr, &alice, "/download?path=Photos/a.txt").body, b"first");

    // Delete to the trash, restore from it.
    let r = post(addr, &alice, "/delete", &format!("csrf_token={token}&path=Photos"));
    assert!(r.text().contains("Moved Photos to the trash."));
    let trash = get(addr, &alice, "/trash").text();
    assert!(trash.contains(">Photos</td>"), "{trash}");
    let id = s.app.store.read(|st| *st.user("alice").unwrap().trash.keys().next().unwrap());
    assert!(
        post(addr, &alice, "/restore", &format!("csrf_token={token}&trash_id={id}"))
            .text()
            .contains("Restored to Photos.")
    );
    assert!(get(addr, &alice, "/download?path=Photos/big.bin").body == big);

    // Moves refuse to replace.
    upload(addr, &alice, &token, "", &[("other.txt", b"o")]);
    let r =
        post(addr, &alice, "/move", &format!("csrf_token={token}&path=other.txt&to=Photos/a.txt"));
    assert!(r.text().contains("already exists"), "{}", r.text());

    // Rewind: a preview first, with a button to carry it out.
    let two_hours_ago = hd_common::timefmt::unix_ms() - 2 * 3_600_000;
    let provenance = hd_store::Provenance {
        device: "laptop".into(),
        mtime_ms: two_hours_ago,
        origin: hd_store::model::Origin::Upload,
        created_ms: Some(two_hours_ago),
        executable: None,
    };
    s.app
        .store
        .write_file("alice", "Old/n.txt", hd_store::Base::Any, &b"before"[..], 1 << 20, &provenance)
        .unwrap();
    upload(addr, &alice, &token, "Old", &[("n.txt", b"after")]);
    let r =
        post(addr, &alice, "/rewind", &format!("csrf_token={token}&dir=Old&amount=1&unit=hours"));
    let html = r.text();
    assert!(html.contains("1 file(s) would get their earlier content"), "{html}");
    assert!(html.contains("Rewind now"), "{html}");
    assert_eq!(get(addr, &alice, "/download?path=Old/n.txt").body, b"after");
    let r = post(
        addr,
        &alice,
        "/rewind",
        &format!("csrf_token={token}&dir=Old&amount=1&unit=hours&apply=1"),
    );
    assert!(r.text().contains("Rewound Old"), "{}", r.text());
    assert_eq!(get(addr, &alice, "/download?path=Old/n.txt").body, b"before");
    let r =
        post(addr, &alice, "/rewind", &format!("csrf_token={token}&dir=Old&amount=0&unit=days"));
    assert!(r.text().contains("from 1 to 3650"));

    // Devices: the token is shown once and works.
    let r = post(addr, &alice, "/devices", &format!("csrf_token={token}&name=phone"));
    let html = r.text();
    let at = html.find("<code>hd1_").unwrap() + 6;
    let device_token = &html[at..at + html[at..].find('<').unwrap()];
    let who = request(
        addr,
        "GET",
        "/api/v1/whoami",
        &[("Authorization", &format!("Bearer {device_token}"))],
        b"",
    );
    assert_eq!(who.status, 200);
    assert!(!get(addr, &alice, "/devices").text().contains(device_token), "shown only once");

    // CSRF and same-origin are enforced.
    assert_eq!(post(addr, &alice, "/mkdir", "csrf_token=wrong&dir=&name=x").status, 403);
    let r = request(
        addr,
        "POST",
        "/mkdir",
        &[
            ("Cookie", &format!("hd_session={alice}")),
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Origin", "https://evil.example"),
            ("Host", "drive.example"),
        ],
        format!("csrf_token={token}&dir=&name=x").as_bytes(),
    );
    assert_eq!(r.status, 403);
    assert_eq!(upload(addr, &alice, "wrong", "", &[("x.txt", b"x")]).status, 403);
    assert!(
        s.app.store.read(|st| st.user("alice").unwrap().get("x.txt").is_none()),
        "nothing stored without a token"
    );

    // The admin page is for admins only.
    assert!(get(addr, &alice, "/admin").text().contains("healthy"));
    let bob = login(addr, "bob", BOB_PW);
    assert_eq!(get(addr, &bob, "/admin").status, 405);
    assert!(!get(addr, &bob, "/files").text().contains("/admin"));
    assert!(
        get(addr, &bob, "/files").text().contains("This folder is empty."),
        "bob sees only his own drive"
    );

    // Logging out ends the session.
    post(addr, &alice, "/logout", &format!("csrf_token={token}"));
    assert_eq!(get(addr, &alice, "/files").status, 303);
    assert!(s.app.store.fsck(true).unwrap().is_clean());
}

fn noise(len: usize, mut seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        out.extend_from_slice(&seed.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Files encrypted through WebDAV (which has no client-side guard) raise
/// an alert: the owner's clients and web UI say so, retention holds the
/// drive, and only a signed-in browser can dismiss it.
#[test]
fn unusual_activity_through_webdav_is_reported_and_holds_retention() {
    let s = common::start("activity");
    let addr = s.addr;
    let dav = |method: &str, path: &str, body: &[u8]| {
        request(addr, method, path, &[("Authorization", &common::basic("alice", ALICE_PW))], body)
    };
    assert_eq!(dav("MKCOL", "/dav/alice/docs", b"").status, 201);
    let prose = |i: usize| -> Vec<u8> {
        format!("Document {i}: minutes of the meeting, notes and plans.\n")
            .into_bytes()
            .into_iter()
            .cycle()
            .take(8192)
            .collect()
    };
    for i in 0..12 {
        assert_eq!(dav("PUT", &format!("/dav/alice/docs/{i}.txt"), &prose(i)).status, 201);
    }
    hd_server::maintenance::check_activity(&s.app);
    assert!(s.app.maintenance.snapshot().alerts.is_empty(), "writing new files is ordinary");
    for i in 0..12_u64 {
        let r = dav("PUT", &format!("/dav/alice/docs/{i}.txt"), &noise(8192, i + 1));
        assert_eq!(r.status, 204, "{}", r.text());
    }
    hd_server::maintenance::check_activity(&s.app);
    let alerts = s.app.maintenance.snapshot().alerts;
    assert_eq!(alerts.len(), 1);
    assert_eq!((alerts[0].user.as_str(), alerts[0].suspicious), ("alice", 12));
    // Alice's clients hear of it; Bob's do not.
    let status = |user: &str, pw: &str| {
        request(addr, "GET", "/api/v1/status", &[("Authorization", &common::basic(user, pw))], b"")
            .text()
    };
    assert!(status("alice", ALICE_PW).contains("unusual activity"));
    assert!(!status("bob", BOB_PW).contains("unusual activity"));
    // The web UI shows it, with the way out.
    let alice = login(addr, "alice", ALICE_PW);
    let page = get(addr, &alice, "/files");
    assert!(page.text().contains("Unusual activity") && page.text().contains("Rewind"));
    let bob = login(addr, "bob", BOB_PW);
    assert!(!get(addr, &bob, "/files").text().contains("Unusual activity"));
    assert!(get(addr, &bob, "/files").text().contains("of 1.0 GiB"), "bob's quota is shown");
    // A device token cannot dismiss it; there is no API for that.
    let r = request(
        addr,
        "POST",
        "/api/v1/alerts/dismiss",
        &[("Authorization", &common::basic("alice", ALICE_PW))],
        b"{}",
    );
    assert_eq!(r.status, 404);
    // Dismissed in the browser, it clears.
    let token = csrf(&page);
    let r = post(addr, &alice, "/alerts/dismiss", &format!("csrf_token={token}"));
    assert!(r.text().contains("Dismissed"), "{}", r.text());
    assert!(s.app.maintenance.snapshot().alerts.is_empty());
    assert!(!status("alice", ALICE_PW).contains("unusual activity"));
}

/// The admin page's download is the whole store as one tar file, which
/// unpacks to a store that reads back clean; only administrators get it,
/// through the browser or the API.
#[test]
fn an_administrator_downloads_the_whole_store() {
    let s = common::start("store-tar");
    let addr = s.addr;
    let alice = login(addr, "alice", ALICE_PW);
    let token = csrf(&get(addr, &alice, "/files"));
    upload(addr, &alice, &token, "", &[("a.txt", b"alpha"), ("big.bin", &noise(2_500_000, 3))]);
    post(addr, &alice, "/delete", &format!("csrf_token={token}&path=a.txt"));
    assert!(get(addr, &alice, "/admin").text().contains("/admin/store-copy.tar"));
    let tar = get(addr, &alice, "/admin/store-copy.tar");
    assert_eq!(tar.status, 200);
    assert!(tar.header("Content-Disposition").unwrap().contains("homedrive-store-"));
    // Unpack it (ustar: 512-byte headers, data padded to 512).
    let out = s.dir.join("unpacked");
    let body = &tar.body;
    let mut at = 0;
    let mut files = 0;
    while at + 512 <= body.len() && body[at] != 0 {
        let h = &body[at..at + 512];
        let name =
            String::from_utf8(h[..100].iter().copied().take_while(|&b| b != 0).collect()).unwrap();
        let size_text = String::from_utf8(h[124..135].to_vec()).unwrap();
        let size = usize::from_str_radix(size_text.trim_matches(char::from(0)), 8).unwrap();
        let sum: u32 = h
            .iter()
            .enumerate()
            .map(|(i, &b)| if (148..156).contains(&i) { 32 } else { u32::from(b) })
            .sum();
        let stated =
            u32::from_str_radix(String::from_utf8(h[148..154].to_vec()).unwrap().trim(), 8)
                .unwrap();
        assert_eq!(sum, stated, "header checksum of {name}");
        let target = out.join(&name);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, &body[at + 512..at + 512 + size]).unwrap();
        files += 1;
        at += 512 + size.div_ceil(512) * 512;
    }
    assert!(files > 3, "{files}");
    let copy = hd_store::Store::open(&out, &hd_store::StoreOptions::default()).unwrap();
    assert!(copy.fsck(true).unwrap().is_clean());
    assert_eq!(copy.read(|st| st.user("alice").unwrap().trash.len()), 1);
    drop(copy);
    // And the tar program unpacks it to the same store.
    std::fs::write(s.dir.join("copy.tar"), body).unwrap();
    let by_tar = s.dir.join("by-tar");
    std::fs::create_dir_all(&by_tar).unwrap();
    let ok = std::process::Command::new("tar")
        .arg("-xf")
        .arg(s.dir.join("copy.tar"))
        .arg("-C")
        .arg(&by_tar)
        .status()
        .unwrap();
    assert!(ok.success());
    let copy = hd_store::Store::open(&by_tar, &hd_store::StoreOptions::default()).unwrap();
    assert!(copy.fsck(true).unwrap().is_clean());
    // Not for anyone else.
    let bob = login(addr, "bob", BOB_PW);
    assert_ne!(get(addr, &bob, "/admin/store-copy.tar").status, 200);
    let r = request(
        addr,
        "GET",
        "/api/v1/store-copy/meta",
        &[("Authorization", &common::basic("bob", BOB_PW))],
        b"",
    );
    assert_eq!(r.status, 403);
    let r = request(
        addr,
        "GET",
        "/api/v1/store-copy/file?name=../users.json",
        &[("Authorization", &common::basic("alice", ALICE_PW))],
        b"",
    );
    assert_eq!(r.status, 404, "only files of the store, by their names in it");
    // A finished download counts as a copy taken.
    assert!(hd_server::backups::load(&s.app.config.data_dir).contains_key("client-copy"));
}

/// With a passphrase, the download is encrypted as it streams, and opens
/// back to the tar that unpacks to a clean store.
#[test]
fn an_encrypted_download_of_the_store_opens_back() {
    let s = common::start("store-tar-sealed");
    let addr = s.addr;
    let alice = login(addr, "alice", ALICE_PW);
    let token = csrf(&get(addr, &alice, "/admin"));
    upload(addr, &alice, &token, "", &[("plans.txt", b"SECRET PLANS")]);
    let form = |a: &str, b: &str| format!("csrf_token={token}&passphrase={a}&passphrase2={b}");
    assert_eq!(
        post(addr, &alice, "/admin/store-copy.tar", &form("one-passphrase", "another-one")).status,
        400
    );
    assert_eq!(post(addr, &alice, "/admin/store-copy.tar", &form("short", "short")).status, 400);
    let pass = "a long and good passphrase";
    let enc = percent(pass);
    let r = post(addr, &alice, "/admin/store-copy.tar", &form(&enc, &enc));
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(r.header("Content-Disposition").unwrap().contains(".tar.hdenc"));
    assert!(r.body.starts_with(b"HDK1"));
    assert!(!String::from_utf8_lossy(&r.body).contains("SECRET PLANS"));
    // Open it as `homedrive decrypt-file` does, then unpack with tar.
    let mut input = &r.body[..];
    let params = hd_store::sealed::read_standalone_head(&mut input).unwrap();
    let keys = hd_store::sealed::Keys::open(pass, &params).unwrap();
    let mut tar = Vec::new();
    let label = keys.sealed_name(hd_store::sealed::STANDALONE_NAME).unwrap();
    hd_store::sealed::open(&mut input, &keys, &label, &mut tar).unwrap();
    std::fs::write(s.dir.join("copy.tar"), &tar).unwrap();
    let out = s.dir.join("unpacked");
    std::fs::create_dir_all(&out).unwrap();
    let ok = std::process::Command::new("tar")
        .arg("-xf")
        .arg(s.dir.join("copy.tar"))
        .arg("-C")
        .arg(&out)
        .status()
        .unwrap();
    assert!(ok.success());
    let copy = hd_store::Store::open(&out, &hd_store::StoreOptions::default()).unwrap();
    assert!(copy.fsck(true).unwrap().is_clean());
    assert!(copy.read(|st| st.user("alice").unwrap().get("plans.txt").is_some()));
    // Another passphrase cannot open it.
    assert!(hd_store::sealed::Keys::open("not the passphrase at all", &params).is_err());
}

fn percent(s: &str) -> String {
    hd_http::percent_encode(s)
}
