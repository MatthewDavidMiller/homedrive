//! The proof that nothing done to a drive through the server loses data.
//!
//! The server changes a drive only through journal operations, and only
//! two of them release content: dropping an old version and purging a
//! trash item. Only retention issues those (`scripts/check-rust.sh`
//! refuses them anywhere else), only by age, and never the current
//! version. Everything else adds: an overwrite is a new version, a delete
//! moves to the trash, a move or copy refuses an occupied name, a
//! replacing WebDAV `MOVE`/`COPY` trashes what it replaces first, and a
//! conflicting commit keeps both copies.
//!
//! This test drives every way a user or device can change a drive: the
//! sync API, WebDAV, the web UI, and a rewind, with every overwrite,
//! delete, move, copy, conflict and restore each offers, including the
//! ones that must be refused. It records every content the server ever
//! acknowledged, and then checks that each one is still there, byte for
//! byte, as a version of a file or of something in the trash:
//! - straight away;
//! - after retention and garbage collection run with no grace periods at
//!   all (nothing here is old enough for retention to let go of);
//! - and the store passes a deep check.
//!
//! What the rest of the suite proves alongside it:
//! - `hd-store/tests/crash.rs`: a crash or failed write at **every** write,
//!   fsync, link and rename, and a journal cut at **every** byte, loses
//!   nothing that was acknowledged;
//! - `hd-store/tests/model.rs`: random operations against a reference
//!   model, then retention and collection, lose and corrupt nothing;
//! - `hd-store/tests/files.rs`: retention cannot be rushed by a clock
//!   that jumps ahead, collection frees only what nothing references, and
//!   damage on the disk is found, never served, and healed.

#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::map_unwrap_or
)]

mod common;

use std::collections::BTreeMap;
use std::io::Read;
use std::net::SocketAddr;

use common::{ALICE_PW, Reply, basic, bearer, request, start};
use hd_api::{BaseSpec, CommitRequest, CommitResult};
use hd_chunk::Chunker;
use hd_server::App;
use hd_store::gc::GcOptions;
use hd_store::model::Node;
use hd_store::retention::Policy;

/// A content named by `tag`; some span several chunks.
fn content(tag: &str) -> Vec<u8> {
    let mut data = format!("{tag}\n").into_bytes();
    if tag.ends_with("big") {
        data.extend(
            (0..3_000_000_u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13).to_le_bytes()[0]),
        );
    }
    data
}

/// Every content the server acknowledged, by SHA-256.
#[derive(Default)]
struct Ledger(BTreeMap<[u8; 32], Vec<u8>>);

impl Ledger {
    fn stored(&mut self, data: &[u8]) {
        self.0.insert(hd_crypto::sha256(data).unwrap(), data.to_vec());
    }

    /// Every acknowledged content reads back intact from a version that
    /// the drive still lists, in place or in the trash.
    fn check(&self, app: &App, when: &str) {
        let manifests = app.store.read(|s| {
            let ns = s.user("alice").unwrap();
            let mut out = BTreeMap::new();
            let mut add = |n: &Node| {
                if let Node::File { versions, .. } = n {
                    for v in versions {
                        out.insert(v.sha256, v.manifest);
                    }
                }
            };
            ns.entries.values().for_each(|e| add(&e.node));
            ns.trash.values().for_each(|t| t.entries.iter().for_each(|(_, n)| add(n)));
            out
        });
        for (sha, data) in &self.0 {
            let tag = String::from_utf8_lossy(&data[..data.len().min(40)]).into_owned();
            let Some(manifest) = manifests.get(sha) else {
                panic!("{when}: no version holds {tag:?} any more");
            };
            let mut back = Vec::new();
            app.store.open_content(manifest).unwrap().read_to_end(&mut back).unwrap();
            assert!(back == *data, "{when}: {tag:?} reads back differently");
        }
        let fsck = app.store.fsck(true).unwrap();
        assert!(fsck.is_clean(), "{when}: {:?}", fsck.problems);
    }
}

fn register(addr: SocketAddr) -> String {
    let r = request(
        addr,
        "POST",
        "/api/v1/devices",
        &[("Authorization", &basic("alice", ALICE_PW))],
        br#"{"name":"laptop"}"#,
    );
    assert_eq!(r.status, 201, "{}", r.text());
    hd_api::DeviceToken::from_json(&r.json()).unwrap().token
}

/// A sync client's upload: missing chunks, then a commit on `base`.
fn commit(addr: SocketAddr, token: &str, path: &str, base: BaseSpec, data: &[u8]) -> CommitResult {
    let auth = bearer(token);
    let mut c = Chunker::new(data).unwrap();
    let mut chunks = Vec::new();
    while let Some(ch) = c.next_chunk().unwrap() {
        let r = request(
            addr,
            "PUT",
            &format!("/api/v1/chunks/{}", ch.id.hex()),
            &[("Authorization", &auth)],
            &ch.data,
        );
        assert!(r.status == 201 || r.status == 200, "{}", r.text());
        chunks.push((ch.id, u32::try_from(ch.data.len()).unwrap()));
    }
    let summary = c.finish().unwrap();
    let req = CommitRequest {
        path: path.into(),
        base,
        size: summary.len,
        sha256: summary.sha256,
        mtime_ms: 1,
        chunks,
        executable: None,
    };
    let r = request(
        addr,
        "POST",
        "/api/v1/commit",
        &[("Authorization", &auth)],
        req.to_json().as_bytes(),
    );
    assert_eq!(r.status, 200, "{}", r.text());
    CommitResult::from_json(&r.json()).unwrap()
}

fn api(addr: SocketAddr, token: &str, route: &str, body: &str) -> Reply {
    request(
        addr,
        "POST",
        &format!("/api/v1/{route}"),
        &[("Authorization", &bearer(token))],
        body.as_bytes(),
    )
}

fn dav(addr: SocketAddr, method: &str, path: &str, extra: &[(&str, &str)], body: &[u8]) -> Reply {
    let auth = basic("alice", ALICE_PW);
    let mut h = vec![("Authorization", auth.as_str())];
    h.extend_from_slice(extra);
    request(addr, method, &format!("/dav/alice/{path}"), &h, body)
}

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
    let at = html.find("name=\"csrf_token\" value=\"").unwrap() + 25;
    html[at..at + html[at..].find('"').unwrap()].to_owned()
}

/// A browser session: its cookie and form token.
fn browser(addr: SocketAddr) -> (String, String) {
    let form = request(addr, "GET", "/login", &[], b"");
    let nonce = cookie(&form, "hd_login");
    let body = format!(
        "csrf_token={}&username=alice&password={}",
        csrf(&form),
        hd_http::percent_encode(ALICE_PW)
    );
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
    let session = cookie(&r, "hd_session");
    let page = request(addr, "GET", "/files", &[("Cookie", &format!("hd_session={session}"))], b"");
    (session.clone(), csrf(&page))
}

fn form(addr: SocketAddr, session: &str, target: &str, body: &str) -> Reply {
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

fn web_upload(addr: SocketAddr, session: &str, token: &str, name: &str, data: &[u8]) -> Reply {
    let b = "----hdproofboundary";
    let mut body = format!(
        "--{b}\r\nContent-Disposition: form-data; name=\"csrf_token\"\r\n\r\n{token}\r\n--{b}\r\nContent-Disposition: form-data; name=\"dir\"\r\n\r\n\r\n--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(data);
    body.extend_from_slice(format!("\r\n--{b}--\r\n").as_bytes());
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

fn trash_id(app: &App, original: &str) -> u64 {
    app.store.read(|s| {
        let ns = s.user("alice").unwrap();
        ns.trash.values().filter(|t| t.path == original).map(|t| t.id).max().unwrap()
    })
}

#[test]
fn nothing_done_through_any_interface_loses_a_stored_content() {
    let s = start("no-data-loss");
    let (addr, app) = (s.addr, &s.app);
    let mut ledger = Ledger::default();

    // The sync API.
    let token = register(addr);
    let v1 = content("api a v1 big");
    let first = commit(addr, &token, "a.txt", BaseSpec::Absent, &v1);
    ledger.stored(&v1);
    let v2 = content("api a v2");
    let second = commit(addr, &token, "a.txt", BaseSpec::Version(first.version), &v2);
    ledger.stored(&v2);
    // Another device still on v1: kept beside it as a conflict copy.
    let v3 = content("api a conflicting");
    let third = commit(addr, &token, "a.txt", BaseSpec::Version(first.version), &v3);
    assert!(third.conflict, "a stale base must never replace the newer version");
    ledger.stored(&v3);
    // A new file where one exists: a conflict copy too.
    let v4 = content("api a believed new");
    assert!(commit(addr, &token, "a.txt", BaseSpec::Absent, &v4).conflict);
    ledger.stored(&v4);
    // A delete based on a version that is no longer current is refused.
    let stale = format!(r#"{{"path":"a.txt","version":{}}}"#, first.version);
    assert_eq!(api(addr, &token, "trash", &stale).status, 412);
    // Moves and copies never land on an existing name.
    let b = content("api b");
    commit(addr, &token, "b.txt", BaseSpec::Absent, &b);
    ledger.stored(&b);
    assert_ne!(api(addr, &token, "move", r#"{"from":"b.txt","to":"a.txt"}"#).status, 200);
    assert_ne!(api(addr, &token, "copy", r#"{"from":"b.txt","to":"a.txt"}"#).status, 200);
    assert_eq!(api(addr, &token, "copy", r#"{"from":"b.txt","to":"b2.txt"}"#).status, 200);
    // Deleted, restored, deleted again.
    let current = format!(r#"{{"path":"a.txt","version":{}}}"#, second.version);
    assert_eq!(api(addr, &token, "trash", &current).status, 200);
    let id = trash_id(app, "a.txt");
    // A restore onto a name in use is refused, not merged.
    assert_ne!(
        api(addr, &token, "restore", &format!(r#"{{"trash_id":{id},"to":"b.txt"}}"#)).status,
        200
    );
    assert_eq!(
        api(addr, &token, "restore", &format!(r#"{{"trash_id":{id},"to":"a.txt"}}"#)).status,
        200
    );
    assert_eq!(api(addr, &token, "trash", r#"{"path":"b2.txt"}"#).status, 200);
    ledger.check(app, "after the sync API");
    std::thread::sleep(std::time::Duration::from_millis(5));
    let after_api = hd_common::timefmt::unix_ms();
    std::thread::sleep(std::time::Duration::from_millis(5));

    // WebDAV.
    assert_eq!(dav(addr, "MKCOL", "d", &[], b"").status, 201);
    for (name, tag) in
        [("d/x", "dav x v1"), ("d/x", "dav x v2 big"), ("d/y", "dav y"), ("z", "dav z")]
    {
        let data = content(tag);
        assert!(dav(addr, "PUT", name, &[], &data).status < 300);
        ledger.stored(&data);
    }
    // Files the sync API made, overwritten and deleted here.
    let data = content("dav b over api");
    assert!(dav(addr, "PUT", "b.txt", &[], &data).status < 300);
    ledger.stored(&data);
    assert!(dav(addr, "DELETE", "a.txt", &[], b"").status < 300);
    // A conditional PUT on an old ETag is refused.
    assert_eq!(dav(addr, "PUT", "d/x", &[("If-Match", "\"v1\"")], b"stale").status, 412);
    // MOVE and COPY onto an existing file replace it: the replaced file
    // goes to the trash first. Without Overwrite they are refused.
    let dest = format!("http://{addr}/dav/alice/d/y");
    assert_eq!(
        dav(addr, "MOVE", "z", &[("Destination", &dest), ("Overwrite", "F")], b"").status,
        412
    );
    assert!(dav(addr, "MOVE", "z", &[("Destination", &dest)], b"").status < 300);
    let dest = format!("http://{addr}/dav/alice/d/x");
    assert!(dav(addr, "COPY", "d/y", &[("Destination", &dest)], b"").status < 300);
    // Onto a folder that holds the source, or into the source: refused.
    let dest = format!("http://{addr}/dav/alice/d");
    assert_eq!(dav(addr, "COPY", "d/x", &[("Destination", &dest)], b"").status, 409);
    let dest = format!("http://{addr}/dav/alice/d/inner");
    assert_eq!(dav(addr, "MOVE", "d", &[("Destination", &dest)], b"").status, 409);
    // A whole folder deleted, and a folder moved over another.
    assert_eq!(dav(addr, "MKCOL", "e", &[], b"").status, 201);
    let data = content("dav e/w");
    assert!(dav(addr, "PUT", "e/w", &[], &data).status < 300);
    ledger.stored(&data);
    let dest = format!("http://{addr}/dav/alice/e");
    assert!(dav(addr, "MOVE", "d", &[("Destination", &dest)], b"").status < 300);
    assert!(dav(addr, "DELETE", "e", &[], b"").status < 300);
    ledger.check(app, "after WebDAV");

    // The web UI.
    let (session, form_token) = browser(addr);
    for tag in ["web f v1", "web f v2 big", "web f v3"] {
        let data = content(tag);
        assert_eq!(web_upload(addr, &session, &form_token, "f.txt", &data).status, 200);
        ledger.stored(&data);
    }
    let g = content("web g");
    web_upload(addr, &session, &form_token, "g.txt", &g);
    ledger.stored(&g);
    // A move onto an existing file is refused.
    let r = form(addr, &session, "/move", &format!("csrf_token={form_token}&path=g.txt&to=f.txt"));
    assert!(!r.text().contains("Moved g.txt"), "a move onto a file must be refused");
    let oldest = app.store.read(|s| match &s.user("alice").unwrap().get("f.txt").unwrap().node {
        Node::File { versions, .. } => versions[0].id,
        Node::Dir => unreachable!(),
    });
    let r = form(
        addr,
        &session,
        "/restore-version",
        &format!("csrf_token={form_token}&path=f.txt&version={oldest}"),
    );
    assert!(r.text().contains("Nothing was removed."), "{}", r.text());
    let r = form(addr, &session, "/delete", &format!("csrf_token={form_token}&path=f.txt"));
    assert!(r.text().contains("Moved f.txt to the trash."), "{}", r.text());
    let again = content("web f after delete");
    web_upload(addr, &session, &form_token, "f.txt", &again);
    ledger.stored(&again);
    // Restoring while the name is taken restores beside it.
    let id = trash_id(app, "f.txt");
    let r = form(addr, &session, "/restore", &format!("csrf_token={form_token}&trash_id={id}"));
    assert!(r.text().contains("Restored to f (restored "), "{}", r.text());
    ledger.check(app, "after the web UI");

    // The whole drive rewound to before WebDAV and the web UI were used,
    // then to before anything existed.
    let r = app.store.rewind("alice", "", after_api, true).unwrap();
    assert_eq!(r.reverted, ["b.txt"], "{r:?}");
    assert_eq!(r.undeleted.len(), 1, "{r:?}");
    assert!(!r.newer.is_empty(), "{r:?}");
    app.store.rewind("alice", "", 0, true).unwrap();
    ledger.check(app, "after rewinding");

    // Retention and collection, with no grace or hold at all.
    let now = hd_common::timefmt::unix_ms();
    app.store.apply_retention(now, &Policy::default()).unwrap();
    let gc = GcOptions { grace_ms: 0, hold_ms: 0, dry_run: false };
    app.store.collect_garbage(now, &gc).unwrap();
    app.store.collect_garbage(now, &gc).unwrap();
    ledger.check(app, "after retention and collection");
    assert!(ledger.0.len() >= 15, "only {} contents were checked", ledger.0.len());
}
