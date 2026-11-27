//! Photo backup from an iPhone Shortcut: the token `/photos` makes, the two
//! endpoints it may use, and everything else it may not.

#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::map_unwrap_or,
    clippy::format_collect,
    clippy::cast_possible_truncation
)]

mod common;

use std::net::SocketAddr;

use common::{ALICE_PW, Reply, basic, bearer, request};

fn cookie(r: &Reply, name: &str) -> String {
    r.head
        .split("\r\n")
        .filter_map(|l| l.strip_prefix("Set-Cookie: "))
        .find_map(|c| c.strip_prefix(&format!("{name}=")))
        .map(|c| c.split(';').next().unwrap().to_owned())
        .unwrap_or_else(|| panic!("no {name} cookie in {}", r.head))
}

fn attr(html: &str, name: &str) -> String {
    let key = format!("{name}=\"");
    let at = html.find(&key).unwrap_or_else(|| panic!("no {name} in {html}")) + key.len();
    html[at..at + html[at..].find('"').unwrap()].to_owned()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha(data: &[u8]) -> String {
    hex(&hd_crypto::sha256(data).unwrap())
}

/// A signed-in browser.
struct Browser {
    addr: SocketAddr,
    session: String,
}

impl Browser {
    fn sign_in(addr: SocketAddr) -> Self {
        let form = request(addr, "GET", "/login", &[], b"");
        let nonce = cookie(&form, "hd_login");
        let token = attr(&form.text(), "name=\"csrf_token\" value");
        let body = format!(
            "csrf_token={token}&username=alice&password={}",
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
        Self { addr, session: cookie(&r, "hd_session") }
    }

    fn get(&self, path: &str) -> Reply {
        request(self.addr, "GET", path, &[("Cookie", &format!("hd_session={}", self.session))], b"")
    }

    /// Submits the photos page's form: the page's answer.
    fn make_token(&self, name: &str) -> Reply {
        let page = self.get("/photos");
        assert_eq!(page.status, 200, "{}", page.text());
        let csrf = attr(&page.text(), "name=\"csrf_token\" value");
        let body = format!("csrf_token={csrf}&name={}", hd_http::percent_encode(name));
        request(
            self.addr,
            "POST",
            "/photos",
            &[
                ("Cookie", &format!("hd_session={}", self.session)),
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Origin", "http://test"),
            ],
            body.as_bytes(),
        )
    }

    /// A phone's token, from the prompt the photos page shows once.
    fn phone(&self, name: &str) -> Phone {
        let r = self.make_token(name);
        assert_eq!(r.status, 200, "{}", r.text());
        let text = r.text();
        let token = attr(&text, "class=\"setup-token\" readonly value");
        assert!(token.starts_with("hd1_"), "{token}");
        Phone { addr: self.addr, token }
    }
}

const T1: &str = "2026-11-20T09:00:00-05:00";
const T2: &str = "2026-11-21T09:00:00-05:00";

/// What the Shortcut does, request by request.
struct Phone {
    addr: SocketAddr,
    token: String,
}

impl Phone {
    fn ask(&self, name: &str, created: &str) -> Reply {
        let auth = bearer(&self.token);
        request(
            self.addr,
            "GET",
            "/api/v1/photos/have",
            &[("Authorization", &auth), ("X-Name", name), ("X-Created", created)],
            b"",
        )
    }

    fn have(&self, name: &str, created: &str) -> bool {
        let r = self.ask(name, created);
        assert_eq!(r.status, 200, "{}", r.text());
        match r.text().as_str() {
            "yes" => true,
            "no" => false,
            other => panic!("{other}"),
        }
    }

    /// The upload as the Shortcuts app sends it: a form with the photo in
    /// `file`, named by the phone (or by X-Name when `filename` is None).
    fn upload(&self, filename: Option<&str>, created: &str, data: &[u8]) -> Reply {
        let mut body = b"--XyZ\r\n".to_vec();
        match filename {
            Some(f) => body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"file\"; filename=\"{f}\"\r\n")
                    .as_bytes(),
            ),
            None => body.extend_from_slice(b"Content-Disposition: form-data; name=\"file\"\r\n"),
        }
        body.extend_from_slice(b"Content-Type: image/heic\r\n\r\n");
        body.extend_from_slice(data);
        body.extend_from_slice(b"\r\n--XyZ--\r\n");
        let auth = bearer(&self.token);
        let stem = filename.map_or("IMG_FALLBACK", |f| f.split('.').next().unwrap());
        request(
            self.addr,
            "POST",
            "/api/v1/photos/upload",
            &[
                ("Authorization", &auth),
                ("X-Name", stem),
                ("X-Created", created),
                ("Content-Type", "multipart/form-data; boundary=XyZ"),
            ],
            &body,
        )
    }

    /// One photo as the Shortcut handles it: "have", or the upload's status.
    fn back_up(&self, name: &str, created: &str, data: &[u8]) -> String {
        if self.have(name.split('.').next().unwrap(), created) {
            return "have".into();
        }
        let r = self.upload(Some(name), created, data);
        assert_eq!(r.status, 200, "{name}: {}", r.text());
        r.text().split(' ').next().unwrap().to_owned()
    }
}

/// Every file under `Photos/`: (path, current content, versions held).
fn photos_in_drive(app: &hd_server::App) -> Vec<(String, [u8; 32], usize)> {
    app.store.read(|st| {
        st.user("alice").map_or_else(Vec::new, |ns| {
            ns.subtree("Photos")
                .filter_map(|(p, e)| match &e.node {
                    hd_store::model::Node::File { versions, .. } => {
                        Some((p.clone(), versions.last().unwrap().sha256, versions.len()))
                    }
                    hd_store::model::Node::Dir => None,
                })
                .collect()
        })
    })
}

fn download(addr: SocketAddr, path: &str) -> Reply {
    request(
        addr,
        "GET",
        &format!(
            "/dav/alice/{}",
            path.split('/').map(hd_http::percent_encode).collect::<Vec<_>>().join("/")
        ),
        &[("Authorization", &basic("alice", ALICE_PW))],
        b"",
    )
}

#[test]
fn the_page_makes_a_photo_token_and_a_prompt_for_siri() {
    let s = common::start("photos-page");
    let web = Browser::sign_in(s.addr);
    let page = web.get("/photos");
    assert_eq!(page.status, 200);
    let text = page.text();
    // The prompt is always there, with this server's addresses and no
    // token: the token is pasted into the built Shortcut.
    let prompt = &text[text.find("class=\"siri-prompt\"").unwrap()..];
    assert!(prompt.contains("URL: http://test/api/v1/photos/have"), "{prompt}");
    assert!(prompt.contains("URL: http://test/api/v1/photos/upload"), "{prompt}");
    assert_eq!(prompt.matches("Authorization: Bearer PASTE-TOKEN-HERE").count(), 2, "{prompt}");
    assert!(text.contains("3. Put the token in the Shortcut"));
    assert!(!text.contains("setup-token"), "no token yet");
    assert!(!text.contains("<script"));
    let policy = page.header("Content-Security-Policy").unwrap();
    assert!(policy.contains("default-src 'none'") && !policy.contains("script-src"), "{policy}");
    assert_eq!(request(s.addr, "GET", "/static/photos.js", &[], b"").status, 404);

    let made = web.make_token("iPhone");
    assert_eq!(made.status, 200);
    let text = made.text();
    // The token, once, apart from the prompt, which still holds none.
    let token = attr(&text, "class=\"setup-token\" readonly value");
    assert!(token.starts_with("hd1_"), "{token}");
    assert_eq!(text.matches(&token).count(), 1);
    let prompt = &text[text.find("class=\"siri-prompt\"").unwrap()..];
    assert!(!prompt[..prompt.find("</textarea>").unwrap()].contains("hd1_"));
    let devices = web.get("/devices").text();
    assert!(devices.contains("iPhone <span class=\"badge\">photo backup only</span>"), "{devices}");
    // The phone is listed, with nothing received yet; the token is not
    // shown again.
    let later = web.get("/photos").text();
    assert!(later.contains("<td>iPhone</td><td>0</td><td>none yet</td>"), "{later}");
    assert!(!later.contains(&token));

    // A second token with the same name would share the folder: refused,
    // as are names that are not one folder name.
    for bad in ["iPhone", "a/b", "..", " ", "con"] {
        let r = web.make_token(bad);
        assert_eq!(r.status, 200);
        assert!(!r.text().contains("setup-token"), "{bad:?} made a token");
    }
    let count = s.app.store.read(|st| st.user("alice").unwrap().devices.len());
    assert_eq!(count, 1);

    // The form is a form like any other: no session, or another site, and
    // nothing is made.
    let r = request(s.addr, "POST", "/photos", &[], b"name=iPad");
    assert_eq!(r.status, 403);
    let r = request(
        s.addr,
        "POST",
        "/photos",
        &[
            ("Cookie", &format!("hd_session={}", web.session)),
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Origin", "https://elsewhere.example"),
        ],
        b"csrf_token=x&name=iPad",
    );
    assert_eq!(r.status, 403);
    let count = s.app.store.read(|st| st.user("alice").unwrap().devices.len());
    assert_eq!(count, 1);
}

#[test]
fn photos_are_added_once_and_never_replace_one_another() {
    let s = common::start("photos-add");
    let web = Browser::sign_in(s.addr);
    let phone = web.phone("iPhone");

    let photo = b"a HEIC photo".to_vec();
    assert_eq!(phone.back_up("IMG_0001.HEIC", T1, &photo), "uploaded");
    // Run again: the server has it, and nothing is sent.
    assert_eq!(phone.back_up("IMG_0001.HEIC", T1, &photo), "have");
    // With or without the extension, it is the same photo.
    assert!(phone.have("IMG_0001.HEIC", T1));
    assert!(phone.have("IMG_0001", "2026-11-20T14:00:00Z"));
    // Sent anyway (a run cut off after the upload): nothing added.
    let r = phone.upload(Some("IMG_0001.HEIC"), T1, &photo);
    assert_eq!(r.status, 200);
    assert!(r.text().starts_with("unchanged "), "{}", r.text());

    // A different photo with a reused name, taken at another time, is kept
    // beside the first, and counts as backed up from then on.
    let other = b"a different photo, same name".to_vec();
    assert!(!phone.have("IMG_0001", T2));
    assert_eq!(phone.back_up("IMG_0001.HEIC", T2, &other), "copy");
    assert!(phone.have("IMG_0001", T2));
    assert_eq!(download(s.addr, "Photos/iPhone/IMG_0001.HEIC").body, photo);
    let copy = photos_in_drive(&s.app)
        .into_iter()
        .map(|(p, ..)| p)
        .find(|p| p.starts_with("Photos/iPhone/IMG_0001 (conflict "))
        .unwrap();
    assert_eq!(download(s.addr, &copy).body, other);

    // The time the photo was taken is the file's time.
    let mtime = s.app.store.read(|st| {
        st.user("alice")
            .unwrap()
            .get("Photos/iPhone/IMG_0001.HEIC")
            .unwrap()
            .node
            .current()
            .unwrap()
            .mtime_ms
    });
    assert_eq!(mtime, 1_795_183_200_000);

    // A form part without a file name takes the name from X-Name.
    let r = phone.upload(None, T2, b"unnamed");
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(r.text().ends_with("Photos/iPhone/IMG_FALLBACK"), "{}", r.text());

    // A second phone has its own folder.
    let ipad = web.phone("iPad");
    assert!(!ipad.have("IMG_0001", T1));
    assert_eq!(ipad.back_up("IMG_0001.HEIC", T1, &photo), "uploaded");
    let paths: Vec<String> = photos_in_drive(&s.app).into_iter().map(|(p, ..)| p).collect();
    assert!(paths.contains(&"Photos/iPad/IMG_0001.HEIC".to_owned()), "{paths:?}");
    // Every file has exactly one version: nothing was ever replaced.
    assert!(photos_in_drive(&s.app).iter().all(|(_, _, n)| *n == 1));
    // A long video in one request.
    let video: Vec<u8> =
        (0..9_000_000_u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    assert_eq!(phone.back_up("IMG_0004.MOV", T2, &video), "uploaded");
    assert_eq!(sha(&download(s.addr, "Photos/iPhone/IMG_0004.MOV").body), sha(&video));
    // The page counts what each phone sent.
    let page = web.get("/photos").text();
    assert!(page.contains("<td>iPhone</td><td>4</td>"), "{page}");
    assert!(page.contains("<td>iPad</td><td>1</td>"), "{page}");
}

/// The token can add photos to its own folder, and do nothing else
/// anywhere: not read, list, move, trash, register devices, or sign in to
/// the web pages.
#[test]
fn a_photo_token_can_only_add_photos() {
    let s = common::start("photos-scope");
    let web = Browser::sign_in(s.addr);
    let phone = web.phone("iPhone");
    assert_eq!(phone.back_up("IMG_0001.HEIC", T1, b"photo"), "uploaded");
    let auth = bearer(&phone.token);
    let as_basic = basic("alice", &phone.token);
    let refused: &[(&str, &str, &[u8])] = &[
        ("GET", "/api/v1/whoami", b""),
        ("GET", "/api/v1/tree?path=", b""),
        ("GET", "/api/v1/changes?since=0", b""),
        ("GET", "/api/v1/devices", b""),
        ("POST", "/api/v1/devices", br#"{"name":"laptop"}"#),
        ("POST", "/api/v1/trash", br#"{"path":"Photos/iPhone/IMG_0001.HEIC"}"#),
        ("POST", "/api/v1/move", br#"{"from":"Photos","to":"Elsewhere"}"#),
        ("POST", "/api/v1/mkdir", br#"{"path":"x"}"#),
        ("GET", "/api/v1/versions?path=Photos/iPhone/IMG_0001.HEIC", b""),
        ("GET", "/dav/alice/Photos/iPhone/IMG_0001.HEIC", b""),
        ("PROPFIND", "/dav/alice/", b""),
        ("PUT", "/dav/alice/Photos/iPhone/IMG_0001.HEIC", b"replaced"),
        ("DELETE", "/dav/alice/Photos/iPhone/IMG_0001.HEIC", b""),
        ("MOVE", "/dav/alice/Photos", b""),
    ];
    for (method, target, body) in refused {
        for a in [&auth, &as_basic] {
            let r = request(s.addr, method, target, &[("Authorization", a)], body);
            assert_eq!(r.status, 403, "{method} {target}: {} {}", r.status, r.text());
        }
    }
    // The web pages take a session, which a token never gets.
    let r = request(s.addr, "GET", "/files", &[("Authorization", &auth)], b"");
    assert!(matches!(r.status, 302 | 303), "{}", r.status);
    // Nothing changed.
    assert_eq!(photos_in_drive(&s.app).len(), 1);
    assert_eq!(download(s.addr, "Photos/iPhone/IMG_0001.HEIC").body, b"photo");
    assert_eq!(s.app.store.read(|st| st.user("alice").unwrap().devices.len()), 1);

    // The endpoints take only a photo token: not the password, and not a
    // full device token.
    let ask = |a: &str| {
        request(
            s.addr,
            "GET",
            "/api/v1/photos/have",
            &[("Authorization", a), ("X-Name", "IMG_0001"), ("X-Created", T1)],
            b"",
        )
    };
    assert_eq!(ask(&basic("alice", ALICE_PW)).status, 403);
    let full = request(
        s.addr,
        "POST",
        "/api/v1/devices",
        &[("Authorization", &basic("alice", ALICE_PW))],
        br#"{"name":"laptop"}"#,
    );
    assert_eq!(full.status, 201, "{}", full.text());
    let full =
        full.json().get("token").and_then(hd_common::json::Value::as_str).unwrap().to_owned();
    assert_eq!(ask(&bearer(&full)).status, 403);
    // A revoked token is refused outright.
    let id = s.app.store.read(|st| {
        st.user("alice").unwrap().devices.values().find(|d| d.name == "iPhone").unwrap().id
    });
    let page = web.get("/devices");
    let csrf = attr(&page.text(), "name=\"csrf_token\" value");
    let r = request(
        s.addr,
        "POST",
        "/devices/revoke",
        &[
            ("Cookie", &format!("hd_session={}", web.session)),
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Origin", "http://test"),
        ],
        format!("csrf_token={csrf}&id={id}").as_bytes(),
    );
    assert_eq!(r.status, 200);
    assert_eq!(ask(&auth).status, 401);
}

/// A misconfigured Shortcut is told what is wrong, the page shows it, and
/// nothing it sends is counted as backed up.
#[test]
fn mistakes_are_explained_and_shown_on_the_page() {
    let s = common::start("photos-checks");
    let web = Browser::sign_in(s.addr);
    let phone = web.phone("iPhone");
    let auth = bearer(&phone.token);
    let ask = |headers: &[(&str, &str)]| {
        let mut h = vec![("Authorization", auth.as_str())];
        h.extend_from_slice(headers);
        request(s.addr, "GET", "/api/v1/photos/have", &h, b"")
    };
    assert_eq!(ask(&[("X-Created", T1)]).status, 400);
    assert_eq!(ask(&[("X-Name", "IMG_0001")]).status, 400);
    // The Shortcuts app's default date format, which differs by language.
    let r = ask(&[("X-Name", "IMG_0001"), ("X-Created", "20 Nov 2026 at 09:00")]);
    assert_eq!(r.status, 400);
    assert!(r.text().contains("ISO 8601"), "{}", r.text());
    let page = web.get("/photos").text();
    assert!(page.contains("X-Created is not a date homedrive can read"), "{page}");
    // A time the photo cannot have.
    assert_eq!(ask(&[("X-Name", "IMG_0001"), ("X-Created", "2999-01-01T00:00:00Z")]).status, 400);

    // Not a form, a form without the file, and a name that is not one.
    let r = request(
        s.addr,
        "POST",
        "/api/v1/photos/upload",
        &[("Authorization", &auth), ("X-Created", T1), ("Content-Type", "image/heic")],
        b"raw bytes",
    );
    assert_eq!(r.status, 415);
    assert!(r.text().contains("Form"), "{}", r.text());
    let r = request(
        s.addr,
        "POST",
        "/api/v1/photos/upload",
        &[
            ("Authorization", &auth),
            ("X-Created", T1),
            ("Content-Type", "multipart/form-data; boundary=XyZ"),
        ],
        b"--XyZ\r\nContent-Disposition: form-data; name=\"other\"\r\n\r\nx\r\n--XyZ--\r\n",
    );
    assert_eq!(r.status, 400);
    assert_eq!(phone.upload(Some(".."), T1, b"photo").status, 400);
    assert!(photos_in_drive(&s.app).is_empty());
    // A name with folders in it keeps only its last part, in this phone's
    // folder.
    let r = phone.upload(Some("../Documents/IMG_0009.HEIC"), T1, b"photo 9");
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(r.text().ends_with(" Photos/iPhone/IMG_0009.HEIC"), "{}", r.text());

    // Methods and addresses.
    let r = request(s.addr, "GET", "/api/v1/photos/upload", &[("Authorization", &auth)], b"");
    assert_eq!(r.status, 405);
    let r = request(s.addr, "POST", "/api/v1/photos/other", &[("Authorization", &auth)], b"");
    assert_eq!(r.status, 404);
    let r =
        request(s.addr, "GET", "/api/v1/photos/have", &[("X-Name", "x"), ("X-Created", T1)], b"");
    assert_eq!(r.status, 401);

    // Once a request works, the page no longer shows a problem.
    assert_eq!(phone.back_up("IMG_0001.HEIC", T1, b"photo"), "uploaded");
    let page = web.get("/photos").text();
    assert!(!page.contains("is not a date"), "{page}");
    assert!(page.contains("<td>iPhone</td><td>2</td>"), "{page}");
}

/// The usual way to use it: back up, then delete the photos from the
/// phone to free space, and later back up what the phone has then. The
/// Shortcut never compares the phone with the drive, so nothing the phone
/// no longer has is touched: not trashed, replaced, or given a new version,
/// and still there after retention and garbage collection.
#[test]
fn photos_deleted_from_the_phone_stay_in_the_drive() {
    let s = common::start("photos-phone-deletes");
    let web = Browser::sign_in(s.addr);
    let phone = web.phone("iPhone");
    let video: Vec<u8> = (0..5_000_000_u32).map(|i| (i % 241) as u8).collect();
    let first: Vec<(&str, &str, Vec<u8>)> = vec![
        ("IMG_0001.HEIC", T1, b"first photo".to_vec()),
        ("IMG_0002.HEIC", T1, b"second photo".to_vec()),
        ("IMG_0003.HEIC", T1, b"third photo".to_vec()),
        ("IMG_0004.MOV", T1, video),
    ];
    for (name, at, data) in &first {
        assert_eq!(phone.back_up(name, at, data), "uploaded");
    }
    let before = photos_in_drive(&s.app);
    assert_eq!(before.len(), 4);

    // The phone deleted all but the third, then took new photos, one of
    // them reusing a deleted photo's name (phones count up again).
    let later: Vec<(&str, &str, Vec<u8>)> = vec![
        ("IMG_0003.HEIC", T1, b"third photo".to_vec()),
        ("IMG_0005.HEIC", T2, b"fifth photo".to_vec()),
        ("IMG_0001.HEIC", T2, b"a new photo with an old name".to_vec()),
    ];
    let got: Vec<String> =
        later.iter().map(|(name, at, data)| phone.back_up(name, at, data)).collect();
    assert_eq!(got, ["have", "uploaded", "copy"]);

    // What was there before is there as it was, with no new version.
    let after = photos_in_drive(&s.app);
    for b in &before {
        assert!(after.contains(b), "{} changed or went: {after:?}", b.0);
    }
    assert_eq!(after.len(), 6, "{after:?}");
    let trash = s.app.store.read(|st| st.user("alice").map_or(0, |ns| ns.trash.len()));
    assert_eq!(trash, 0);

    // Retention and garbage collection, with no grace at all.
    let now = hd_common::timefmt::unix_ms();
    s.app.store.apply_retention(now, &hd_store::retention::Policy::default()).unwrap();
    let gc = hd_store::gc::GcOptions { grace_ms: 0, hold_ms: 0, dry_run: false };
    s.app.store.collect_garbage(now, &gc).unwrap();
    assert_eq!(photos_in_drive(&s.app), after);
    for (name, _, data) in &first {
        let r = download(s.addr, &format!("Photos/iPhone/{name}"));
        assert_eq!(r.status, 200, "{name}");
        assert!(r.body == *data, "{name} came back different");
    }
}
