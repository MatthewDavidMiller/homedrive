//! Two clients and a server on loopback, and what the tests look at.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hd_client::engine::{Engine, Folder, Options};
use hd_client::remote::Remote;
use hd_server::App;
use hd_server::config::Config;

pub const PW: &str = "alice password";

pub struct World {
    pub dir: PathBuf,
    pub server: String,
    pub token: String,
    pub app: Arc<App>,
}

pub fn world(name: &str) -> World {
    let dir = std::env::temp_dir().join(format!("hd-client-e2e-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let users = dir.join("users.json");
    fs::write(
        &users,
        format!(r#"{{"version":1,"users":[{{"name":"alice","password":"{PW}","admin":true,"quota_gb":10}}]}}"#),
    )
    .unwrap();
    let data = dir.join("store");
    hd_store::Store::init(&data).unwrap();
    let (app, server) = serve(&data, &users);
    let token = Remote::register(&server, None, "alice", PW, "test").unwrap().token;
    World { dir, server, token, app }
}

/// Opens the store at `data` and serves it on a new port.
pub fn serve(data: &Path, users: &Path) -> (Arc<App>, String) {
    let app = Arc::new(App::open(Config::for_test(data.to_owned(), users.to_owned())).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let served = Arc::clone(&app);
    std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || hd_http::serve(&listener, &served))
        .unwrap();
    (app, format!("http://{addr}"))
}

impl World {
    pub fn client(&self, name: &str, remote: &str) -> Engine {
        let local = self.dir.join(name);
        if !local.join(hd_client::scan::SENTINEL).exists() {
            Engine::mark_root(&local).unwrap();
        }
        self.reopen(name, remote, Options::default())
    }

    pub fn folder(&self, name: &str, remote: &str) -> Folder {
        Folder {
            local: self.dir.join(name),
            remote: remote.to_owned(),
            ignore: vec!["*.ignored".into()],
            state_dir: self.dir.join(format!("{name}-state")),
        }
    }

    pub fn reopen(&self, name: &str, remote: &str, options: Options) -> Engine {
        let folder = self.folder(name, remote);
        Engine::open(folder, Remote::new(&self.server, None, &self.token).unwrap(), options)
            .unwrap()
    }

    pub fn reopen_with_ignore(&self, name: &str, ignore: &[&str]) -> Engine {
        let folder = Folder {
            local: self.dir.join(name),
            remote: String::new(),
            ignore: ignore.iter().map(|s| (*s).to_owned()).collect(),
            state_dir: self.dir.join(format!("{name}-state")),
        };
        Engine::open(
            folder,
            Remote::new(&self.server, None, &self.token).unwrap(),
            Options::default(),
        )
        .unwrap()
    }

    pub fn path(&self, client: &str, rel: &str) -> PathBuf {
        self.dir.join(client).join(rel)
    }

    pub fn write(&self, client: &str, rel: &str, data: &[u8]) {
        let p = self.path(client, rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, data).unwrap();
    }
}

/// Every synced file under a folder, by relative path.
pub fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(dir: &Path, rel: &str, out: &mut BTreeMap<String, Vec<u8>>) {
        let mut names: Vec<_> =
            fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name()).collect();
        names.sort();
        for n in names {
            let n = n.to_str().unwrap().to_owned();
            if n == ".homedrive" || n == ".homedrive-root" {
                continue;
            }
            let child = if rel.is_empty() { n.clone() } else { format!("{rel}/{n}") };
            let p = dir.join(&n);
            if p.is_dir() {
                out.insert(format!("{child}/"), Vec::new());
                walk(&p, &child, out);
            } else {
                out.insert(child, fs::read(&p).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, "", &mut out);
    out
}

/// Every file's content under `dir`, recursively.
pub fn contents_under(dir: &Path) -> Vec<Vec<u8>> {
    fn walk(dir: &Path, out: &mut Vec<Vec<u8>>) {
        if let Ok(entries) = fs::read_dir(dir) {
            for e in entries {
                let p = e.unwrap().path();
                if p.is_dir() { walk(&p, out) } else { out.push(fs::read(&p).unwrap()) }
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, &mut out);
    out
}

/// Every content in a folder's client trash, whose items expire.
pub fn trashed(root: &Path) -> Vec<Vec<u8>> {
    contents_under(&root.join(".homedrive/trash"))
}

/// Every content the client keeps where nothing expires: changed copies
/// it could not put back, files with attribute data, and copies damaged on
/// this computer's disk.
pub fn kept(root: &Path) -> Vec<Vec<u8>> {
    let mut out = contents_under(&root.join(".homedrive/kept"));
    out.extend(contents_under(&root.join(".homedrive/damaged")));
    out
}

/// Every content on the server, current or old, in place or in its trash.
pub fn server_hashes(app: &App) -> BTreeSet<[u8; 32]> {
    app.store.read(|s| {
        let ns = s.user("alice").unwrap();
        let mut out = BTreeSet::new();
        let mut add = |n: &hd_store::model::Node| {
            if let hd_store::model::Node::File { versions, .. } = n {
                out.extend(versions.iter().map(|v| v.sha256));
            }
        };
        ns.entries.values().for_each(|e| add(&e.node));
        ns.trash.values().for_each(|t| t.entries.iter().for_each(|(_, n)| add(n)));
        out
    })
}

/// Makes `engine`'s record of `rel` take the file's change time as it is
/// now. Every write from a program moves the change time, so this is how
/// a test makes a write look like damage done by the disk itself, which
/// changes content without any write the filesystem sees.
pub fn as_if_the_disk_did_it(engine: &mut Engine, rel: &str, path: &Path) {
    use std::os::unix::fs::MetadataExt;
    let m = fs::metadata(path).unwrap();
    let mut s = engine.state.state.synced.get(rel).cloned().unwrap();
    s.ctime_ns = m.ctime() * 1_000_000_000 + m.ctime_nsec();
    engine.state.set_synced(rel, s).unwrap();
}
