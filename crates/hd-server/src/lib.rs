//! The homedrive server: configuration, accounts, and the HTTP handler
//! that the sync API (`/api/v1/`), WebDAV (`/dav/<user>/`), and the web UI
//! are routed through.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::disallowed_methods))]

pub mod admin;
pub mod api;
pub mod auth;
pub mod backups;
pub mod config;
pub mod copy;
pub mod dav;
pub mod drill;
pub mod export;
pub mod html;
pub mod maintenance;
pub mod multipart;
pub mod session;
pub mod web;

use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, PoisonError};

use hd_common::{Error, Result, fsio, timefmt};
use hd_http::{Handler, Method, Request, Response};
use hd_store::{Store, StoreOptions};

use crate::auth::{Accounts, FAILURE_LIMIT, FAILURE_WINDOW, Throttle, Who};
use crate::config::Config;

#[derive(Debug)]
pub struct App {
    pub config: Config,
    pub store: Store,
    pub accounts: Accounts,
    pub throttle: Throttle,
    pub maintenance: maintenance::Maintenance,
    pub sessions: session::Sessions,
    /// Per user, bytes of new chunks uploaded and not yet accounted for by
    /// a commit. They take disk space before any version names them, so
    /// they count against the quota too.
    pending: Mutex<HashMap<String, u64>>,
}

/// In the data directory: when each drive's unusual-activity alert was
/// last dismissed, as `{"user": unix ms}`.
const DISMISSED_FILE: &str = "alerts-dismissed.json";

/// A size in GiB, for messages.
pub(crate) fn gib(bytes: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let g = bytes as f64 / f64::from(1_u32 << 30);
    format!("{g:.1} GiB")
}

/// Reads and validates the users file.
pub fn load_accounts(config: &Config) -> Result<Accounts> {
    let mut raw = fsio::read_bounded(&config.users_file, auth::MAX_USERS_FILE)
        .map_err(|e| {
            Error::new(format!("cannot read the users file {}: {e}", config.users_file.display()))
        })?
        .ok_or_else(|| {
            Error::new(format!(
                "the users file {} does not exist (set HD_USERS_FILE)",
                config.users_file.display()
            ))
        })?;
    let accounts = Accounts::parse(&raw);
    hd_common::buf::wipe_vec(&mut raw);
    accounts
}

impl App {
    /// Loads the accounts and opens the store named by the configuration.
    /// This is where the server fails closed on a missing or foreign data
    /// directory, or a bad users file.
    pub fn open(config: Config) -> Result<Self> {
        let accounts = load_accounts(&config)?;
        let options = StoreOptions { min_free: config.min_free, ..StoreOptions::default() };
        let store = Store::open(&config.data_dir, &options)?;
        let r = store.recovery();
        if r.torn_bytes > 0 || r.repaired_bytes > 0 || !r.bad_snapshots.is_empty() {
            eprintln!(
                "hd-server: recovery set aside {} torn and {} repaired journal bytes and {} bad \
                 snapshot(s); all of it is in quarantine/",
                r.torn_bytes,
                r.repaired_bytes,
                r.bad_snapshots.len()
            );
        }
        let stored: Vec<String> = store.read(|s| s.users.keys().cloned().collect());
        for user in stored.iter().filter(|u| accounts.get(u).is_none()) {
            eprintln!(
                "hd-server: {user} has a drive but is not in the users file; they cannot sign in"
            );
        }
        let names: Vec<&String> = accounts.names().collect();
        eprintln!(
            "hd-server: {} account(s): {}",
            names.len(),
            names.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        );
        let app = Self {
            config,
            store,
            accounts,
            throttle: Throttle::new(FAILURE_LIMIT, FAILURE_WINDOW),
            maintenance: maintenance::Maintenance::default(),
            sessions: session::Sessions::new(web::SESSION_LIFETIME)?,
            pending: Mutex::new(HashMap::new()),
        };
        app.check_capacity()?;
        if let Some(warning) = app.overcommitted() {
            eprintln!("hd-server: WARNING: {warning}");
        }
        Ok(app)
    }

    /// Refuses quotas that could never fit: every drive filled to its
    /// quota, plus what the drives of people no longer in the users file
    /// hold, plus the free-space reserve, must fit on the store's disk. A
    /// quota counts every version at full size and storage deduplicates,
    /// so the disk can then never be filled by the drives.
    fn check_capacity(&self) -> Result<()> {
        let total = hd_sys::posix::fs_space(&self.config.data_dir)
            .map_err(|e| Error::new(format!("cannot measure the store's disk: {e}")))?
            .total;
        let quotas: u64 = self
            .accounts
            .names()
            .filter_map(|n| self.accounts.get(n))
            .map(|a| a.quota)
            .fold(0, u64::saturating_add);
        let orphaned: u64 = self.store.read(|st| {
            st.users
                .iter()
                .filter(|(u, _)| self.accounts.get(u).is_none())
                .map(|(_, ns)| ns.stored_bytes())
                .fold(0, u64::saturating_add)
        });
        let needed = quotas.saturating_add(orphaned).saturating_add(self.config.min_free);
        if needed > total {
            return Err(Error::new(format!(
                "the quotas in the users file add up to {}{}, which with the {} free-space \
                 reserve is more than the store's disk holds ({}). Lower quota_gb so the drives \
                 can never fill the disk",
                gib(quotas),
                if orphaned > 0 {
                    format!(", and removed accounts' drives hold {}", gib(orphaned))
                } else {
                    String::new()
                },
                gib(self.config.min_free),
                gib(total)
            )));
        }
        Ok(())
    }

    /// Whether the drives may grow by more than the disk has free, which
    /// happens when something else uses the store's disk. The free-space
    /// reserve still stops writes before the disk fills; this says it may
    /// come to that.
    pub fn overcommitted(&self) -> Option<String> {
        let available = hd_sys::posix::fs_space(&self.config.data_dir).ok()?.available;
        let headroom: u64 =
            self.accounts.names().map(|n| self.room(n)).fold(0, u64::saturating_add);
        let needed = headroom.saturating_add(self.config.min_free);
        (needed > available).then(|| {
            format!(
                "the drives may still grow by {} under their quotas, but the store's disk has \
                 only {} free (keeping {} in reserve). Something else is using the disk: free \
                 space there, or lower quotas",
                gib(headroom),
                gib(available),
                gib(self.config.min_free)
            )
        })
    }

    /// Bytes `user`'s drive holds, as a quota counts them.
    pub fn usage(&self, user: &str) -> u64 {
        self.store.read(|st| st.user(user).map_or(0, hd_store::model::Namespace::stored_bytes))
    }

    /// Bytes `user` may still store: their quota, less what the drive
    /// holds and the chunks uploaded for commits not yet made. 0 for
    /// someone not in the users file.
    pub fn room(&self, user: &str) -> u64 {
        let Some(account) = self.accounts.get(user) else { return 0 };
        let pending = self.pending_bytes(user);
        account.quota.saturating_sub(self.usage(user)).saturating_sub(pending)
    }

    fn pending_bytes(&self, user: &str) -> u64 {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner).get(user).copied().unwrap_or(0)
    }

    /// A new chunk of `len` bytes was stored for `user`.
    pub(crate) fn note_chunk(&self, user: &str, len: u64) {
        let mut p = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        let slot = p.entry(user.to_owned()).or_insert(0);
        *slot = slot.saturating_add(len);
    }

    /// A commit of `size` bytes by `user` now counts in the drive, and
    /// with it the chunks uploaded for it.
    pub(crate) fn note_commit(&self, user: &str, size: u64) {
        let mut p = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(slot) = p.get_mut(user) {
            *slot = slot.saturating_sub(size);
            if *slot == 0 {
                p.remove(user);
            }
        }
    }

    /// The most a streamed write for `user` may be: the server's file
    /// limit, or the room left under the quota if that is less. A write
    /// past it fails as too large, so a stream of unknown length can never
    /// take a drive over its quota.
    pub(crate) fn write_limit(&self, user: &str) -> u64 {
        self.config.max_file.min(self.room(user))
    }

    /// The message for a write refused or cut off by the quota.
    pub(crate) fn quota_message(&self, user: &str) -> String {
        let quota = self.accounts.get(user).map_or(0, |a| a.quota);
        let used = self.usage(user);
        format!(
            "the drive is full: it holds {} of its {} quota, counting old versions and the \
             trash. Nothing was stored. Ask the administrator for more room; deleting files \
             frees space only once they leave the trash",
            gib(used),
            gib(quota)
        )
    }

    /// Why storing `adding` more bytes for `user` is refused, if it would
    /// take the drive over its quota (with nothing left at all, any write
    /// is). Restores and rewinds are never refused: they reuse content
    /// already stored, and are how a drive is recovered.
    pub(crate) fn over_quota(&self, user: &str, adding: u64) -> Option<String> {
        let room = self.room(user);
        (adding > room || room == 0).then(|| self.quota_message(user))
    }

    /// When each drive's alert was last dismissed.
    pub fn dismissed(&self) -> BTreeMap<String, i64> {
        let Ok(Some(bytes)) =
            fsio::read_bounded(self.config.data_dir.join(DISMISSED_FILE), 1024 * 1024)
        else {
            return BTreeMap::new();
        };
        let Ok(hd_common::json::Value::Object(fields)) = hd_common::json::parse(&bytes) else {
            return BTreeMap::new();
        };
        fields.into_iter().filter_map(|(k, v)| Some((k, v.as_i64()?))).collect()
    }

    /// Dismisses `user`'s unusual-activity alert: what happened until now
    /// has been looked at. Retention resumes for the drive.
    pub fn dismiss_alert(&self, user: &str) -> Result<()> {
        let mut all = self.dismissed();
        all.insert(user.to_owned(), timefmt::unix_ms());
        // User names are plain (validated: A-Z a-z 0-9 . _ -), so they need
        // no escaping.
        let fields: Vec<String> = all
            .iter()
            .filter(|(u, _)| hd_store::model::validate_user(u).is_ok())
            .map(|(u, at)| format!("\"{u}\":{at}"))
            .collect();
        let text = format!("{{{}}}", fields.join(","));
        fsio::atomic_replace(self.config.data_dir.join(DISMISSED_FILE), text.as_bytes(), 1 << 20)?;
        maintenance::check_activity(self);
        Ok(())
    }

    /// Signs a request in: a bearer token, or Basic with a password or a
    /// device token. `None` means no credentials were given at all.
    fn sign_in(&self, req: &Request<'_, '_>) -> std::result::Result<Option<Who>, ()> {
        if let Some(token) = auth::bearer_token(req) {
            return auth::verify_token(&self.store, &self.accounts, token).map(Some).ok_or(());
        }
        if let Some((user, password)) = auth::basic_credentials(req) {
            return auth::verify_basic(&self.store, &self.accounts, &user, &password)
                .map(Some)
                .ok_or(());
        }
        Ok(None)
    }

    /// Runs `f` as the signed-in user, or answers 401/429.
    fn authenticated<'a>(
        &'a self,
        req: &mut Request<'_, '_>,
        f: impl FnOnce(&'a Self, &mut Request<'_, '_>, &Who) -> Response<'a>,
    ) -> Response<'a> {
        let ip = auth::client_ip(req, &self.config.trusted_proxies);
        if self.throttle.blocked(ip) {
            return api::error(429, "too many failed sign-ins; try again later");
        }
        match self.sign_in(req) {
            Ok(Some(who)) => f(self, req, &who),
            Ok(None) => api::error(401, "sign in required").with_header(
                "WWW-Authenticate",
                "Basic realm=\"homedrive\", charset=\"UTF-8\"".into(),
            ),
            Err(()) => {
                self.throttle.fail(ip);
                eprintln!("hd-server: failed sign-in from {ip}");
                api::error(401, "wrong credentials").with_header(
                    "WWW-Authenticate",
                    "Basic realm=\"homedrive\", charset=\"UTF-8\"".into(),
                )
            }
        }
    }
}

impl Handler for App {
    fn handle<'a>(&'a self, request: &mut Request<'_, '_>) -> Response<'a> {
        let path = request.path.clone();
        if path == "/healthz" {
            return match request.method {
                Method::Get | Method::Head if self.store.is_poisoned() => {
                    Response::text(503, "the store stopped accepting writes")
                }
                Method::Get | Method::Head => Response::text(200, "ok"),
                _ => Response::text(405, "Method Not Allowed"),
            };
        }
        if let Some(route) = path.strip_prefix("/api/v1/") {
            let route = route.to_owned();
            return self.authenticated(request, |app, req, who| app.api(req, who, &route));
        }
        if let Some(rest) = path.strip_prefix("/dav/") {
            let rest = rest.to_owned();
            return self.authenticated(request, |app, req, who| app.dav(req, who, &rest));
        }
        if let Some(r) = self.web(request) {
            return r;
        }
        Response::text(404, "Not Found")
    }

    fn hsts(&self) -> bool {
        self.config.secure_cookies
    }
}
