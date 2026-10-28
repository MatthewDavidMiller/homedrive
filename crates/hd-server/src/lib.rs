//! The homedrive server: configuration, accounts, and the HTTP handler
//! that the sync API (and, later, WebDAV and the web UI) are routed
//! through.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::disallowed_methods))]

pub mod api;
pub mod auth;
pub mod config;
pub mod maintenance;

use hd_common::{Error, Result, fsio};
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
        Ok(Self {
            config,
            store,
            accounts,
            throttle: Throttle::new(FAILURE_LIMIT, FAILURE_WINDOW),
            maintenance: maintenance::Maintenance::default(),
        })
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
        Response::text(404, "Not Found")
    }

    fn hsts(&self) -> bool {
        self.config.secure_cookies
    }
}
