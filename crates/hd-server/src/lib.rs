//! The homedrive server: configuration and the HTTP handler that the store,
//! the sync API, WebDAV, and the web UI are assembled into.
//!
//! At this milestone (M1) it opens the store, refusing to start without
//! one, and answers only `/healthz`; docs/PLAN.md lists what each later
//! milestone adds.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::disallowed_methods))]

pub mod config;

use hd_common::Result;
use hd_http::{Handler, Method, Request, Response};
use hd_store::{Store, StoreOptions};

use crate::config::Config;

#[derive(Debug)]
pub struct App {
    pub config: Config,
    pub store: Store,
}

impl App {
    /// Opens the store named by the configuration. This is where the server
    /// fails closed on a missing or foreign data directory.
    pub fn open(config: Config) -> Result<Self> {
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
        Ok(Self { config, store })
    }
}

impl Handler for App {
    fn handle(&self, request: &Request) -> Response {
        match (request.method, request.path.as_str()) {
            (Method::Get | Method::Head, "/healthz") => Response::text(200, "ok"),
            (_, "/healthz") => Response::text(405, "Method Not Allowed"),
            _ => Response::text(404, "Not Found"),
        }
    }

    fn hsts(&self) -> bool {
        false
    }
}
