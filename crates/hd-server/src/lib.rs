//! The homedrive server: configuration and the HTTP handler that the store,
//! the sync API, WebDAV, and the web UI are assembled into.
//!
//! At this milestone (M0) it answers only `/healthz`; docs/PLAN.md lists
//! what each later milestone adds.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::disallowed_methods))]

pub mod config;

use hd_http::{Handler, Method, Request, Response};

use crate::config::Config;

#[derive(Debug)]
pub struct App {
    pub config: Config,
}

impl App {
    pub fn new(config: Config) -> Self {
        Self { config }
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
