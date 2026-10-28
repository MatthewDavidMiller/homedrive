//! The homedrive sync client: an engine that keeps local folders and the
//! server in step without ever losing a file, the state it keeps, and the
//! `homedrive` command around them.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::disallowed_methods))]

pub mod config;
pub mod engine;
pub mod http;
pub mod notify;
pub mod remote;
pub mod scan;
pub mod state;
pub mod trash;
