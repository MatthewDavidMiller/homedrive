//! The homedrive sync client: an engine that keeps local folders and the
//! server in step without ever losing a file, the state it keeps, and the
//! `homedrive` command around them.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::disallowed_methods))]

/// `eprintln!`, except that a failed write is ignored. A background program
/// may have no working output, and `eprintln!` would end it over that.
#[macro_export]
macro_rules! say {
    ($($arg:tt)*) => {{
        let _ = ::std::io::Write::write_fmt(
            &mut ::std::io::stderr(),
            ::std::format_args!("{}\n", ::std::format_args!($($arg)*)),
        );
    }};
}

pub mod autostart;
pub mod config;
pub mod control;
pub mod copy;
pub mod crash;
pub mod engine;
mod generations;
pub mod gui;
pub mod history;
pub mod http;
pub mod notify;
pub mod remote;
pub mod restore;
pub mod scan;
pub mod service;
pub mod state;
pub mod trash;
pub mod tray;
pub mod vcs;
