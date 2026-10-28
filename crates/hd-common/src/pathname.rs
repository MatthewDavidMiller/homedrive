//! Paths inside a user's drive.
//!
//! A path is relative, `/`-separated, and UTF-8, with no empty, `.` or `..`
//! component, so one string names one place and nothing can climb out of
//! the drive. The drive's root is the empty string. Control characters
//! are refused: names travel through HTTP headers, logs, and XML, where
//! they cause trouble, and a client reports such a file instead of
//! syncing it.
//!
//! Names are compared byte for byte. [`fold_key`] gives the key clients on
//! case-insensitive filesystems use to find two names that would collide
//! there. [`windows_problem`] says why a name cannot exist on Windows.

use crate::{Error, Result};

pub const MAX_COMPONENT: usize = 255;
pub const MAX_PATH: usize = 4096;
/// Deeper trees are refused, which bounds every recursion over a tree.
pub const MAX_DEPTH: usize = 64;

/// Checks a path. The root (`""`) is valid.
pub fn validate(path: &str) -> Result<()> {
    if path.is_empty() {
        return Ok(());
    }
    if path.len() > MAX_PATH {
        return Err(Error::new("path is too long"));
    }
    let mut depth = 0;
    for component in path.split('/') {
        depth += 1;
        if component.is_empty() {
            return Err(Error::new("path has an empty component"));
        }
        if component == "." || component == ".." {
            return Err(Error::new("path has a . or .. component"));
        }
        if component.len() > MAX_COMPONENT {
            return Err(Error::new("path has a name longer than 255 bytes"));
        }
        if component.chars().any(char::is_control) {
            return Err(Error::new("path has a control character"));
        }
    }
    if depth > MAX_DEPTH {
        return Err(Error::new("path is too deep"));
    }
    Ok(())
}

/// The directory holding `path` (`""` for a top-level name or the root).
pub fn parent(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(dir, _)| dir)
}

/// The final component of `path`.
pub fn name(path: &str) -> &str {
    path.rsplit_once('/').map_or(path, |(_, name)| name)
}

pub fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() { name.to_owned() } else { format!("{dir}/{name}") }
}

/// Whether `path` is `dir` or lies beneath it. Everything is within the
/// root.
pub fn is_within(path: &str, dir: &str) -> bool {
    dir.is_empty()
        || path == dir
        || (path.len() > dir.len() && path.starts_with(dir) && path.as_bytes()[dir.len()] == b'/')
}

/// `path` re-rooted from `from` to `to`, for a path within `from`.
pub fn rebase(path: &str, from: &str, to: &str) -> Option<String> {
    if !is_within(path, from) {
        return None;
    }
    let rest = if from.is_empty() { path } else { path[from.len()..].trim_start_matches('/') };
    Some(if rest.is_empty() { to.to_owned() } else { join(to, rest) })
}

/// Every proper ancestor of `path`, nearest the root first, excluding the
/// root itself.
pub fn ancestors(path: &str) -> Vec<&str> {
    let mut out = Vec::new();
    for (i, b) in path.bytes().enumerate() {
        if b == b'/' {
            out.push(&path[..i]);
        }
    }
    out
}

/// The key two names collide under on a case-insensitive filesystem.
/// ASCII-only folding: that is what every client filesystem agrees on, and
/// a client still verifies before acting on a match.
pub fn fold_key(path: &str) -> String {
    path.to_ascii_lowercase()
}

/// Why a single name cannot be created on Windows, if it cannot.
pub fn windows_problem(name: &str) -> Option<&'static str> {
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    if name.contains(['<', '>', ':', '"', '\\', '|', '?', '*']) {
        return Some("contains a character Windows forbids");
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return Some("ends with a dot or a space");
    }
    let stem = name.split('.').next().unwrap_or(name).trim_end();
    if RESERVED.iter().any(|r| r.eq_ignore_ascii_case(stem)) {
        return Some("is a reserved device name on Windows");
    }
    None
}

/// The name for a conflicting copy of `path`, made by `device` at `stamp`
/// ("yyyy-mm-dd hhmm"). The suffix goes before the extension, so the copy
/// still opens with the same program.
pub fn conflict_name(path: &str, device: &str, stamp: &str) -> String {
    let device: String = device.chars().filter(|c| !c.is_control() && *c != '/').take(32).collect();
    suffixed_name(path, &format!("conflict {device} {stamp}"))
}

/// `path` with " (<label>)" before its extension, kept within the name
/// length limit by shortening the stem.
pub fn suffixed_name(path: &str, label: &str) -> String {
    let (dir, file) = (parent(path), name(path));
    let (stem, ext) = match file.rfind('.') {
        Some(i) if i > 0 => (&file[..i], &file[i..]),
        _ => (file, ""),
    };
    let label: String = label.chars().filter(|c| !c.is_control() && *c != '/').collect();
    let suffix = format!(" ({label})");
    let room = MAX_COMPONENT.saturating_sub(suffix.len() + ext.len());
    let mut cut = stem.len().min(room);
    while !stem.is_char_boundary(cut) {
        cut -= 1;
    }
    join(dir, &format!("{}{suffix}{ext}", &stem[..cut]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation() {
        for good in ["", "a", "a/b/c", "Ünïcødé/文件.txt", "a b/.hidden", "..x/x.."] {
            assert!(validate(good).is_ok(), "{good:?}");
        }
        for bad in ["/a", "a/", "a//b", ".", "..", "a/./b", "a/../b", "a\nb", "a\0b", "a\u{7f}"] {
            assert!(validate(bad).is_err(), "{bad:?}");
        }
        assert!(validate(&"x".repeat(256)).is_err());
        assert!(validate(&"x".repeat(255)).is_ok());
        assert!(validate(&vec!["d"; 65].join("/")).is_err());
        assert!(validate(&vec!["d"; 64].join("/")).is_ok());
    }

    #[test]
    fn structure() {
        assert_eq!(parent("a/b/c"), "a/b");
        assert_eq!(parent("a"), "");
        assert_eq!(name("a/b/c"), "c");
        assert_eq!(name("a"), "a");
        assert_eq!(join("", "a"), "a");
        assert_eq!(join("a", "b"), "a/b");
        assert!(is_within("a/b", "a"));
        assert!(is_within("a", "a"));
        assert!(is_within("a", ""));
        assert!(!is_within("ab", "a"));
        assert!(!is_within("a", "a/b"));
        assert_eq!(rebase("a/b/c", "a", "x").as_deref(), Some("x/b/c"));
        assert_eq!(rebase("a", "a", "x/y").as_deref(), Some("x/y"));
        assert_eq!(rebase("ab", "a", "x"), None);
        assert_eq!(ancestors("a/b/c"), vec!["a", "a/b"]);
        assert!(ancestors("a").is_empty());
    }

    #[test]
    fn windows_names() {
        assert!(windows_problem("report.txt").is_none());
        assert!(windows_problem("a:b").is_some());
        assert!(windows_problem("con").is_some());
        assert!(windows_problem("COM1.txt").is_some());
        assert!(windows_problem("console").is_none());
        assert!(windows_problem("trailing.").is_some());
        assert!(windows_problem("trailing ").is_some());
        assert_eq!(fold_key("Docs/A.TXT"), "docs/a.txt");
    }

    #[test]
    fn conflict_names_keep_extensions_and_limits() {
        assert_eq!(
            conflict_name("docs/report.txt", "laptop", "2026-10-27 1405"),
            "docs/report (conflict laptop 2026-10-27 1405).txt"
        );
        assert_eq!(conflict_name("Makefile", "pc", "s"), "Makefile (conflict pc s)");
        assert_eq!(conflict_name(".bashrc", "pc", "s"), ".bashrc (conflict pc s)");
        let long = conflict_name(&format!("{}.txt", "é".repeat(127)), "d", "s");
        assert!(validate(&long).is_ok());
        assert!(long.ends_with(" (conflict d s).txt"));
        assert_eq!(suffixed_name("a/b.tar.gz", "restored"), "a/b.tar (restored).gz");
    }
}
