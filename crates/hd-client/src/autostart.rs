//! Starting with the user's session, for this user alone and needing no
//! administrator: the `Run` key on Windows, and an XDG autostart entry on
//! Linux, which desktops read at sign-in.

use hd_common::{Error, Result};

/// This program, started as the daemon.
fn command() -> Result<String> {
    let exe = std::env::current_exe()?;
    let exe = exe.to_str().ok_or_else(|| Error::new("the program's path is not text"))?;
    if exe.contains('"') {
        return Err(Error::new("the program's path has a quotation mark in it"));
    }
    Ok(format!("\"{exe}\" daemon"))
}

#[cfg(windows)]
mod os {
    use hd_common::Result;
    use hd_sys::windows::run_key;

    /// Tests use a name of their own, to leave the real one alone.
    fn name() -> String {
        std::env::var("HOMEDRIVE_AUTOSTART_NAME").unwrap_or_else(|_| "homedrive".to_owned())
    }

    pub(super) fn current() -> Result<Option<String>> {
        Ok(run_key::get(&name())?)
    }

    pub(super) fn write(command: &str) -> Result<()> {
        Ok(run_key::set(&name(), command)?)
    }

    pub(super) fn clear() -> Result<()> {
        Ok(run_key::delete(&name())?)
    }
}

#[cfg(not(windows))]
mod os {
    use hd_common::{Result, fsio};

    use super::entry_path;

    const MAX_ENTRY: usize = 16 * 1024;

    fn exec_line(text: &str) -> Option<String> {
        text.lines().find_map(|l| l.strip_prefix("Exec=")).map(str::to_owned)
    }

    pub(super) fn current() -> Result<Option<String>> {
        let path = entry_path()?;
        Ok(fsio::read_text(path, MAX_ENTRY)?.as_deref().and_then(exec_line))
    }

    pub(super) fn write(command: &str) -> Result<()> {
        let path = entry_path()?;
        if let Some(dir) = path.parent() {
            fsio::mkdir_durable(dir, 0o755)?;
        }
        let entry = format!(
            "[Desktop Entry]\nType=Application\nName=homedrive\n\
             Comment=Keep your folders in sync\nExec={command}\nIcon=folder-sync\n\
             Terminal=false\nX-GNOME-Autostart-enabled=true\n"
        );
        fsio::atomic_replace(path, entry.as_bytes(), MAX_ENTRY)
    }

    pub(super) fn clear() -> Result<()> {
        crate::trash::remove_own_file(&entry_path()?)
    }
}

/// Where the Linux entry lives.
#[cfg(not(windows))]
fn entry_path() -> Result<std::path::PathBuf> {
    let config = crate::config::config_dir()?;
    let base = config.parent().ok_or_else(|| Error::new("no configuration folder"))?;
    Ok(base.join("autostart").join("homedrive.desktop"))
}

/// Whether homedrive starts at sign-in.
pub fn enabled() -> bool {
    os::current().ok().flatten().is_some()
}

/// Turns starting at sign-in on or off.
pub fn set(on: bool) -> Result<()> {
    if on { os::write(&command()?) } else { os::clear() }
}

/// If it is on but names another path, the program has moved: points it
/// here, or sign-in would start nothing.
pub fn refresh() -> Result<()> {
    if let (Some(stored), Ok(wanted)) = (os::current()?, command())
        && stored != wanted
    {
        os::write(&wanted)?;
    }
    Ok(())
}
