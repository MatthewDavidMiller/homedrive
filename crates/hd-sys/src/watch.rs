//! A wake-up hint for the sync client: "something under this folder may
//! have changed". inotify on Linux, a recursive change notification on
//! Windows, and plain timed waits elsewhere. The client rescans to learn
//! what changed, so a missed or spurious wake-up only costs time.

use std::io;
use std::path::Path;

#[derive(Debug)]
pub struct Watcher {
    #[cfg(target_os = "linux")]
    inner: crate::posix::inotify::Inotify,
    #[cfg(windows)]
    inner: Vec<crate::windows::ChangeNotification>,
}

impl Watcher {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            #[cfg(target_os = "linux")]
            inner: crate::posix::inotify::Inotify::new()?,
            #[cfg(windows)]
            inner: Vec::new(),
        })
    }

    /// Whether directories must be added one by one (Linux) or the root
    /// covers its whole tree (Windows).
    pub fn recursive(&self) -> bool {
        cfg!(windows)
    }

    /// Watches `dir`. On Windows only the first call (the folder's root)
    /// does anything, since that watch covers the whole tree.
    pub fn watch_dir(&mut self, dir: &Path) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.inner.watch_dir(dir)
        }
        #[cfg(windows)]
        {
            if self.inner.is_empty() {
                self.inner.push(crate::windows::ChangeNotification::new(dir)?);
            }
            Ok(())
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            let _ = dir;
            Ok(())
        }
    }

    /// Waits up to `ms` for a change; true if one was seen.
    pub fn wait(&mut self, ms: u32) -> io::Result<bool> {
        #[cfg(target_os = "linux")]
        {
            self.inner.wait(i32::try_from(ms).unwrap_or(i32::MAX))
        }
        #[cfg(windows)]
        {
            if let Some(n) = self.inner.first_mut() {
                n.wait(ms)
            } else {
                std::thread::sleep(std::time::Duration::from_millis(u64::from(ms)));
                Ok(false)
            }
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            std::thread::sleep(std::time::Duration::from_millis(u64::from(ms)));
            Ok(false)
        }
    }
}
