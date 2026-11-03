//! A wake-up hint for the sync client: "something under this folder may
//! have changed". inotify on Linux, and a recursive change notification on
//! Windows. The client rescans to learn
//! what changed, so a missed or spurious wake-up only costs time.

use std::io;
#[cfg(target_os = "linux")]
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

/// Ends a [`Watcher::wait`] from another thread, and every wait after it, so
/// a waiting thread can sleep for as long as it likes and still stop at once.
#[derive(Debug)]
pub struct Waker {
    #[cfg(target_os = "linux")]
    pipe: io::PipeWriter,
    #[cfg(windows)]
    event: crate::windows::WakeEvent,
}

impl Waker {
    pub fn wake(&self) {
        #[cfg(target_os = "linux")]
        {
            // Nothing reads it, so it stays readable: one byte is for good.
            let _ = (&self.pipe).write_all(&[1]);
        }
        #[cfg(windows)]
        self.event.set();
    }
}

#[derive(Debug)]
pub struct Watcher {
    #[cfg(target_os = "linux")]
    inner: crate::posix::inotify::Inotify,
    #[cfg(target_os = "linux")]
    woken: io::PipeReader,
    #[cfg(windows)]
    inner: Vec<crate::windows::ChangeNotification>,
    waker: Arc<Waker>,
}

impl Watcher {
    pub fn new() -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let (woken, pipe) = io::pipe()?;
            Ok(Self {
                inner: crate::posix::inotify::Inotify::new()?,
                woken,
                waker: Arc::new(Waker { pipe }),
            })
        }
        #[cfg(windows)]
        {
            let event = crate::windows::WakeEvent::new()?;
            Ok(Self { inner: Vec::new(), waker: Arc::new(Waker { event }) })
        }
    }

    pub fn waker(&self) -> Arc<Waker> {
        Arc::clone(&self.waker)
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
    }

    /// Waits up to `ms` for a change, or for the [`Waker`]; true if a
    /// change was seen.
    pub fn wait(&mut self, ms: u32) -> io::Result<bool> {
        #[cfg(target_os = "linux")]
        {
            self.inner.wait(i32::try_from(ms).unwrap_or(i32::MAX), &self.woken)
        }
        #[cfg(windows)]
        {
            if let Some(n) = self.inner.first_mut() {
                n.wait(ms, &self.waker.event)
            } else {
                self.waker.event.wait(ms);
                Ok(false)
            }
        }
    }
}
