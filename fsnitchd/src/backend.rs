//! Enforcement backend abstraction. Today: fanotify. A BPF-LSM backend is planned.

use std::os::fd::OwnedFd;
use std::path::PathBuf;

/// Opaque handle the backend needs to answer a specific pending event.
pub struct EventToken(pub(crate) OwnedFd);

/// One gated open() waiting for a verdict.
pub struct AccessEvent {
    pub token: EventToken,
    pub path: Option<PathBuf>,
    pub pid: i32,
    pub exe: Option<PathBuf>,
    pub uid: Option<u32>,
    /// `(st_dev, st_ino)` of the target, for inode-identity matching. `(0, 0)`
    /// if the stat failed (won't match any real tracked inode).
    pub dev: u64,
    pub ino: u64,
    /// Birth time of the target, to unmask recycled inode numbers on the
    /// inode-identity fallback. `None` if the filesystem reports no btime.
    pub btime: Option<std::time::SystemTime>,
}

pub trait EnforcementBackend: Send + Sync {
    /// Block until at least one event arrives; return all queued events.
    /// Called only from the single enforcement thread.
    fn next_events(&self) -> anyhow::Result<Vec<AccessEvent>>;
    /// Answer a pending event. Callable from any thread; must be called
    /// exactly once per event.
    fn respond(&self, token: EventToken, allow: bool) -> anyhow::Result<()>;
    /// Idempotently make sure events for the filesystem containing `root`
    /// are delivered (marks are per-filesystem and set at startup for the
    /// configured roots; `fsnitch protect` needs them at runtime too).
    /// Callable from any thread.
    fn ensure_watched(&self, root: &std::path::Path) -> anyhow::Result<()>;
}
