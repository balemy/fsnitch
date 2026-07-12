//! fanotify implementation of EnforcementBackend.
//!
//! Requires CAP_SYS_ADMIN and CONFIG_FANOTIFY_ACCESS_PERMISSIONS (Arch default kernel: yes).
//!
//! API drift note: nix 0.30.1's `FanotifyEvent::fd()` returns `Option<BorrowedFd>`
//! borrowed from the event itself (the event's `Drop` impl closes the fd), not an
//! owned fd handed to the caller. To keep `EventToken` holding a plain `OwnedFd`
//! (as `backend.rs` specifies), `next_events` below takes ownership of the raw
//! descriptor out of the `FanotifyEvent` and prevents the event's `Drop` from
//! closing it out from under us — see the safety comment at the call site.
//! `Fanotify::mark`'s `dirfd` parameter is a required `AsFd` value (not an
//! `Option`), so we pass `nix::fcntl::AT_FDCWD` (ignored by the kernel when an
//! absolute path is given, per fanotify_mark(2)).

use crate::backend::{AccessEvent, EnforcementBackend, EventToken};
use crate::procinfo;
use anyhow::Context;
use nix::fcntl::AT_FDCWD;
use nix::sys::fanotify::{
    EventFFlags, Fanotify, FanotifyResponse, InitFlags, MarkFlags, MaskFlags, Response,
};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

pub struct FanotifyBackend {
    fan: Fanotify,
}

impl FanotifyBackend {
    /// `roots`: the protected paths. We mark the whole filesystem containing
    /// each root (directory marks are not recursive) and filter in userspace
    /// via `CompiledPaths::policy_for` (an unmatched path returns `None`).
    pub fn new(roots: &[PathBuf]) -> anyhow::Result<FanotifyBackend> {
        let fan = Fanotify::init(
            InitFlags::FAN_CLASS_CONTENT | InitFlags::FAN_CLOEXEC | InitFlags::FAN_UNLIMITED_QUEUE,
            EventFFlags::O_RDONLY | EventFFlags::O_CLOEXEC,
        )
        .context("fanotify_init failed (need root/CAP_SYS_ADMIN)")?;

        let backend = FanotifyBackend { fan };
        for root in roots {
            backend.ensure_watched(root)?;
        }
        Ok(backend)
    }
}

/// Closest existing ancestor of `root` (the protected path itself may not
/// exist yet — protecting a not-yet-created vault dir is legal).
fn existing_ancestor(root: &Path) -> PathBuf {
    let mut p = root;
    while !p.exists() {
        p = p.parent().unwrap_or(Path::new("/"));
    }
    p.to_path_buf()
}

impl EnforcementBackend for FanotifyBackend {
    fn next_events(&self) -> anyhow::Result<Vec<AccessEvent>> {
        let events = self
            .fan
            .read_events()
            .context("fanotify read_events failed")?;
        let mut out = Vec::with_capacity(events.len());
        for event in events {
            // Queue-overflow events carry no fd; nothing to answer. Log upstream.
            let Some(fd) = event.fd() else {
                tracing::warn!("fanotify queue overflow — some events were dropped");
                continue;
            };
            let pid = event.pid();
            let raw = fd.as_raw_fd();
            let path = procinfo::path_of_fd(raw);
            let exe = procinfo::exe_of(pid);
            let uid = procinfo::uid_of(pid);

            // `event` currently owns `raw` and will `close()` it when dropped.
            // We need the descriptor to outlive this loop iteration until
            // `respond()` answers it, so take ownership of the raw fd
            // ourselves and stop `event` from closing it underneath us.
            //
            // SAFETY: `raw` is a valid, open file descriptor exclusively owned
            // by `event` here (guaranteed by `event.fd()` returning `Some`).
            // The `mem::forget(event)` below prevents `event`'s `Drop` impl
            // (which would otherwise `close(raw)`) from ever running, so
            // `owned` becomes the single owner of `raw` and no
            // double-close/use-after-close can occur.
            let owned = unsafe { OwnedFd::from_raw_fd(raw) };
            std::mem::forget(event);

            out.push(AccessEvent {
                token: EventToken(owned),
                path,
                pid,
                exe,
                uid,
            });
        }
        Ok(out)
    }

    fn respond(&self, token: EventToken, allow: bool) -> anyhow::Result<()> {
        let response = if allow {
            Response::FAN_ALLOW
        } else {
            Response::FAN_DENY
        };
        self.fan
            .write_response(FanotifyResponse::new(token.0.as_fd(), response))
            .context("fanotify write_response failed")?;
        // token.0 (the event fd) drops here, closing it — required after responding.
        Ok(())
    }

    fn ensure_watched(&self, root: &Path) -> anyhow::Result<()> {
        // Re-issue the mark unconditionally: FAN_MARK_ADD on an already-marked
        // filesystem is an idempotent merge, while any dedupe cache (e.g. by
        // st_dev) would go stale when a filesystem is unmounted (the kernel
        // drops its marks) and remounted with the same device id — a later
        // protect would then silently not enforce. Resolve the target once so
        // the path we mark is exactly the path we reasoned about.
        let target = existing_ancestor(root);
        self.fan
            .mark(
                MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_FILESYSTEM,
                MaskFlags::FAN_OPEN_PERM,
                AT_FDCWD,
                Some(target.as_path()),
            )
            .with_context(|| format!("fanotify_mark failed for {}", root.display()))?;
        Ok(())
    }
}
