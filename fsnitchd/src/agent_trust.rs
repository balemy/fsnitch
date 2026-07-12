//! Peer trust for agent connections: pin the peer via a pidfd, then require it
//! to be the agent binary in an active graphical logind session (same uid).
//! The pure decision (`evaluate_session`) is unit-tested; the pidfd/sd-login
//! plumbing needs a real session and is exercised via dev-run + manual checks.

use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

/// A logind session's trust-relevant facts.
#[cfg(feature = "session-hardening")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub active: bool,
    pub kind: String, // sd_session_get_type: "wayland"|"x11"|"mir"|"tty"|...
    pub uid: u32,
}

#[cfg(feature = "session-hardening")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionVerdict {
    Ok,
    NotInSession,
    NotActive,
    NotGraphical,
    UidMismatch,
}

/// Pure trust decision over a peer's session facts.
#[cfg(feature = "session-hardening")]
pub fn evaluate_session(info: Option<&SessionInfo>, peer_uid: u32) -> SessionVerdict {
    let Some(info) = info else {
        return SessionVerdict::NotInSession;
    };
    if info.uid != peer_uid {
        return SessionVerdict::UidMismatch;
    }
    if !info.active {
        return SessionVerdict::NotActive;
    }
    match info.kind.as_str() {
        "wayland" | "x11" | "mir" => SessionVerdict::Ok,
        _ => SessionVerdict::NotGraphical,
    }
}

/// Pidfd of the connected peer (TOCTOU-safe pin). None if the kernel/socket
/// doesn't support SO_PEERPIDFD (< 6.5) — caller falls back to SO_PEERCRED.
pub fn peer_pidfd(stream: &UnixStream) -> Option<OwnedFd> {
    use nix::sys::socket::{getsockopt, sockopt::PeerPidfd};
    getsockopt(stream, PeerPidfd).ok()
}

/// The pid a pidfd refers to, from /proc/self/fdinfo (`Pid:` line).
pub fn pid_from_pidfd(pidfd: &OwnedFd) -> Option<i32> {
    let content =
        std::fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd())).ok()?;
    content
        .lines()
        .find_map(|l| l.strip_prefix("Pid:").and_then(|v| v.trim().parse().ok()))
}

/// Session-binding gate. Hardened build: reject unless the peer is in an active
/// graphical logind session owned by `peer_uid` (when `require`). Base build:
/// always allow (the session check is compiled out; main() warns at startup if
/// `require` is set so the operator isn't misled).
#[cfg(feature = "session-hardening")]
pub fn session_gate(pid: i32, peer_uid: u32, require: bool) -> bool {
    if !require {
        return false;
    }
    let info = session_of(pid);
    let verdict = evaluate_session(info.as_ref(), peer_uid);
    if verdict != SessionVerdict::Ok {
        tracing::warn!(
            ?verdict,
            session = ?info,
            uid = peer_uid,
            "agent not in an active graphical session; rejecting"
        );
        return true;
    }
    false
}

#[cfg(not(feature = "session-hardening"))]
pub fn session_gate(_pid: i32, _peer_uid: u32, _require: bool) -> bool {
    false
}

// --- libsystemd sd-login FFI (isolated; the only unsafe here) ---
#[cfg(feature = "session-hardening")]
mod sd {
    use libc::{c_char, c_int, free, pid_t, uid_t};
    use std::ffi::{c_void, CStr};

    #[link(name = "systemd")]
    extern "C" {
        fn sd_pid_get_session(pid: pid_t, session: *mut *mut c_char) -> c_int;
        fn sd_session_is_active(session: *const c_char) -> c_int;
        fn sd_session_get_type(session: *const c_char, type_: *mut *mut c_char) -> c_int;
        fn sd_session_get_uid(session: *const c_char, uid: *mut uid_t) -> c_int;
    }

    /// Gather the peer's session facts, or None if the pid is in no logind
    /// session (or sd-login errors). Frees all libsystemd-allocated strings.
    pub fn session_of(pid: i32) -> Option<super::SessionInfo> {
        // SAFETY: FFI to libsystemd; out-pointers are freed below; strings are
        // copied out before free.
        unsafe {
            let mut session: *mut c_char = std::ptr::null_mut();
            if sd_pid_get_session(pid as pid_t, &mut session) < 0 || session.is_null() {
                return None;
            }
            let active = sd_session_is_active(session) > 0;

            let mut uid: uid_t = 0;
            let uid_ok = sd_session_get_uid(session, &mut uid) >= 0;

            let mut type_ptr: *mut c_char = std::ptr::null_mut();
            let kind = if sd_session_get_type(session, &mut type_ptr) >= 0 && !type_ptr.is_null() {
                let s = CStr::from_ptr(type_ptr).to_string_lossy().into_owned();
                free(type_ptr as *mut c_void);
                s
            } else {
                String::new()
            };

            free(session as *mut c_void);
            if !uid_ok {
                return None;
            }
            Some(super::SessionInfo {
                active,
                kind,
                uid: uid as u32,
            })
        }
    }
}
#[cfg(feature = "session-hardening")]
pub use sd::session_of;

#[cfg(all(test, feature = "session-hardening"))]
mod tests {
    use super::*;

    fn info(active: bool, kind: &str, uid: u32) -> SessionInfo {
        SessionInfo {
            active,
            kind: kind.into(),
            uid,
        }
    }

    #[test]
    fn active_graphical_same_uid_is_ok() {
        assert_eq!(
            evaluate_session(Some(&info(true, "wayland", 1000)), 1000),
            SessionVerdict::Ok
        );
        assert_eq!(
            evaluate_session(Some(&info(true, "x11", 1000)), 1000),
            SessionVerdict::Ok
        );
    }
    #[test]
    fn none_is_not_in_session() {
        assert_eq!(evaluate_session(None, 1000), SessionVerdict::NotInSession);
    }
    #[test]
    fn wrong_uid_rejected() {
        assert_eq!(
            evaluate_session(Some(&info(true, "wayland", 0)), 1000),
            SessionVerdict::UidMismatch
        );
    }
    #[test]
    fn inactive_rejected() {
        assert_eq!(
            evaluate_session(Some(&info(false, "wayland", 1000)), 1000),
            SessionVerdict::NotActive
        );
    }
    #[test]
    fn non_graphical_rejected() {
        assert_eq!(
            evaluate_session(Some(&info(true, "tty", 1000)), 1000),
            SessionVerdict::NotGraphical
        );
        assert_eq!(
            evaluate_session(Some(&info(true, "", 1000)), 1000),
            SessionVerdict::NotGraphical
        );
    }
}
