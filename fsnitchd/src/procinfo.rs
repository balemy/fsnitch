//! Subject resolution via /proc.

use std::path::PathBuf;

/// Canonical executable path of a process; None if it exited or is inaccessible.
pub fn exe_of(pid: i32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

/// Real UID of a process, parsed from /proc/<pid>/status.
pub fn uid_of(pid: i32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = status.lines().find(|l| l.starts_with("Uid:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

/// Path of an open fd in *our* process (fanotify hands us an fd to the target).
pub fn path_of_fd(fd: i32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn exe_of_self_is_this_test_binary() {
        let me = std::process::id() as i32;
        let exe = exe_of(me).unwrap();
        assert!(exe.is_absolute());
        // cargo test binaries live under target/
        assert!(exe.to_string_lossy().contains("target"));
    }

    #[test]
    fn uid_of_self_matches() {
        let me = std::process::id() as i32;
        assert_eq!(uid_of(me), Some(nix::unistd::getuid().as_raw()));
    }

    #[test]
    fn path_of_fd_resolves() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = path_of_fd(file.as_file().as_raw_fd()).unwrap();
        assert_eq!(path, file.path().canonicalize().unwrap());
    }

    #[test]
    fn dead_pid_yields_none() {
        assert_eq!(exe_of(-1), None);
        assert_eq!(uid_of(-1), None);
    }
}
