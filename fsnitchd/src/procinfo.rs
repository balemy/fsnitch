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

/// `(st_dev, st_ino)` of an open fd (the fanotify event target). None if the
/// stat fails. Used for inode-identity matching when the path no longer
/// resolves under a protected root.
pub fn stat_fd(fd: i32) -> Option<(u64, u64)> {
    use std::os::fd::BorrowedFd;
    // SAFETY: `fd` is a live descriptor owned by the caller for the duration of
    // this call; BorrowedFd does not take ownership and is dropped before the
    // caller closes the fd.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let st = nix::sys::stat::fstat(borrowed).ok()?;
    Some((st.st_dev as u64, st.st_ino as u64))
}

/// Birth time of an open fd, if the filesystem reports one. Compared against
/// the birth time captured at index time to unmask recycled inode numbers.
/// Reads only the already-open fd — no path re-open (an event-time open on the
/// marked filesystem would deadlock the enforcement loop).
pub fn btime_fd(fd: i32) -> Option<std::time::SystemTime> {
    use std::mem::ManuallyDrop;
    use std::os::fd::FromRawFd;
    // SAFETY: `fd` is a live descriptor owned by the caller for the duration of
    // this call; ManuallyDrop keeps the temporary File from closing it.
    let file = ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd) });
    file.metadata().ok().and_then(|md| md.created().ok())
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
    fn stat_fd_matches_metadata() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        let file = tempfile::NamedTempFile::new().unwrap();
        let (dev, ino) = stat_fd(file.as_file().as_raw_fd()).unwrap();
        let md = std::fs::metadata(file.path()).unwrap();
        assert_eq!((dev, ino), (md.dev(), md.ino()));
    }

    #[test]
    fn dead_pid_yields_none() {
        assert_eq!(exe_of(-1), None);
        assert_eq!(uid_of(-1), None);
    }
}
