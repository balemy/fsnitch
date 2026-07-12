//! The sole filesystem-touching helper in `fsnitch-core`, kept apart from the
//! pure matcher. Resolves a path to the kernel-canonical form the daemon sees
//! from `/proc/self/fd`, tolerating not-yet-existing targets.

use std::path::{Path, PathBuf};

/// Canonicalize the longest existing ancestor of `path` (resolving all
/// symlinks) and re-append the non-existent remainder. Idempotent on an
/// already-canonical path. Best-effort: if the existing prefix can't be
/// canonicalized (e.g. EACCES) or the path has no resolvable base (a relative,
/// non-existent path), the input is returned unchanged rather than erroring —
/// the daemon must never refuse to start over one path.
pub fn canonicalize_lenient(path: &Path) -> PathBuf {
    let mut existing = path;
    let mut remainder: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if existing.exists() {
            break;
        }
        match (existing.parent(), existing.file_name()) {
            (Some(parent), Some(name)) => {
                remainder.push(name.to_os_string());
                existing = parent;
            }
            // No parent / no file name (empty or relative root): unresolvable.
            _ => return path.to_path_buf(),
        }
    }
    let mut base = match existing.canonicalize() {
        Ok(c) => c,
        Err(_) => return path.to_path_buf(),
    };
    for name in remainder.iter().rev() {
        base.push(name);
    }
    base
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn already_canonical_is_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        // tempdir() may itself sit under a symlinked $TMPDIR; compare against
        // its own canonical form so the test is about idempotence, not layout.
        let canon = dir.path().canonicalize().unwrap();
        assert_eq!(canonicalize_lenient(&canon), canon);
    }

    #[test]
    fn resolves_symlinked_ancestor() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::create_dir(real.join("vaults")).unwrap();
        let link = dir.path().join("link");
        symlink(&real, &link).unwrap(); // link -> real
                                        // A path through the symlink resolves to the real location.
        let via_link = link.join("vaults");
        let expected = real.join("vaults").canonicalize().unwrap();
        assert_eq!(canonicalize_lenient(&via_link), expected);
    }

    #[test]
    fn keeps_nonexistent_leaf_under_real_dir() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let leaf = base.join("not-yet.kdbx"); // does not exist
        assert_eq!(canonicalize_lenient(&leaf), leaf);
    }

    #[test]
    fn resolves_symlinked_dir_and_keeps_nonexistent_leaf() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();
        let via_link = link.join("newvault.kdbx"); // leaf doesn't exist
        let expected = real.canonicalize().unwrap().join("newvault.kdbx");
        assert_eq!(canonicalize_lenient(&via_link), expected);
    }

    #[test]
    fn is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();
        let via_link = link.join("a/b"); // nested nonexistent under symlink
        let once = canonicalize_lenient(&via_link);
        let twice = canonicalize_lenient(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn relative_nonexistent_returns_input() {
        let p = Path::new("some/relative/none");
        assert_eq!(canonicalize_lenient(p), p.to_path_buf());
    }
}
