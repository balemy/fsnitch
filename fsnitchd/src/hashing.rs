//! Pin hashes: sha256 of each pinned exe, computed at config load and verified
//! at event time via a `stat` (not an `open`) so no file is read on the fanotify
//! hot path — that read would self-deadlock.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// What we cached about a pinned file at load time.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HashEntry {
    dev: u64,
    ino: u64,
    mtime: i64,
    mtime_nsec: i64,
    hash: String,
}

/// Lowercase-hex sha256 of every readable pinned exe, keyed by path.
#[derive(Debug, Default)]
pub struct PinHashes {
    map: HashMap<PathBuf, HashEntry>,
}

pub(crate) fn hash_file(path: &Path) -> std::io::Result<String> {
    let bytes = std::fs::read(path)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

impl PinHashes {
    /// Hash each pinned exe once (reading the file). Unreadable/missing files are
    /// skipped — `verify` then returns `None`, so the pin fails safe.
    pub fn build<'a>(pinned_exes: impl Iterator<Item = &'a Path>) -> PinHashes {
        let mut map = HashMap::new();
        for exe in pinned_exes {
            if map.contains_key(exe) {
                continue;
            }
            match (std::fs::metadata(exe), hash_file(exe)) {
                (Ok(meta), Ok(hash)) => {
                    map.insert(
                        exe.to_path_buf(),
                        HashEntry {
                            dev: meta.dev(),
                            ino: meta.ino(),
                            mtime: meta.mtime(),
                            mtime_nsec: meta.mtime_nsec(),
                            hash,
                        },
                    );
                }
                _ => {
                    tracing::warn!(exe = %exe.display(), "pinned exe not readable at load; its pin will not verify");
                }
            }
        }
        PinHashes { map }
    }

    /// The cached hash for `exe`, but only if the file still matches the
    /// `(dev, ino, mtime)` seen at load (a `stat`, not an `open`). A changed or
    /// missing file returns `None` so the pin fails safe.
    pub fn verify(&self, exe: &Path) -> Option<String> {
        let entry = self.map.get(exe)?;
        let meta = std::fs::metadata(exe).ok()?;
        if meta.dev() == entry.dev
            && meta.ino() == entry.ino
            && meta.mtime() == entry.mtime
            && meta.mtime_nsec() == entry.mtime_nsec
        {
            Some(entry.hash.clone())
        } else {
            None
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.map.len()
    }
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write(path: &Path, contents: &[u8]) {
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(contents).unwrap();
    }

    #[test]
    fn verifies_unchanged_file_and_rejects_changed() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("borg");
        write(&exe, b"binary v1");

        let pins = PinHashes::build([exe.as_path()].into_iter());
        assert_eq!(pins.len(), 1);
        let h1 = pins.verify(&exe).expect("fresh file verifies");
        // Known sha256 of "binary v1"
        assert_eq!(h1.len(), 64);
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));

        // Change the file: a new mtime (and content) must invalidate the cache.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        write(&exe, b"binary v2 (tampered)");
        assert_eq!(pins.verify(&exe), None, "changed file must not verify");
    }

    #[test]
    fn missing_file_is_skipped_and_unverifiable() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("does-not-exist");
        let pins = PinHashes::build([exe.as_path()].into_iter());
        assert!(pins.is_empty());
        assert_eq!(pins.verify(&exe), None);
    }

    #[test]
    fn hash_matches_known_vector() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("f");
        write(&exe, b"abc");
        let pins = PinHashes::build([exe.as_path()].into_iter());
        // sha256("abc")
        assert_eq!(
            pins.verify(&exe).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn build_dedupes_repeated_paths() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("dup");
        write(&exe, b"x");
        let pins = PinHashes::build([exe.as_path(), exe.as_path()].into_iter());
        assert_eq!(pins.len(), 1);
    }
}
