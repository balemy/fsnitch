//! Persistent remembered verdicts: (path, program) -> allow|deny.
//! Written by the daemon when a user picks an "always" verdict in the prompt.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Distinguishes concurrent temp files written by persist().
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RememberedEntry {
    path: String,
    program: PathBuf,
    /// true = allow forever, false = deny forever.
    allow: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RememberedStore {
    #[serde(default, rename = "entry")]
    entries: Vec<RememberedEntry>,
    /// On-disk path of the store file (named `file` to avoid clashing with an
    /// entry's protected `path`).
    #[serde(skip)]
    file: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum RememberedError {
    #[error("{op} {path:?} failed: {source}")]
    Io {
        op: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse {path:?}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("failed to serialize remembered store: {0}")]
    Serialize(#[from] toml::ser::Error),
}

impl RememberedStore {
    /// Load the store; a missing file yields an empty store bound to `path`.
    pub fn load(path: &Path) -> Result<RememberedStore, RememberedError> {
        if !path.exists() {
            return Ok(RememberedStore {
                entries: Vec::new(),
                file: path.to_path_buf(),
            });
        }
        let text = std::fs::read_to_string(path).map_err(|source| RememberedError::Io {
            op: "reading",
            path: path.to_path_buf(),
            source,
        })?;
        let mut store: RememberedStore =
            toml::from_str(&text).map_err(|source| RememberedError::Parse {
                path: path.to_path_buf(),
                source,
            })?;
        store.file = path.to_path_buf();
        Ok(store)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up a verdict; `Some(true)` = allow, `Some(false)` = deny, `None` = no entry.
    pub fn get(&self, path: &str, program: &Path) -> Option<bool> {
        self.entries
            .iter()
            .find(|e| e.path == path && e.program == program)
            .map(|e| e.allow)
    }

    /// Insert or replace a verdict and persist atomically (temp file + rename).
    pub fn set(
        &mut self,
        path: &str,
        program: PathBuf,
        allow: bool,
    ) -> Result<(), RememberedError> {
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.path == path && e.program == program)
        {
            existing.allow = allow;
        } else {
            self.entries.push(RememberedEntry {
                path: path.to_string(),
                program,
                allow,
            });
        }
        self.persist()
    }

    /// All stored verdicts as (path, program, allow) triples.
    pub fn entries(&self) -> Vec<(String, PathBuf, bool)> {
        self.entries
            .iter()
            .map(|e| (e.path.clone(), e.program.clone(), e.allow))
            .collect()
    }

    /// Drop verdicts for `path` (all of them, or only `program`'s) and persist.
    /// Returns how many were removed.
    pub fn remove_matching(
        &mut self,
        path: &str,
        program: Option<&Path>,
    ) -> Result<usize, RememberedError> {
        let before = self.entries.len();
        self.entries
            .retain(|e| !(e.path == path && program.is_none_or(|x| e.program == x)));
        let removed = before - self.entries.len();
        if removed > 0 {
            self.persist()?;
        }
        Ok(removed)
    }

    /// Drop every verdict stored for `path` and persist. Returns whether
    /// anything changed. Used when a path is unprotected so a later policy on
    /// the same path doesn't silently resurrect old "forever" verdicts.
    pub fn remove_path(&mut self, path: &str) -> Result<bool, RememberedError> {
        self.remove_matching(path, None).map(|n| n > 0)
    }

    fn persist(&self) -> Result<(), RememberedError> {
        // An in-memory store (e.g. Default) has no path; skip persistence.
        if self.file.as_os_str().is_empty() {
            return Ok(());
        }
        if let Some(parent) = self.file.parent() {
            std::fs::create_dir_all(parent).map_err(|source| RememberedError::Io {
                op: "creating dir",
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let text = toml::to_string_pretty(self)?;
        // Unique temp name per (process, call) so concurrent persists never
        // clobber each other's in-progress temp file before the atomic rename.
        let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = self
            .file
            .with_extension(format!("toml.tmp.{}.{}", std::process::id(), n));
        std::fs::write(&tmp, text).map_err(|source| RememberedError::Io {
            op: "writing",
            path: tmp.clone(),
            source,
        })?;
        std::fs::rename(&tmp, &self.file).map_err(|source| RememberedError::Io {
            op: "renaming to",
            path: self.file.clone(),
            source,
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn empty_when_file_absent() {
        let dir = tempfile::tempdir().unwrap();
        let store = RememberedStore::load(&dir.path().join("remembered.toml")).unwrap();
        assert_eq!(
            store.get("/home/luke/vaults", &PathBuf::from("/usr/bin/keepassxc")),
            None
        );
    }

    #[test]
    fn set_persists_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("remembered.toml");
        let mut store = RememberedStore::load(&path).unwrap();
        store
            .set("/vaults", PathBuf::from("/usr/bin/keepassxc"), true)
            .unwrap();
        store
            .set("/vaults", PathBuf::from("/tmp/stealer"), false)
            .unwrap();

        let reloaded = RememberedStore::load(&path).unwrap();
        assert_eq!(
            reloaded.get("/vaults", &PathBuf::from("/usr/bin/keepassxc")),
            Some(true)
        );
        assert_eq!(
            reloaded.get("/vaults", &PathBuf::from("/tmp/stealer")),
            Some(false)
        );
        assert_eq!(
            reloaded.get("/vaults", &PathBuf::from("/usr/bin/other")),
            None
        );
    }

    #[test]
    fn entries_and_remove_matching() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("remembered.toml");
        let mut store = RememberedStore::load(&path).unwrap();
        store
            .set("/vaults", PathBuf::from("/usr/bin/keepassxc"), true)
            .unwrap();
        store
            .set("/vaults", PathBuf::from("/tmp/stealer"), false)
            .unwrap();
        store
            .set("/other", PathBuf::from("/usr/bin/cat"), true)
            .unwrap();
        assert_eq!(store.entries().len(), 3);

        // Program-filtered removal drops only that entry.
        assert_eq!(
            store
                .remove_matching("/vaults", Some(&PathBuf::from("/tmp/stealer")))
                .unwrap(),
            1
        );
        assert_eq!(store.get("/vaults", &PathBuf::from("/tmp/stealer")), None);
        assert_eq!(
            store.get("/vaults", &PathBuf::from("/usr/bin/keepassxc")),
            Some(true)
        );

        // Path-wide removal drops the rest of the path; other paths survive.
        assert_eq!(store.remove_matching("/vaults", None).unwrap(), 1);
        assert_eq!(store.remove_matching("/vaults", None).unwrap(), 0);
        assert_eq!(
            store.get("/other", &PathBuf::from("/usr/bin/cat")),
            Some(true)
        );

        // Persisted, not just in-memory.
        let reloaded = RememberedStore::load(&path).unwrap();
        assert_eq!(reloaded.entries().len(), 1);
    }

    #[test]
    fn set_replaces_existing_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("remembered.toml");
        let mut store = RememberedStore::load(&path).unwrap();
        store.set("/p", PathBuf::from("/x"), true).unwrap();
        store.set("/p", PathBuf::from("/x"), false).unwrap();
        assert_eq!(store.get("/p", &PathBuf::from("/x")), Some(false));
        // no duplicate rows
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn keys_are_path_and_program_specific() {
        let mut store = RememberedStore::default();
        store.set("/p1", PathBuf::from("/x"), true).unwrap_or(());
        // (different path, same program) and (same path, different program) are distinct
        assert_eq!(store.get("/p2", &PathBuf::from("/x")), None);
        assert_eq!(store.get("/p1", &PathBuf::from("/y")), None);
    }
}
