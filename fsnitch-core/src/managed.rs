//! The CLI-managed paths drop-in (`paths.d/managed.toml`): path policies created
//! by `fsnitch protect`, owned and written exclusively by the daemon. The file is
//! an ordinary `[[path]]` drop-in that `Config::load` merges like any other.

use crate::config::PathPolicy;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Distinguishes concurrent temp files written by save().
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

const HEADER: &str = "# Managed by 'fsnitch protect' \u{2014} do not edit by hand.\n\n";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManagedPaths {
    #[serde(default, rename = "path")]
    paths: Vec<PathPolicy>,
    #[serde(skip)]
    file: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum ManagedError {
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
    #[error("failed to serialize managed paths: {0}")]
    Serialize(#[from] toml::ser::Error),
    #[error("{path} is already protected")]
    AlreadyProtected { path: String },
}

impl ManagedPaths {
    /// Load the managed drop-in; a missing file yields an empty store bound to `path`.
    pub fn load(path: &Path) -> Result<ManagedPaths, ManagedError> {
        if !path.exists() {
            return Ok(ManagedPaths {
                paths: Vec::new(),
                file: path.to_path_buf(),
            });
        }
        let text = std::fs::read_to_string(path).map_err(|source| ManagedError::Io {
            op: "reading",
            path: path.to_path_buf(),
            source,
        })?;
        let mut store: ManagedPaths =
            toml::from_str(&text).map_err(|source| ManagedError::Parse {
                path: path.to_path_buf(),
                source,
            })?;
        store.file = path.to_path_buf();
        // Canonicalize stored paths (in memory only) with the same helper the
        // daemon and CLI use, so a pre-canonicalization entry — or one whose
        // ancestor became a symlink — still compares equal for source labeling,
        // allow/deny, and unprotect. The file migrates on the next save.
        for p in &mut store.paths {
            let canon = crate::pathutil::canonicalize_lenient(Path::new(&p.path));
            let canon = canon.to_string_lossy();
            if canon != p.path {
                p.path = canon.into_owned();
            }
        }
        Ok(store)
    }

    /// The protected paths in this store (for `list`'s source column).
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.paths.iter().map(|p| p.path.as_str())
    }

    /// Add a policy; rejects a path that is already managed (exact match).
    pub fn add(&mut self, policy: PathPolicy) -> Result<(), ManagedError> {
        if self.paths.iter().any(|p| p.path == policy.path) {
            return Err(ManagedError::AlreadyProtected { path: policy.path });
        }
        self.paths.push(policy);
        Ok(())
    }

    /// Remove the policy whose path equals `path`.
    pub fn remove(&mut self, path: &str) -> Option<PathPolicy> {
        let idx = self.paths.iter().position(|p| p.path == path)?;
        Some(self.paths.remove(idx))
    }

    /// Persist atomically (unique temp file + rename), with a do-not-edit header.
    pub fn save(&self) -> Result<(), ManagedError> {
        if let Some(parent) = self.file.parent() {
            std::fs::create_dir_all(parent).map_err(|source| ManagedError::Io {
                op: "creating dir",
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let body = toml::to_string_pretty(self)?;
        let text = format!("{HEADER}{body}");
        let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = self
            .file
            .with_extension(format!("toml.tmp.{}.{}", std::process::id(), n));
        std::fs::write(&tmp, text).map_err(|source| ManagedError::Io {
            op: "writing",
            path: tmp.clone(),
            source,
        })?;
        std::fs::rename(&tmp, &self.file).map_err(|source| ManagedError::Io {
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
    use crate::config::{Config, Mode, PathPolicy};

    fn policy(path: &str) -> PathPolicy {
        PathPolicy {
            path: path.into(),
            mode: Mode::Ask,
            allow: vec![],
            deny: vec![],
        }
    }

    #[test]
    fn missing_file_loads_empty_and_saves() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("managed.toml");
        let mut m = ManagedPaths::load(&path).unwrap();
        assert!(m.paths.is_empty());
        m.add(policy("/data/a")).unwrap();
        m.save().unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("# Managed by 'fsnitch protect'"));
        // The saved file is a valid Config drop-in.
        let cfg = Config::parse_str(&text).unwrap();
        assert_eq!(cfg.paths.len(), 1);
        // And loads back.
        let again = ManagedPaths::load(&path).unwrap();
        assert_eq!(again.paths, m.paths);
    }

    #[test]
    fn add_rejects_duplicate_path() {
        let dir = tempfile::tempdir().unwrap();
        let mut m = ManagedPaths::load(&dir.path().join("m.toml")).unwrap();
        m.add(policy("/data/a")).unwrap();
        assert!(matches!(
            m.add(policy("/data/a")),
            Err(ManagedError::AlreadyProtected { .. })
        ));
    }

    #[test]
    fn remove_by_path() {
        let dir = tempfile::tempdir().unwrap();
        let mut m = ManagedPaths::load(&dir.path().join("m.toml")).unwrap();
        m.add(policy("/data/a")).unwrap();
        assert!(m.remove("/data/b").is_none());
        assert_eq!(m.remove("/data/a").unwrap().path, "/data/a");
        assert!(m.paths.is_empty());
    }
}
