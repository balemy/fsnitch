//! Inode-identity index: `(st_dev, st_ino) -> protected root`. Consulted as a
//! fallback when a file's current path no longer matches a protected root
//! (e.g. after a same-filesystem `rename` out of the root). Built by
//! `scan_roots`; in Phase 2 also kept fresh live by the inotify watcher.
//!
//! A single global `cap` bounds total tracked inodes. A root whose scan would
//! exceed it is *degraded*: its inodes are dropped (move protection off, path
//! protection unchanged) and it is recorded in `degraded_roots` so the daemon
//! can warn and surface it in status. Degradation is fail-safe — it only
//! removes the extra recognition, never weakens the path policy.

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;

/// `(st_dev, st_ino)`.
pub type InodeKey = (u64, u64);

#[derive(Debug)]
pub struct InodeIndex {
    /// Interned root path strings, indexed by `root_idx`.
    roots: Vec<Arc<str>>,
    /// `(dev, ino) -> root_idx`.
    entries: HashMap<InodeKey, u32>,
    /// `root_idx`es that exceeded the cap (entries dropped).
    degraded: Vec<u32>,
    /// Global maximum number of tracked inodes.
    cap: usize,
}

impl InodeIndex {
    pub fn new(cap: usize) -> InodeIndex {
        InodeIndex {
            roots: Vec::new(),
            entries: HashMap::new(),
            degraded: Vec::new(),
            cap,
        }
    }

    /// Intern a root path and return its index (deduplicated per distinct string).
    pub fn add_root(&mut self, root: &str) -> u32 {
        if let Some(i) = self.roots.iter().position(|r| &**r == root) {
            return i as u32;
        }
        let i = self.roots.len() as u32;
        self.roots.push(Arc::from(root));
        i
    }

    /// Insert `(dev, ino)` under `root_idx`. Returns false and inserts nothing if
    /// the global cap is already reached (an update of an existing key always
    /// succeeds — it does not grow the set).
    pub fn try_insert(&mut self, dev: u64, ino: u64, root_idx: u32) -> bool {
        let key = (dev, ino);
        if !self.entries.contains_key(&key) && self.entries.len() >= self.cap {
            return false;
        }
        self.entries.insert(key, root_idx);
        true
    }

    /// Live eviction (Phase 2). No-op if absent.
    pub fn remove(&mut self, dev: u64, ino: u64) {
        self.entries.remove(&(dev, ino));
    }

    /// Mark `root_idx` degraded: drop all its entries and record it.
    pub fn degrade(&mut self, root_idx: u32) {
        self.entries.retain(|_, &mut idx| idx != root_idx);
        if !self.degraded.contains(&root_idx) {
            self.degraded.push(root_idx);
        }
    }

    /// The protected root owning `(dev, ino)`, if tracked.
    pub fn root_for(&self, dev: u64, ino: u64) -> Option<&str> {
        let idx = *self.entries.get(&(dev, ino))?;
        Some(&self.roots[idx as usize])
    }

    /// Roots that were degraded (cap exceeded), as owned strings for status.
    pub fn degraded_roots(&self) -> Vec<String> {
        self.degraded
            .iter()
            .map(|&i| self.roots[i as usize].to_string())
            .collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Walk each root recursively and index the `(dev, ino)` of every regular file
/// underneath, tagged with that root. Symlinks (and symlinked directories),
/// directories themselves, and special files are not indexed — a moved
/// directory keeps its descendants' inodes (held individually), and a symlink
/// open resolves to its target's inode (held separately if under a root).
/// A root that would exceed `cap` is degraded (see `InodeIndex::degrade`).
pub fn scan_roots<P: AsRef<Path>>(roots: &[P], cap: usize) -> InodeIndex {
    let mut idx = InodeIndex::new(cap);
    for root in roots {
        let root = root.as_ref();
        let root_idx = idx.add_root(&root.to_string_lossy());
        let ok = match std::fs::symlink_metadata(root) {
            Ok(md) if md.file_type().is_file() => idx.try_insert(md.dev(), md.ino(), root_idx),
            Ok(md) if md.file_type().is_dir() => scan_dir(root, root_idx, &mut idx),
            // nonexistent / symlink / special: nothing to index
            _ => true,
        };
        if !ok {
            idx.degrade(root_idx);
        }
    }
    idx
}

/// Recurse a directory. Returns false as soon as the cap is hit (caller
/// degrades the root). Uses `DirEntry::file_type`/`metadata`, neither of which
/// follows symlinks, so symlinked directories are never traversed.
fn scan_dir(dir: &Path, root_idx: u32, idx: &mut InodeIndex) -> bool {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return true;
    };
    for entry in rd.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_file() {
            if let Ok(md) = entry.metadata() {
                if !idx.try_insert(md.dev(), md.ino(), root_idx) {
                    return false;
                }
            }
        } else if ft.is_dir() && !scan_dir(&entry.path(), root_idx, idx) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ino_of(p: &Path) -> (u64, u64) {
        let md = std::fs::metadata(p).unwrap();
        (md.dev(), md.ino())
    }

    #[test]
    fn insert_and_lookup() {
        let mut idx = InodeIndex::new(100);
        let r = idx.add_root("/vaults");
        assert!(idx.try_insert(66, 1234, r));
        assert_eq!(idx.root_for(66, 1234), Some("/vaults"));
        assert_eq!(idx.root_for(66, 9999), None);
    }

    #[test]
    fn add_root_dedups() {
        let mut idx = InodeIndex::new(100);
        assert_eq!(idx.add_root("/a"), 0);
        assert_eq!(idx.add_root("/b"), 1);
        assert_eq!(idx.add_root("/a"), 0);
    }

    #[test]
    fn cap_blocks_new_but_allows_update() {
        let mut idx = InodeIndex::new(1);
        let r = idx.add_root("/v");
        assert!(idx.try_insert(1, 1, r));
        assert!(!idx.try_insert(1, 2, r)); // cap reached
        assert!(idx.try_insert(1, 1, r)); // update existing key still ok
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn degrade_drops_root_entries_only() {
        let mut idx = InodeIndex::new(100);
        let a = idx.add_root("/a");
        let b = idx.add_root("/b");
        idx.try_insert(1, 1, a);
        idx.try_insert(1, 2, a);
        idx.try_insert(1, 3, b);
        idx.degrade(a);
        assert_eq!(idx.root_for(1, 1), None);
        assert_eq!(idx.root_for(1, 3), Some("/b"));
        assert_eq!(idx.degraded_roots(), vec!["/a".to_string()]);
    }

    #[test]
    fn remove_evicts() {
        let mut idx = InodeIndex::new(100);
        let r = idx.add_root("/v");
        idx.try_insert(7, 7, r);
        idx.remove(7, 7);
        assert_eq!(idx.root_for(7, 7), None);
    }

    #[test]
    fn scans_regular_files_recursively() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("vault");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        let a = root.join("a.kdbx");
        let b = root.join("sub/b.kdbx");
        std::fs::write(&a, "x").unwrap();
        std::fs::write(&b, "y").unwrap();

        let idx = scan_roots(std::slice::from_ref(&root), usize::MAX);
        let (da, ia) = ino_of(&a);
        let (db, ib) = ino_of(&b);
        assert_eq!(idx.root_for(da, ia), Some(root.to_string_lossy().as_ref()));
        assert_eq!(idx.root_for(db, ib), Some(root.to_string_lossy().as_ref()));
    }

    #[test]
    fn skips_symlinks_and_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("v");
        std::fs::create_dir_all(&root).unwrap();
        let target = dir.path().join("outside.txt");
        std::fs::write(&target, "z").unwrap();
        std::os::unix::fs::symlink(&target, root.join("link")).unwrap();

        let idx = scan_roots(std::slice::from_ref(&root), usize::MAX);
        // The symlink's target lives outside the root and must not be indexed.
        let (dt, it) = ino_of(&target);
        assert_eq!(idx.root_for(dt, it), None);
        // The root directory inode itself is not indexed.
        let (dr, ir) = ino_of(&root);
        assert_eq!(idx.root_for(dr, ir), None);
    }

    #[test]
    fn single_file_root_is_indexed() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("secret.kdbx");
        std::fs::write(&f, "x").unwrap();
        let idx = scan_roots(std::slice::from_ref(&f), usize::MAX);
        let (d, i) = ino_of(&f);
        assert_eq!(idx.root_for(d, i), Some(f.to_string_lossy().as_ref()));
    }

    #[test]
    fn nonexistent_root_is_harmless() {
        let idx = scan_roots(&[std::path::PathBuf::from("/no/such/path/xyz")], usize::MAX);
        assert!(idx.is_empty());
    }

    #[test]
    fn cap_degrades_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("big");
        std::fs::create_dir_all(&root).unwrap();
        for n in 0..5 {
            std::fs::write(root.join(format!("f{n}")), "x").unwrap();
        }
        let idx = scan_roots(std::slice::from_ref(&root), 3); // cap below file count
        assert_eq!(
            idx.degraded_roots(),
            vec![root.to_string_lossy().to_string()]
        );
        // Degraded root contributes no entries.
        assert!(idx.is_empty());
    }
}
