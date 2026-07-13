# Inode-identity Move Protection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep a protected file protected after a same-filesystem `rename` out of its root, by taking the open() verdict on `(st_dev, st_ino)` identity when the current path no longer matches a root.

**Architecture:** A userspace inode index maps `(dev, ino) → protected root`. Phase 1 builds it by a recursive scan at snapshot build (load + reload) and consults it as a fallback in `decide_event` after the existing path match misses. Phase 2 keeps it fresh between reloads with an inotify watcher thread. Enforcement stays entirely on the existing whole-filesystem fanotify mark; the index only adds *recognition*.

**Tech Stack:** Rust, `nix` 0.30 (fanotify + inotify wrappers), `std::os::unix::fs::MetadataExt`, existing `fsnitch-core` / `fsnitchd` workspace crates.

> **Git note (user policy):** Do NOT run `git commit` unless the user explicitly asks. The "Commit" steps below mean: stage the listed files and prepare the message; hold the actual commit until the user requests it. Verification (build/test) still runs at each step.

**Spec:** `docs/superpowers/specs/2026-07-13-inode-identity-move-protection-design.md`

---

## File Structure

Phase 1 (scan-based, mergeable on its own):

- `fsnitch-core/src/inode_index.rs` **(new)** — `InodeIndex` type + `scan_roots` scanner. Pure data + filesystem walk; no threading, no `tracing`.
- `fsnitch-core/src/lib.rs` — export `inode_index`.
- `fsnitch-core/src/rules.rs` — `CompiledPaths::policy_for_inode`.
- `fsnitch-core/src/config.rs` — `General.max_tracked_inodes`.
- `fsnitch-core/src/protocol.rs` — `Response::Status.degraded_roots`.
- `fsnitchd/src/procinfo.rs` — `stat_fd` helper.
- `fsnitchd/src/backend.rs` — `AccessEvent { dev, ino }`.
- `fsnitchd/src/fanotify.rs` — fill `dev`/`ino` via `stat_fd` in `next_events`.
- `fsnitchd/src/engine.rs` — inode fallback in `decide_event`.
- `fsnitchd/src/state.rs` — build `inode_index` in `Snapshot`; propagate it in the clone-based constructors; log degraded roots.
- `fsnitchd/src/main.rs` — pass `event.dev`/`event.ino` + snapshot index into `decide_event`.
- `fsnitchd/src/control.rs` — return `degraded_roots` in `Status`.
- `fsnitch-cli/src/output.rs` — render degraded roots in `status`.
- `SECURITY.md`, `CONFIGURATION.md`, `CHANGELOG.md` — docs.

Phase 2 (inotify live freshness):

- `fsnitchd/src/inode_watch.rs` **(new)** — `LiveInodeIndex` (shared, interior-mutable) + inotify watcher thread.
- `fsnitchd/src/state.rs`, `fsnitchd/src/main.rs`, `fsnitchd/src/control.rs` — move the index from `Snapshot` to the shared `LiveInodeIndex`; reseed on reload.

---

# PHASE 1 — Scan-based inode index

## Task 1: Config key `max_tracked_inodes`

**Files:**
- Modify: `fsnitch-core/src/config.rs`

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `fsnitch-core/src/config.rs`:

```rust
#[test]
fn max_tracked_inodes_default_and_parse() {
    assert_eq!(
        Config::parse_str("").unwrap().general.max_tracked_inodes,
        1_000_000
    );
    let cfg = Config::parse_str("[general]\nmax_tracked_inodes = 42\n").unwrap();
    assert_eq!(cfg.general.max_tracked_inodes, 42);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p fsnitch-core max_tracked_inodes_default_and_parse`
Expected: FAIL — `no field max_tracked_inodes on type General`.

- [ ] **Step 3: Implement**

In `struct General`, add the field (after `require_agent_session`):

```rust
    #[serde(default = "default_max_tracked_inodes")]
    pub max_tracked_inodes: usize,
```

Add the default fn near the other `default_*` fns:

```rust
fn default_max_tracked_inodes() -> usize {
    1_000_000
}
```

In `impl Default for General`, add the field:

```rust
            max_tracked_inodes: default_max_tracked_inodes(),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p fsnitch-core max_tracked_inodes_default_and_parse`
Expected: PASS. Also run `cargo test -p fsnitch-core config::` — existing config tests still pass.

- [ ] **Step 5: Commit** (stage; hold per git note)

```bash
git add fsnitch-core/src/config.rs
# message: "core: add general.max_tracked_inodes (inode-index cap)"
```

---

## Task 2: `InodeIndex` type

**Files:**
- Create: `fsnitch-core/src/inode_index.rs`
- Modify: `fsnitch-core/src/lib.rs`

- [ ] **Step 1: Write the failing tests**

Create `fsnitch-core/src/inode_index.rs`:

```rust
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
```

- [ ] **Step 2: Run tests to verify they fail**

Add `pub mod inode_index;` to `fsnitch-core/src/lib.rs` (alphabetical, before `managed`).
Run: `cargo test -p fsnitch-core inode_index::`
Expected: compiles once the module is declared; tests PASS immediately (the impl above is complete). If you write the tests before the impl, they FAIL to compile with "cannot find type InodeIndex".

> Note: this task's impl and tests are in the same new file, so the fail→pass rhythm is: declare module → tests fail to compile → paste impl → pass.

- [ ] **Step 3: (impl included above)**

- [ ] **Step 4: Verify**

Run: `cargo test -p fsnitch-core inode_index::`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add fsnitch-core/src/inode_index.rs fsnitch-core/src/lib.rs
# message: "core: add InodeIndex (dev,ino)->root lookup with global cap"
```

---

## Task 3: `scan_roots` scanner

**Files:**
- Modify: `fsnitch-core/src/inode_index.rs`

- [ ] **Step 1: Write the failing tests**

Append to `inode_index.rs` (module body, above `#[cfg(test)]`):

```rust
use std::os::unix::fs::MetadataExt;
use std::path::Path;

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
```

Add tests inside the `tests` module:

```rust
    use std::os::unix::fs::MetadataExt as _;

    fn ino_of(p: &std::path::Path) -> (u64, u64) {
        let md = std::fs::metadata(p).unwrap();
        (md.dev(), md.ino())
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

        let idx = scan_roots(&[root.clone()], usize::MAX);
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

        let idx = scan_roots(&[root.clone()], usize::MAX);
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
        let idx = scan_roots(&[f.clone()], usize::MAX);
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
        let idx = scan_roots(&[root.clone()], 3); // cap below file count
        assert_eq!(idx.degraded_roots(), vec![root.to_string_lossy().to_string()]);
        // Degraded root contributes no entries.
        assert!(idx.is_empty());
    }
```

- [ ] **Step 2: Run tests to verify they fail, then pass**

Run: `cargo test -p fsnitch-core inode_index::`
Expected: with the impl above pasted, PASS (10 tests total).

- [ ] **Step 3–4: (impl included above; verify)**

Run: `cargo test -p fsnitch-core`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add fsnitch-core/src/inode_index.rs
# message: "core: scan_roots — recursive regular-file inode scanner"
```

---

## Task 4: `CompiledPaths::policy_for_inode`

**Files:**
- Modify: `fsnitch-core/src/rules.rs`

- [ ] **Step 1: Write the failing test**

Add to `rules.rs` tests:

```rust
    #[test]
    fn policy_for_inode_maps_to_root_policy() {
        use crate::inode_index::InodeIndex;
        let paths = compile(CFG);
        let mut idx = InodeIndex::new(100);
        let r = idx.add_root("/home/luke/vaults");
        idx.try_insert(66, 42, r);
        // A path outside every root, but its inode is tracked under /home/luke/vaults.
        let pol = paths.policy_for_inode(&idx, 66, 42).unwrap();
        assert_eq!(pol.path, "/home/luke/vaults");
        // Unknown inode -> None.
        assert!(paths.policy_for_inode(&idx, 66, 43).is_none());
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p fsnitch-core policy_for_inode_maps_to_root_policy`
Expected: FAIL — `no method policy_for_inode`.

- [ ] **Step 3: Implement**

In `rules.rs`, add `use crate::inode_index::InodeIndex;` to the imports, and this method to `impl CompiledPaths`:

```rust
    /// Policy for a file identified by inode rather than path — used as a
    /// fallback when `policy_for` misses because the file was renamed out of
    /// its root (same-filesystem move preserves the inode). Resolves the
    /// tracked root string back through `policy_for`, so nested-root tie-break
    /// stays identical and a root removed by a reload yields `None`.
    pub fn policy_for_inode(
        &self,
        index: &InodeIndex,
        dev: u64,
        ino: u64,
    ) -> Option<&PathPolicy> {
        let root = index.root_for(dev, ino)?;
        self.policy_for(Path::new(root))
    }
```

- [ ] **Step 4: Verify**

Run: `cargo test -p fsnitch-core rules::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add fsnitch-core/src/rules.rs
# message: "core: CompiledPaths::policy_for_inode fallback"
```

---

## Task 5: `stat_fd` + `AccessEvent { dev, ino }`

**Files:**
- Modify: `fsnitchd/src/procinfo.rs`
- Modify: `fsnitchd/src/backend.rs`
- Modify: `fsnitchd/src/fanotify.rs`

- [ ] **Step 1: Write the failing test**

Add to `procinfo.rs` tests:

```rust
    #[test]
    fn stat_fd_matches_metadata() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        let file = tempfile::NamedTempFile::new().unwrap();
        let (dev, ino) = stat_fd(file.as_file().as_raw_fd()).unwrap();
        let md = std::fs::metadata(file.path()).unwrap();
        assert_eq!((dev, ino), (md.dev(), md.ino()));
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p fsnitchd stat_fd_matches_metadata`
Expected: FAIL — `cannot find function stat_fd`.

- [ ] **Step 3: Implement**

In `procinfo.rs`, add (confirm the `nix::sys::stat::fstat` argument type against the installed nix 0.30 — it takes an `AsFd`; if the local build rejects `BorrowedFd`, fall back to the `libc::fstat` form shown in the comment):

```rust
/// `(st_dev, st_ino)` of an open fd (the fanotify event target). None if the
/// stat fails. Used for inode-identity matching when the path no longer
/// resolves under a protected root.
pub fn stat_fd(fd: i32) -> Option<(u64, u64)> {
    use std::os::fd::BorrowedFd;
    // SAFETY: `fd` is a live descriptor owned by the caller for the duration of
    // this call; BorrowedFd does not take ownership.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let st = nix::sys::stat::fstat(borrowed).ok()?;
    Some((st.st_dev as u64, st.st_ino as u64))
}
```

In `backend.rs`, add the fields to `AccessEvent`:

```rust
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
}
```

In `fanotify.rs::next_events`, after `let path = procinfo::path_of_fd(raw);` add:

```rust
            let (dev, ino) = procinfo::stat_fd(raw).unwrap_or((0, 0));
```

and add `dev,` and `ino,` to the `AccessEvent { .. }` construction.

- [ ] **Step 4: Verify**

Run: `cargo test -p fsnitchd stat_fd_matches_metadata` then `cargo build -p fsnitchd`
Expected: test PASS; build FAILS only where `AccessEvent` is constructed elsewhere (the mock/tests) — fix those in Task 6/7.

- [ ] **Step 5: Commit**

```bash
git add fsnitchd/src/procinfo.rs fsnitchd/src/backend.rs fsnitchd/src/fanotify.rs
# message: "fsnitchd: capture (dev,ino) of each gated open"
```

---

## Task 6: Inode fallback in `decide_event`

**Files:**
- Modify: `fsnitchd/src/engine.rs`

- [ ] **Step 1: Write the failing test**

Add to `engine.rs` tests (the module already has `setup`, `SnoozeStore`, `PinHashes`, `RememberedStore`):

```rust
    #[test]
    fn inode_fallback_applies_root_policy_when_path_misses() {
        use fsnitch_core::inode_index::InodeIndex;
        let (cfg, rules) = setup("block"); // root "/vaults"
        let overlay = RememberedStore::default();
        let pins = PinHashes::default();
        let mut index = InodeIndex::new(100);
        let r = index.add_root("/vaults");
        index.try_insert(66, 42, r); // the moved file's inode

        // Path is now /tmp/leaked.kdbx (outside every root), but the inode is tracked.
        let d = decide_event(
            &rules,
            &cfg.general,
            &overlay,
            &SnoozeStore::default(),
            &pins,
            &index,
            Path::new("/tmp/leaked.kdbx"),
            66,
            42,
            Some(Path::new("/tmp/stealer")),
            1,
            Some(1000),
        );
        let Decision::Resolved(dec) = d else {
            panic!("expected Resolved")
        };
        assert!(!dec.allow); // block policy of /vaults applies via inode identity
        assert_eq!(dec.record.unwrap().path, "/vaults");
    }

    #[test]
    fn untracked_inode_outside_root_is_allowed() {
        use fsnitch_core::inode_index::InodeIndex;
        let (cfg, rules) = setup("block");
        let overlay = RememberedStore::default();
        let pins = PinHashes::default();
        let index = InodeIndex::new(100); // empty
        let d = decide_event(
            &rules,
            &cfg.general,
            &overlay,
            &SnoozeStore::default(),
            &pins,
            &index,
            Path::new("/tmp/whatever"),
            66,
            42,
            Some(Path::new("/bin/cat")),
            1,
            Some(1000),
        );
        let Decision::Resolved(dec) = d else {
            panic!("expected Resolved")
        };
        assert!(dec.allow);
        assert!(dec.record.is_none());
    }
```

- [ ] **Step 2: Run to verify it fails (compile error)**

Run: `cargo test -p fsnitchd inode_fallback_applies_root_policy_when_path_misses`
Expected: FAIL — `decide_event` takes fewer arguments.

- [ ] **Step 3: Implement**

Change `decide_event`'s signature to add `index: &InodeIndex`, `dev: u64`, `ino: u64` (place `index` right after `pins`, and `dev`/`ino` right after `path`):

```rust
#[allow(clippy::too_many_arguments)]
pub fn decide_event(
    rules: &CompiledPaths,
    general: &General,
    overlay: &RememberedStore,
    snoozes: &SnoozeStore,
    pins: &PinHashes,
    index: &fsnitch_core::inode_index::InodeIndex,
    path: &Path,
    dev: u64,
    ino: u64,
    program: Option<&Path>,
    pid: i32,
    uid: Option<u32>,
) -> Decision {
```

Replace the opening `let Some(policy) = ...` guard with the fallback chain:

```rust
    let Some(policy) = rules
        .policy_for(path)
        .or_else(|| rules.policy_for_inode(index, dev, ino))
    else {
        return Decision::Resolved(EventDecision {
            allow: true,
            record: None,
        });
    };
```

Update EVERY existing call in the `engine.rs` test module: insert `&index_empty,` after `&pins,` and `<dev>, <ino>,` after the `Path::new(...)` arg. Add a helper at the top of the tests module:

```rust
    fn empty_index() -> fsnitch_core::inode_index::InodeIndex {
        fsnitch_core::inode_index::InodeIndex::new(usize::MAX)
    }
```

and in each existing test call pass `&empty_index(), <path>, 0, 0, ...`. (There are ~10 call sites: `unprotected_path_allowed_without_record`, `allowlisted_program_allowed_with_record`, `block_denies_unlisted`, `watch_allows_unlisted_with_watch_source`, `unresolvable_program_is_never_allowlisted`, `ask_mode_unlisted_returns_prompt`, `overlay_allow_short_circuits_prompt`, `overlay_deny_short_circuits_prompt`, `prompt_without_program_falls_back_to_on_no_agent`, `block_and_watch_still_resolve` (two calls), `paused_path_allows_unlisted_program`, `uid_scoped_pause_does_not_leak` (three calls).)

- [ ] **Step 4: Verify**

Run: `cargo test -p fsnitchd engine::`
Expected: PASS (existing + 2 new).

- [ ] **Step 5: Commit**

```bash
git add fsnitchd/src/engine.rs
# message: "fsnitchd: decide_event falls back to inode identity on path miss"
```

---

## Task 7: Wire the index into `Snapshot` + `main.rs`

**Files:**
- Modify: `fsnitchd/src/state.rs`
- Modify: `fsnitchd/src/main.rs`

- [ ] **Step 1: Write the failing test**

Add to `state.rs` tests:

```rust
    #[test]
    fn snapshot_indexes_existing_files_under_roots() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault");
        std::fs::create_dir_all(&vault).unwrap();
        let f = vault.join("a.kdbx");
        std::fs::write(&f, "x").unwrap();
        write_config(
            dir.path(),
            &format!(
                "[[path]]\npath = \"{}\"\nmode = \"block\"\n",
                vault.display()
            ),
        );
        let state = State::load(dir.path()).unwrap();
        let snap = state.snapshot();
        let md = std::fs::metadata(&f).unwrap();
        // The file is recognized by inode even though we query a foreign path.
        assert!(snap
            .rules
            .policy_for_inode(&snap.inode_index, md.dev(), md.ino())
            .is_some());
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p fsnitchd snapshot_indexes_existing_files_under_roots`
Expected: FAIL — `no field inode_index on Snapshot`.

- [ ] **Step 3: Implement**

In `state.rs`:

Add the import: `use fsnitch_core::inode_index::{self, InodeIndex};`

Add the field to `struct Snapshot`:

```rust
    /// (dev,ino) -> protected root, for recognizing files moved out of a root.
    pub inode_index: Arc<InodeIndex>,
```

In `build_snapshot`, after `let rules = CompiledPaths::compile(&config);` and its self-protection validation, build the index:

```rust
        let inode_index = inode_index::scan_roots(rules.roots(), config.general.max_tracked_inodes);
        for root in inode_index.degraded_roots() {
            tracing::warn!(
                root = %root,
                cap = config.general.max_tracked_inodes,
                "inode index cap exceeded — move protection OFF for this root (path \
                 protection unchanged); raise general.max_tracked_inodes to restore it"
            );
        }
        let inode_index = Arc::new(inode_index);
```

Add `inode_index,` to the `Ok(Snapshot { .. })` at the end of `build_snapshot`.

Add `inode_index: current.inode_index.clone(),` to the three clone-based `Snapshot { .. }` constructors: in `set_remembered`, `forget_remembered`, and `remove_managed_path`.

In `main.rs`, in the event loop where `decide_event` is called, add before the `match`:

```rust
            let index = &snapshot.inode_index;
```

and update the call to insert `index,` after `&snapshot.pin_hashes,` and `event.dev, event.ino,` after `path,`:

```rust
            match engine::decide_event(
                &snapshot.rules,
                &snapshot.config.general,
                &snapshot.remembered,
                &snoozes,
                &snapshot.pin_hashes,
                index,
                path,
                event.dev,
                event.ino,
                event.exe.as_deref(),
                event.pid,
                event.uid,
            ) {
```

- [ ] **Step 4: Verify**

Run: `cargo test -p fsnitchd` then `cargo build --workspace`
Expected: PASS; workspace builds.

- [ ] **Step 5: Commit**

```bash
git add fsnitchd/src/state.rs fsnitchd/src/main.rs
# message: "fsnitchd: build inode index in snapshot and consult it in the loop"
```

---

## Task 8: Surface degraded roots in `status`

**Files:**
- Modify: `fsnitch-core/src/protocol.rs`
- Modify: `fsnitchd/src/control.rs`
- Modify: `fsnitch-cli/src/output.rs`

- [ ] **Step 1: Write the failing test**

In `protocol.rs`, update the existing `Response::Status { .. }` literal in its roundtrip test to include the new field, and assert it survives the roundtrip. Find the test constructing `Response::Status { version, paths, roots, log_file, config_dir }` (around line 294) and add `degraded_roots: vec!["/big".into()],`, then after decoding assert the field equals `vec![PathBuf::from("/big")]`.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p fsnitch-core protocol::`
Expected: FAIL — missing field `degraded_roots`.

- [ ] **Step 3: Implement**

In `protocol.rs`, add to the `Status` variant:

```rust
        /// Roots whose inode index exceeded `max_tracked_inodes` — move
        /// protection is off for them (path protection unchanged).
        #[serde(default)]
        degraded_roots: Vec<PathBuf>,
```

In `control.rs`, in the `Request::Status` arm, add:

```rust
            degraded_roots: snapshot
                .inode_index
                .degraded_roots()
                .into_iter()
                .map(PathBuf::from)
                .collect(),
```

(Confirm `PathBuf` is imported in `control.rs`; it is used already via `std::path::Path` — add `use std::path::PathBuf;` if needed.)

In `fsnitch-cli/src/output.rs`, in the function that renders `Response::Status`, after the existing fields, if `!degraded_roots.is_empty()` print a highlighted warning line, e.g.:

```rust
    if !degraded_roots.is_empty() {
        println!(
            "  move-protection DEGRADED (inode cap) for: {}",
            degraded_roots
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
```

(Match the surrounding print style; update the `Response::Status { .. }` destructuring pattern in `output.rs` to bind `degraded_roots`.)

- [ ] **Step 4: Verify**

Run: `cargo test --workspace` then `cargo build --workspace`
Expected: PASS; builds.

- [ ] **Step 5: Commit**

```bash
git add fsnitch-core/src/protocol.rs fsnitchd/src/control.rs fsnitch-cli/src/output.rs
# message: "status: report roots degraded by the inode cap"
```

---

## Task 9: Docs (Phase 1)

**Files:**
- Modify: `SECURITY.md`, `CONFIGURATION.md`, `CHANGELOG.md`

- [ ] **Step 1: SECURITY.md** — replace the "Delete and rename" non-goal bullet with an honest, scoped version:

```
- **Delete and cross-filesystem move.** fanotify cannot block these as
  permission events, so fsnitch gates opens (read/write), not unlink/rename.
  A *same-filesystem* rename out of a protected path is now covered: the open
  verdict falls back to the file's inode identity `(dev, ino)`, so moving a
  secret elsewhere on the same filesystem and reading it there is still gated.
  Out of scope: delete; cross-filesystem move (a copy whose source read is
  already gated, into a new inode); the brief create→move race before the
  index sees a newly created file; and any root that exceeded
  `max_tracked_inodes` (see status — it falls back to path-only).
```

- [ ] **Step 2: CONFIGURATION.md** — document `max_tracked_inodes` under `[general]`: default `1000000`, purpose (cap the inode index; a root that exceeds it keeps path protection but loses move protection and is reported in `fsnitch status`).

- [ ] **Step 3: CHANGELOG.md** — add an entry (match the file's existing format) describing: "Same-filesystem move protection via inode identity; `general.max_tracked_inodes`; degraded roots shown in status."

- [ ] **Step 4: Verify** — `cargo build --workspace` (docs only; no test impact).

- [ ] **Step 5: Commit**

```bash
git add SECURITY.md CONFIGURATION.md CHANGELOG.md
# message: "docs: same-fs move protection + max_tracked_inodes"
```

**Phase 1 exit check:** `cargo test --workspace && cargo build --workspace` green. The daemon now recognizes any file present under a root at load/reload time after a same-fs move. Manual e2e (needs sudo, run by the user): protect a vault, `mv` a file out, try to read it — it is gated.

---

# PHASE 2 — inotify live freshness

Goal: keep the index fresh for files **created under a root after** load/reload, so "create then move out then open" is also gated (up to the inherent event-drain race). Moves the index from the immutable `Snapshot` to a shared, mutable `LiveInodeIndex`; `decide_event` (which already takes `&InodeIndex`) is unchanged.

## Task 10: `LiveInodeIndex` shared handle

**Files:**
- Create: `fsnitchd/src/inode_watch.rs` (handle portion)
- Modify: `fsnitchd/src/main.rs` (module decl)

- [ ] **Step 1: Write the failing test**

Create `fsnitchd/src/inode_watch.rs` with the handle and a test:

```rust
//! Live inode index: a scan-seeded `InodeIndex` kept fresh by an inotify
//! watcher thread, shared with the enforcement loop. Enforcement reads; the
//! watcher writes. Reload re-seeds it (rescan + re-watch).

use fsnitch_core::inode_index::InodeIndex;
use std::sync::{Arc, RwLock};

#[derive(Clone)]
pub struct LiveInodeIndex(Arc<RwLock<InodeIndex>>);

impl LiveInodeIndex {
    pub fn new(seed: InodeIndex) -> LiveInodeIndex {
        LiveInodeIndex(Arc::new(RwLock::new(seed)))
    }

    /// Read the index for a decision. Poisoned lock -> treat as empty (fail to
    /// path-only, never panic the enforcement loop).
    pub fn with<R>(&self, f: impl FnOnce(&InodeIndex) -> R) -> R {
        match self.0.read() {
            Ok(g) => f(&g),
            Err(_) => f(&InodeIndex::new(0)),
        }
    }

    /// Replace the whole index (used on reload re-seed).
    pub fn replace(&self, next: InodeIndex) {
        if let Ok(mut g) = self.0.write() {
            *g = next;
        }
    }

    pub(crate) fn write(&self) -> Option<std::sync::RwLockWriteGuard<'_, InodeIndex>> {
        self.0.write().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_and_replace() {
        let mut seed = InodeIndex::new(10);
        let r = seed.add_root("/v");
        seed.try_insert(1, 1, r);
        let live = LiveInodeIndex::new(seed);
        assert_eq!(live.with(|i| i.root_for(1, 1).map(str::to_string)), Some("/v".into()));
        live.replace(InodeIndex::new(10));
        assert_eq!(live.with(|i| i.root_for(1, 1).map(str::to_string)), None);
    }
}
```

Add `mod inode_watch;` to `main.rs`.

- [ ] **Step 2–4:** Run `cargo test -p fsnitchd inode_watch::` → PASS.

- [ ] **Step 5: Commit** — `git add fsnitchd/src/inode_watch.rs fsnitchd/src/main.rs` — message: "fsnitchd: LiveInodeIndex shared handle".

## Task 11: inotify watcher thread

**Files:**
- Modify: `fsnitchd/src/inode_watch.rs`
- Modify: `fsnitchd/Cargo.toml` (ensure `nix` has the `inotify` feature)

- [ ] **Step 1:** Add the `inotify` feature to the `nix` dependency in `fsnitchd/Cargo.toml`:
  `nix = { version = "0.30", features = ["fanotify", "socket", "user", "fs", "inotify"] }`

- [ ] **Step 2: Write the integration test** (inotify needs no privilege):

```rust
    #[test]
    fn watcher_indexes_a_created_file() {
        use std::os::unix::fs::MetadataExt;
        use std::time::{Duration, Instant};
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("v");
        std::fs::create_dir_all(&root).unwrap();
        let live = LiveInodeIndex::new(
            fsnitch_core::inode_index::scan_roots(&[root.clone()], usize::MAX),
        );
        let handle = Watcher::spawn(vec![root.clone()], live.clone(), usize::MAX).unwrap();

        // Create a file after the watcher is running.
        let f = root.join("new.kdbx");
        std::fs::write(&f, "x").unwrap();
        let md = std::fs::metadata(&f).unwrap();

        // Poll until the watcher indexes it (bounded).
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if live.with(|i| i.root_for(md.dev(), md.ino()).is_some()) {
                break;
            }
            assert!(Instant::now() < deadline, "file was not indexed in time");
            std::thread::sleep(Duration::from_millis(20));
        }
        handle.stop();
    }
```

- [ ] **Step 3: Implement the watcher.** Design:

- `Watcher::spawn(roots, live, cap) -> io::Result<WatcherHandle>` creates an `Inotify` (`IN_NONBLOCK` not required; a blocking read in the thread is fine), adds recursive directory watches under each root, and stores `wd -> dir path` plus per-dir `name -> (dev,ino)` bookkeeping. It spawns a thread that loops on `read_events`.
- Watch mask: `IN_CREATE | IN_MOVED_TO | IN_MOVED_FROM | IN_DELETE | IN_ONLYDIR`. Files are reported via their parent-dir watch.
- Event handling (each event carries `wd`, `mask`, optional `name`):
  - resolve `dir = wds[wd]`, `full = dir.join(name)`.
  - `IN_CREATE|IN_ISDIR` or `IN_MOVED_TO|IN_ISDIR`: `add_watch_recursive(full)` then rescan its contents into `live` (respecting cap → degrade root).
  - `IN_CREATE` / `IN_MOVED_TO` on a regular file: `stat(full)`, `live.write().try_insert(dev,ino,root_idx)`; record `name->(dev,ino)`; if displaced a prior inode no longer referenced by any tracked name in that dir, `live.write().remove(old)`.
  - `IN_MOVED_FROM`: drop `name` from the dir map but KEEP the inode in `live` (protection travels with the file).
  - `IN_DELETE`: drop `name`; if that inode is no longer referenced by any tracked name, `live.write().remove(dev,ino)`.
  - `IN_IGNORED` (watch auto-removed, e.g. dir deleted): drop the `wd`.
- `root_idx` for a watched dir is the index of the owning root; carry it in the `wd -> (dir, root_idx)` map.
- Stop: `WatcherHandle::stop()` sets an `AtomicBool` and drops the inotify fd; the thread checks the flag between reads. (A blocking `read_events` will return on fd close; if the wrapper does not, use `IN_NONBLOCK` + a short poll loop honoring the flag.)

Concrete skeleton (fill bookkeeping structs; keep them in this file):

```rust
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify, WatchDescriptor};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::os::unix::fs::MetadataExt;

pub struct WatcherHandle {
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}
impl WatcherHandle {
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(j) = self.join.take() { let _ = j.join(); }
    }
}

struct DirState { root_idx: u32, names: HashMap<std::ffi::OsString, (u64, u64)> }

pub struct Watcher;
impl Watcher {
    pub fn spawn(roots: Vec<PathBuf>, live: LiveInodeIndex, cap: usize)
        -> nix::Result<WatcherHandle>
    {
        let inotify = Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC)?;
        let mut wds: HashMap<WatchDescriptor, (PathBuf, u32)> = HashMap::new();
        let mut dirs: HashMap<WatchDescriptor, DirState> = HashMap::new();
        // add_watch_recursive over each root's directories, filling wds/dirs and
        // the root_idx (interned in the seed index so live.write() can reuse it).
        // ... (see event handling above) ...
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let join = std::thread::spawn(move || {
            let mask = AddWatchFlags::IN_CREATE | AddWatchFlags::IN_MOVED_TO
                | AddWatchFlags::IN_MOVED_FROM | AddWatchFlags::IN_DELETE;
            while !stop2.load(Ordering::SeqCst) {
                match inotify.read_events() {
                    Ok(events) => { /* handle per above, mutating `live` */ let _ = &mask; }
                    Err(nix::errno::Errno::EAGAIN) => {
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(WatcherHandle { stop, join: Some(join) })
    }
}
```

> Note: `AddWatchFlags::IN_ONLYDIR` is added when calling `add_watch` on a directory. The exact `nix` inotify event field names (`event.wd`, `event.mask`, `event.name`) are as in `nix::sys::inotify::InotifyEvent`; confirm against the installed version while implementing.

- [ ] **Step 4: Verify** — `cargo test -p fsnitchd inode_watch::` (both tests) → PASS.

- [ ] **Step 5: Commit** — message: "fsnitchd: inotify watcher keeps inode index fresh".

## Task 12: Move the index to the live handle + reseed on reload

**Files:**
- Modify: `fsnitchd/src/state.rs`, `fsnitchd/src/main.rs`, `fsnitchd/src/control.rs`

- [ ] **Step 1:** Remove `inode_index` from `Snapshot`; instead `State` owns a `LiveInodeIndex` plus (for reseed) the current roots. `build_snapshot` still scans and seeds it. Add `State::reseed_inode_index(&self)` that rescans the current snapshot's roots and calls `live.replace(...)`, and restarts the watcher against the new roots.
- [ ] **Step 2:** `main.rs`: construct the `LiveInodeIndex` from the initial scan, spawn the `Watcher`, and in the loop read via `snapshot`-independent handle: `let decision = index_handle.with(|idx| engine::decide_event(.., idx, ..));` (wrap the whole match, or clone out the needed data). Keep `decide_event`'s `&InodeIndex` param.
- [ ] **Step 3:** `control.rs` reload path: after `state.reload()`, call `state.reseed_inode_index()`. `Status` reads `degraded_roots` from the live handle.
- [ ] **Step 4:** Verify: `cargo test --workspace && cargo build --workspace`; manual e2e with sudo: create a file under a protected root, `mv` it out, read it → gated.
- [ ] **Step 5: Commit** — message: "fsnitchd: live inode index with reload reseed".

## Task 13: Docs (Phase 2)

- [ ] Update `SECURITY.md` residual-limits wording (create→move race is now the only same-fs gap) and `CHANGELOG.md`. Commit — message: "docs: live inode freshness".

**Phase 2 exit check:** `cargo test --workspace && cargo build --workspace` green; the create→move→open scenario is gated in manual e2e.

---

## Self-review notes

- Spec coverage: config cap (T1), InodeIndex+cap/degrade (T2), scanner regular-files-only (T3), policy_for_inode (T4), (dev,ino) capture (T5), decide_event fallback (T6), snapshot wiring (T7), status surfacing (T8), docs incl. SECURITY.md (T9); inotify freshness + reseed (T10–12), docs (T13). All spec sections mapped.
- Type consistency: `InodeIndex` methods (`new/add_root/try_insert/remove/degrade/root_for/degraded_roots/len/is_empty`), `scan_roots`, `policy_for_inode(index, dev, ino)`, `AccessEvent{dev,ino}`, `decide_event(.., index, path, dev, ino, ..)`, `LiveInodeIndex{new/with/replace}` used consistently across tasks.
- Open confirmations flagged for implementation time: exact `nix::sys::stat::fstat` fd-arg type (T5) and `nix` inotify event field names / stop-on-close behavior (T11).
