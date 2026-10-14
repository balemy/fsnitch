//! Live inode index: a scan-seeded [`InodeIndex`] kept fresh by an inotify
//! watcher thread, shared with the enforcement loop. Enforcement reads; the
//! watcher writes. A reload re-seeds it (rescan + re-watch).
//!
//! Why inotify and not fanotify FID events: the `nix` fanotify wrapper does not
//! expose `FAN_REPORT_FID`, so directory-change events would need raw-libc
//! info-record parsing. inotify gives the same "file created/moved under a
//! root" signal through a safe wrapper. Enforcement itself stays on the
//! whole-filesystem fanotify mark; this watcher only keeps the *recognition*
//! fresh for files created after the last (re)seed.
//!
//! Freshness model:
//! - `IN_CREATE` / `IN_MOVED_TO` on a regular file → index its `(dev, ino)`.
//! - a new/moved-in subdirectory → watch it recursively and index its contents.
//! - `IN_MOVED_FROM` on a file → it left a watched dir; drop the name link but
//!   KEEP the inode indexed — a move out of the root is exactly what we protect.
//! - `IN_MOVED_FROM` on a directory → drop its subtree's watches and old-path
//!   links (inodes stay indexed); a within-root rename rebuilds both via the
//!   paired `IN_MOVED_TO` rescan.
//! - `IN_DELETE` → a link was removed; evict the inode once its last known link
//!   is gone (prevents churn, e.g. editor atomic-saves, from creeping the cap).
//! - `IN_Q_OVERFLOW` → the kernel dropped events; rescan all roots rather than
//!   trust the index (a missed delete would leave a stale entry that a recycled
//!   inode number could later match).

use fsnitch_core::inode_index::InodeIndex;
use nix::errno::Errno;
use nix::poll::{poll, PollFd, PollFlags};
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify, InotifyEvent, WatchDescriptor};
use std::collections::HashMap;
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::{Arc, RwLock, RwLockWriteGuard};
use std::thread::JoinHandle;

/// The index shared between the enforcement loop (reader) and the watcher
/// (writer). Cheap to clone (an `Arc`).
#[derive(Clone)]
pub struct LiveInodeIndex(Arc<RwLock<InodeIndex>>);

impl LiveInodeIndex {
    pub fn new(seed: InodeIndex) -> LiveInodeIndex {
        LiveInodeIndex(Arc::new(RwLock::new(seed)))
    }

    /// Read the index for a decision. A poisoned lock is treated as an empty
    /// index (fail to path-only rather than panicking the enforcement loop).
    pub fn with<R>(&self, f: impl FnOnce(&InodeIndex) -> R) -> R {
        match self.0.read() {
            Ok(g) => f(&g),
            Err(_) => f(&InodeIndex::new(0)),
        }
    }

    /// Replace the whole index (reload re-seed).
    fn replace(&self, next: InodeIndex) {
        if let Ok(mut g) = self.0.write() {
            *g = next;
        }
    }

    fn write(&self) -> Option<RwLockWriteGuard<'_, InodeIndex>> {
        self.0.write().ok()
    }
}

/// Commands sent to the watcher thread.
pub enum Cmd {
    /// Rescan `roots` (with a possibly new cap) and reset all watches.
    Reseed(Vec<PathBuf>, usize),
    /// Stop the watcher thread.
    Stop,
}

/// Handle to the watcher thread. `tx()` hands out a sender for reload re-seeds.
/// Dropping the handle stops the thread and joins it — so the daemon keeps it
/// alive for its whole lifetime, while tests drop it to shut the thread down.
pub struct WatcherHandle {
    tx: Sender<Cmd>,
    join: Option<JoinHandle<()>>,
}

impl WatcherHandle {
    pub fn tx(&self) -> Sender<Cmd> {
        self.tx.clone()
    }
}

impl Drop for WatcherHandle {
    fn drop(&mut self) {
        let _ = self.tx.send(Cmd::Stop);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

struct Dir {
    /// Owning root path string (interned in the index to resolve `root_idx`).
    root: Arc<str>,
    /// This directory's own path (to build full child paths from event names).
    path: PathBuf,
}

struct Watcher {
    inotify: Inotify,
    live: LiveInodeIndex,
    cap: usize,
    /// The currently watched roots, kept for a self-initiated rescan (e.g.
    /// after an inotify queue overflow).
    roots: Vec<PathBuf>,
    /// Watched directories, by watch descriptor.
    dirs: HashMap<WatchDescriptor, Dir>,
    /// Each tracked link's full path → the inode it points at.
    path_to_inode: HashMap<PathBuf, (u64, u64)>,
    /// Number of tracked links per inode (handles hardlinks within watched
    /// dirs; an inode is evicted only when its last link is deleted).
    inode_links: HashMap<(u64, u64), u32>,
}

/// Watch mask: directory-content changes only. `IN_ONLYDIR` makes `add_watch`
/// fail (rather than silently watch a file) if the target is not a directory.
fn watch_mask() -> AddWatchFlags {
    AddWatchFlags::IN_CREATE
        | AddWatchFlags::IN_MOVED_TO
        | AddWatchFlags::IN_MOVED_FROM
        | AddWatchFlags::IN_DELETE
        | AddWatchFlags::IN_ONLYDIR
}

impl Watcher {
    /// Spawn the watcher. The initial scan + watch setup runs *synchronously*
    /// here (before the thread starts), so the index is populated before the
    /// caller enables enforcement — no startup gap.
    pub fn spawn(
        roots: Vec<PathBuf>,
        live: LiveInodeIndex,
        cap: usize,
    ) -> nix::Result<WatcherHandle> {
        let inotify = Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC)?;
        let mut st = Watcher {
            inotify,
            live,
            cap,
            roots: roots.clone(),
            dirs: HashMap::new(),
            path_to_inode: HashMap::new(),
            inode_links: HashMap::new(),
        };
        st.seed(&roots);
        let (tx, rx) = channel();
        let join = std::thread::spawn(move || st.run(rx));
        Ok(WatcherHandle {
            tx,
            join: Some(join),
        })
    }

    fn run(mut self, rx: Receiver<Cmd>) {
        loop {
            // Block up to 250ms for inotify events; the timeout lets us also
            // service reseed/stop commands. Events drain immediately on arrival.
            let events: Vec<InotifyEvent> = {
                let fd = self.inotify.as_fd();
                let mut fds = [PollFd::new(fd, PollFlags::POLLIN)];
                match poll(&mut fds, 250u16) {
                    Ok(n)
                        if n > 0
                            && fds[0]
                                .revents()
                                .is_some_and(|r| r.intersects(PollFlags::POLLIN)) =>
                    {
                        match self.inotify.read_events() {
                            Ok(evs) => evs,
                            Err(Errno::EAGAIN) => Vec::new(),
                            Err(_) => Vec::new(),
                        }
                    }
                    _ => Vec::new(),
                }
            };
            self.process(&events);
            loop {
                match rx.try_recv() {
                    Ok(Cmd::Reseed(roots, cap)) => self.reseed(&roots, cap),
                    Ok(Cmd::Stop) | Err(TryRecvError::Disconnected) => return,
                    Err(TryRecvError::Empty) => break,
                }
            }
        }
    }

    /// Handle one drained batch of inotify events. An IN_Q_OVERFLOW in the
    /// batch means the kernel dropped events (missed deletions would leave
    /// stale inodes that a recycled inode number could match later) — the
    /// whole batch is untrustworthy, so rescan the roots instead of replaying.
    fn process(&mut self, events: &[InotifyEvent]) {
        if events
            .iter()
            .any(|ev| ev.mask.contains(AddWatchFlags::IN_Q_OVERFLOW))
        {
            tracing::warn!("inotify event queue overflowed — rescanning all roots");
            let roots = std::mem::take(&mut self.roots);
            self.reseed(&roots, self.cap);
            return;
        }
        for ev in events {
            self.handle(ev);
        }
    }

    /// Tear down every watch, clear bookkeeping, and rescan `roots` into a fresh
    /// index (used on reload — roots and cap may have changed).
    fn reseed(&mut self, roots: &[PathBuf], cap: usize) {
        if let Ok(inotify) = Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC) {
            self.inotify = inotify; // dropping the old one removes all its watches
        }
        self.dirs.clear();
        self.path_to_inode.clear();
        self.inode_links.clear();
        self.cap = cap;
        self.roots = roots.to_vec();
        self.live.replace(InodeIndex::new(cap));
        self.seed(roots);
    }

    fn seed(&mut self, roots: &[PathBuf]) {
        for root in roots {
            let root: Arc<str> = Arc::from(root.to_string_lossy().as_ref());
            let Some(root_idx) = self.write_index(|g| g.add_root(&root)) else {
                continue;
            };
            match std::fs::symlink_metadata(Path::new(&*root)) {
                Ok(md) if md.file_type().is_file() => {
                    // A single-file root: index it (no directory to watch, so no
                    // live updates — its inode identity is captured at seed time).
                    self.index_file(
                        Path::new(&*root),
                        md.dev(),
                        md.ino(),
                        md.created().ok(),
                        &root,
                        root_idx,
                    );
                }
                Ok(md) if md.file_type().is_dir() => {
                    self.watch_tree(&PathBuf::from(&*root), &root, root_idx);
                }
                _ => {}
            }
        }
    }

    /// Add a watch on `dir`, index its regular files, and recurse into
    /// subdirectories. Symlinks (and symlinked dirs) are skipped — matching the
    /// scan in `fsnitch_core::inode_index`.
    fn watch_tree(&mut self, dir: &Path, root: &Arc<str>, root_idx: u32) {
        match self.inotify.add_watch(dir, watch_mask()) {
            Ok(wd) => {
                self.dirs.insert(
                    wd,
                    Dir {
                        root: root.clone(),
                        path: dir.to_path_buf(),
                    },
                );
            }
            Err(err) => {
                tracing::debug!(dir = %dir.display(), %err, "inotify add_watch failed");
            }
        }
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in rd.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            let path = entry.path();
            if ft.is_file() {
                if let Ok(md) = entry.metadata() {
                    if !self.index_file(
                        &path,
                        md.dev(),
                        md.ino(),
                        md.created().ok(),
                        root,
                        root_idx,
                    ) {
                        self.degrade_root(root, root_idx);
                        return;
                    }
                }
            } else if ft.is_dir() {
                self.watch_tree(&path, root, root_idx);
            }
        }
    }

    /// Insert `(dev, ino)` into the index under `root_idx` and record the link.
    /// Returns false if the cap blocked the insert.
    fn index_file(
        &mut self,
        path: &Path,
        dev: u64,
        ino: u64,
        btime: Option<std::time::SystemTime>,
        _root: &Arc<str>,
        root_idx: u32,
    ) -> bool {
        let ok = self
            .write_index(|g| g.try_insert(dev, ino, root_idx, btime))
            .unwrap_or(false);
        if ok {
            self.set_link(path.to_path_buf(), (dev, ino));
        }
        ok
    }

    /// A root exceeded the cap: mark it degraded (index drops its entries) and
    /// stop watching it. Path protection is unchanged; status surfaces it.
    fn degrade_root(&mut self, root: &Arc<str>, root_idx: u32) {
        self.write_index(|g| g.degrade(root_idx));
        tracing::warn!(
            root = %&**root,
            cap = self.cap,
            "inode index cap exceeded — move protection OFF for this root (path \
             protection unchanged); raise general.max_tracked_inodes to restore it"
        );
        let to_remove: Vec<WatchDescriptor> = self
            .dirs
            .iter()
            .filter(|(_, d)| *d.root == **root)
            .map(|(wd, _)| *wd)
            .collect();
        for wd in to_remove {
            let _ = self.inotify.rm_watch(wd);
            self.dirs.remove(&wd);
        }
    }

    fn handle(&mut self, ev: &InotifyEvent) {
        let Some(dir) = self.dirs.get(&ev.wd) else {
            return;
        };
        let root = dir.root.clone();
        let dirpath = dir.path.clone();

        let Some(name) = ev.name.as_ref() else {
            // A nameless event on the watched dir itself: IN_IGNORED means the
            // watch was auto-removed (dir gone) — forget it.
            if ev.mask.contains(AddWatchFlags::IN_IGNORED) {
                self.dirs.remove(&ev.wd);
            }
            return;
        };
        let full = dirpath.join(name);
        let m = ev.mask;
        let is_dir = m.contains(AddWatchFlags::IN_ISDIR);

        if m.intersects(AddWatchFlags::IN_CREATE | AddWatchFlags::IN_MOVED_TO) {
            if is_dir {
                if let Some(root_idx) = self.write_index(|g| g.add_root(&root)) {
                    // A moved-in subtree may already contain files.
                    self.watch_tree(&full, &root, root_idx);
                }
            } else if let Ok(md) = std::fs::symlink_metadata(&full) {
                if md.file_type().is_file() {
                    if let Some(root_idx) = self.write_index(|g| g.add_root(&root)) {
                        if !self.index_file(
                            &full,
                            md.dev(),
                            md.ino(),
                            md.created().ok(),
                            &root,
                            root_idx,
                        ) {
                            self.degrade_root(&root, root_idx);
                        }
                    }
                }
            }
        } else if m.contains(AddWatchFlags::IN_MOVED_FROM) {
            if is_dir {
                // A directory left this dir. Its subtree's old-path links and
                // watches are stale and must go; the inodes stay indexed
                // (move-out semantics). A rename within the root re-links and
                // re-watches everything via the paired IN_MOVED_TO rescan.
                self.drop_tree(&full);
            } else {
                // Left this dir: drop the link but KEEP the inode indexed (a
                // move out of the root is exactly what inode identity protects).
                self.drop_link(&full, false);
            }
        } else if m.contains(AddWatchFlags::IN_DELETE) {
            // Unlinked: drop the link and evict the inode if it was the last one.
            self.drop_link(&full, true);
        }
    }

    /// Bind `path → ino`. If `path` previously pointed at a different inode
    /// (e.g. an atomic-save rename replaced it), that old inode loses this link.
    /// Re-binding the same path to the same inode is a no-op — the seed scan
    /// and a racing IN_CREATE event may both report one link, which must not
    /// double-count it (a leaked count would block eviction forever).
    fn set_link(&mut self, path: PathBuf, ino: (u64, u64)) {
        if let Some(old) = self.path_to_inode.insert(path, ino) {
            if old == ino {
                return;
            }
            self.dec_link(old, true);
        }
        *self.inode_links.entry(ino).or_insert(0) += 1;
    }

    /// A directory under `prefix` left its watched parent (rename or move-out):
    /// remove the watches and path links underneath it. Inodes stay indexed
    /// (move-out semantics); a within-root rename rebuilds links and watches
    /// when the paired IN_MOVED_TO rescans the subtree under its new path.
    fn drop_tree(&mut self, prefix: &Path) {
        let stale: Vec<WatchDescriptor> = self
            .dirs
            .iter()
            .filter(|(_, d)| d.path.starts_with(prefix))
            .map(|(wd, _)| *wd)
            .collect();
        for wd in stale {
            let _ = self.inotify.rm_watch(wd);
            self.dirs.remove(&wd);
        }
        let links: Vec<PathBuf> = self
            .path_to_inode
            .keys()
            .filter(|p| p.starts_with(prefix))
            .cloned()
            .collect();
        for path in links {
            self.drop_link(&path, false);
        }
    }

    /// Remove the link at `path`. `evict_if_last` distinguishes a true unlink
    /// (evict when the last link is gone) from a move-out (keep the inode).
    fn drop_link(&mut self, path: &Path, evict_if_last: bool) {
        if let Some(ino) = self.path_to_inode.remove(path) {
            self.dec_link(ino, evict_if_last);
        }
    }

    fn dec_link(&mut self, ino: (u64, u64), evict_if_last: bool) {
        if let Some(count) = self.inode_links.get_mut(&ino) {
            *count -= 1;
            if *count == 0 {
                self.inode_links.remove(&ino);
                if evict_if_last {
                    self.write_index(|g| g.remove(ino.0, ino.1));
                }
            }
        }
    }

    fn write_index<R>(&self, f: impl FnOnce(&mut InodeIndex) -> R) -> Option<R> {
        self.live.write().map(|mut g| f(&mut g))
    }
}

/// Public entry point mirroring `Watcher::spawn`.
pub fn spawn(roots: Vec<PathBuf>, live: LiveInodeIndex, cap: usize) -> nix::Result<WatcherHandle> {
    Watcher::spawn(roots, live, cap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn ino_of(p: &Path) -> (u64, u64) {
        let md = std::fs::metadata(p).unwrap();
        (md.dev(), md.ino())
    }

    fn wait_until(live: &LiveInodeIndex, key: (u64, u64), want_present: bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let present = live.with(|i| i.root_for(key.0, key.1, None).is_some());
            if present == want_present {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn read_and_replace() {
        let mut seed = InodeIndex::new(10);
        let r = seed.add_root("/v");
        seed.try_insert(1, 1, r, None);
        let live = LiveInodeIndex::new(seed);
        assert_eq!(
            live.with(|i| i.root_for(1, 1, None).map(str::to_string)),
            Some("/v".into())
        );
        live.replace(InodeIndex::new(10));
        assert_eq!(
            live.with(|i| i.root_for(1, 1, None).map(str::to_string)),
            None
        );
    }

    #[test]
    fn spawn_seeds_existing_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("v");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        let f = root.join("sub/a.kdbx");
        std::fs::write(&f, "x").unwrap();
        let live = LiveInodeIndex::new(InodeIndex::new(usize::MAX));
        let handle = spawn(vec![root.clone()], live.clone(), usize::MAX).unwrap();
        // Seed is synchronous in spawn(): the file is indexed immediately.
        let key = ino_of(&f);
        assert!(live.with(|i| i.root_for(key.0, key.1, None).is_some()));
        drop(handle);
    }

    #[test]
    fn watcher_indexes_a_created_file() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("v");
        std::fs::create_dir_all(&root).unwrap();
        let live = LiveInodeIndex::new(InodeIndex::new(usize::MAX));
        let handle = spawn(vec![root.clone()], live.clone(), usize::MAX).unwrap();

        let f = root.join("new.kdbx");
        std::fs::write(&f, "x").unwrap();
        let key = ino_of(&f);
        assert!(wait_until(&live, key, true), "created file was not indexed");
        drop(handle);
    }

    #[test]
    fn move_out_of_root_keeps_the_inode() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("v");
        let outside = dir.path().join("out");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let live = LiveInodeIndex::new(InodeIndex::new(usize::MAX));
        let handle = spawn(vec![root.clone()], live.clone(), usize::MAX).unwrap();

        let f = root.join("secret.kdbx");
        std::fs::write(&f, "x").unwrap();
        let key = ino_of(&f);
        assert!(wait_until(&live, key, true), "file not indexed");
        // Move it out of the root (same tmpfs → inode preserved).
        std::fs::rename(&f, outside.join("secret.kdbx")).unwrap();
        // It must stay recognized by inode after the move settles.
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            live.with(|i| i.root_for(key.0, key.1, None).is_some()),
            "moved-out file lost inode protection"
        );
        drop(handle);
    }

    #[test]
    fn reindexing_the_same_link_does_not_block_eviction() {
        // The seed scan and a racing IN_CREATE event can both index the same
        // path+inode. That must count as ONE link: the file's deletion has to
        // evict the inode, or a recycled inode number later matches an
        // unrelated file.
        let live = LiveInodeIndex::new(InodeIndex::new(usize::MAX));
        let mut w = Watcher {
            inotify: Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC).unwrap(),
            live: live.clone(),
            cap: usize::MAX,
            roots: Vec::new(),
            dirs: HashMap::new(),
            path_to_inode: HashMap::new(),
            inode_links: HashMap::new(),
        };
        let root: Arc<str> = Arc::from("/v");
        let root_idx = w.write_index(|g| g.add_root(&root)).unwrap();
        let p = PathBuf::from("/v/f");
        w.index_file(&p, 1, 7, None, &root, root_idx);
        w.index_file(&p, 1, 7, None, &root, root_idx);
        w.drop_link(&p, true);
        assert!(
            live.with(|i| i.root_for(1, 7, None).is_none()),
            "double-indexed link kept the deleted inode in the index"
        );
    }

    #[test]
    fn dir_rename_within_root_then_delete_still_evicts() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("v");
        std::fs::create_dir_all(&root).unwrap();
        let live = LiveInodeIndex::new(InodeIndex::new(usize::MAX));
        let handle = spawn(vec![root.clone()], live.clone(), usize::MAX).unwrap();

        // Chromium-style staging: create a subdir with a file, then rename the
        // subdir into place within the same root.
        std::fs::create_dir(root.join("sub")).unwrap();
        let f = root.join("sub/data.ldb");
        std::fs::write(&f, "x").unwrap();
        let key = ino_of(&f);
        assert!(wait_until(&live, key, true), "file not indexed");

        std::fs::rename(root.join("sub"), root.join("sub2")).unwrap();
        // Let the watcher process the rename and rescan the directory.
        std::thread::sleep(Duration::from_millis(300));

        // Deleting the file is a true unlink: its inode must leave the index,
        // otherwise a recycled inode number later matches an unrelated file.
        std::fs::remove_file(root.join("sub2/data.ldb")).unwrap();
        assert!(
            wait_until(&live, key, false),
            "deleted file still indexed after its directory was renamed within the root"
        );
        drop(handle);
    }

    #[test]
    fn queue_overflow_triggers_a_rescan() {
        // On IN_Q_OVERFLOW the kernel dropped events — deletions may have been
        // missed. The watcher must rescan its roots so the index matches the
        // filesystem again.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("v");
        std::fs::create_dir_all(&root).unwrap();
        let stale = root.join("stale.kdbx");
        std::fs::write(&stale, "x").unwrap();
        let stale_key = ino_of(&stale);

        let live = LiveInodeIndex::new(InodeIndex::new(usize::MAX));
        let mut w = Watcher {
            inotify: Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC).unwrap(),
            live: live.clone(),
            cap: usize::MAX,
            roots: vec![root.clone()],
            dirs: HashMap::new(),
            path_to_inode: HashMap::new(),
            inode_links: HashMap::new(),
        };
        w.seed(std::slice::from_ref(&root));
        assert!(live.with(|i| i.root_for(stale_key.0, stale_key.1, None).is_some()));

        // Events for these are "lost" (never drained before the overflow).
        std::fs::remove_file(&stale).unwrap();
        let fresh = root.join("fresh.kdbx");
        std::fs::write(&fresh, "y").unwrap();
        let fresh_key = ino_of(&fresh);

        let wd = *w.dirs.keys().next().unwrap();
        w.process(&[InotifyEvent {
            wd,
            mask: AddWatchFlags::IN_Q_OVERFLOW,
            cookie: 0,
            name: None,
        }]);

        assert!(
            live.with(|i| i.root_for(stale_key.0, stale_key.1, None).is_none()),
            "deleted file survived the overflow rescan"
        );
        assert!(
            live.with(|i| i.root_for(fresh_key.0, fresh_key.1, None).is_some()),
            "existing file missing after the overflow rescan"
        );
    }

    #[test]
    fn delete_evicts_the_inode() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("v");
        std::fs::create_dir_all(&root).unwrap();
        let live = LiveInodeIndex::new(InodeIndex::new(usize::MAX));
        let handle = spawn(vec![root.clone()], live.clone(), usize::MAX).unwrap();

        let f = root.join("tmp.kdbx");
        std::fs::write(&f, "x").unwrap();
        let key = ino_of(&f);
        assert!(wait_until(&live, key, true), "file not indexed");
        std::fs::remove_file(&f).unwrap();
        assert!(
            wait_until(&live, key, false),
            "deleted file was not evicted"
        );
        drop(handle);
    }
}
