//! Shared daemon state: config + compiled paths, atomically reloadable.

use crate::hashing::PinHashes;
use anyhow::Context;
use fsnitch_core::config::{Config, PathPolicy};
use fsnitch_core::managed::ManagedPaths;
use fsnitch_core::remembered::RememberedStore;
use fsnitch_core::rules::CompiledPaths;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

/// Outcome of `update_managed_path`.
pub enum ManagedUpdate {
    Updated,
    NotManaged,
    Rejected(String),
}

pub struct Snapshot {
    pub config: Config,
    pub rules: Arc<CompiledPaths>,
    pub remembered: RememberedStore,
    /// sha256 of pinned programs, hashed at load; verified by `stat` at event time.
    pub pin_hashes: Arc<PinHashes>,
    /// Protected paths from the CLI-managed drop-in (`list` source column,
    /// unprotect/allow/deny errors). Path is the identity, so this is an exact
    /// set of the managed drop-in's `path`s.
    pub managed_paths: HashSet<String>,
}

/// The CLI-managed drop-in owned by the daemon (`fsnitch protect`).
fn managed_path(config_dir: &Path) -> PathBuf {
    config_dir.join("paths.d").join("managed.toml")
}

/// Write `bytes` to `path` atomically (temp file + rename). Caller holds
/// `write_lock`, so a fixed temp name per path cannot race itself.
fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("revert.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

pub struct State {
    config_dir: PathBuf,
    inner: RwLock<Arc<Snapshot>>,
    /// Serializes snapshot-producing writers (reload, set_remembered, managed
    /// mutations) so their read-modify-swap sequences and disk writes can't
    /// interleave and lose updates. The `inner` RwLock only guards the (fast)
    /// pointer swap; hot-path readers via `snapshot()` never wait on this.
    write_lock: Mutex<()>,
}

impl State {
    pub fn load(config_dir: &Path) -> anyhow::Result<State> {
        let snapshot = Self::build_snapshot(config_dir)?;
        Ok(State {
            config_dir: config_dir.to_path_buf(),
            inner: RwLock::new(Arc::new(snapshot)),
            write_lock: Mutex::new(()),
        })
    }

    /// Reload from disk. On any error the previous snapshot stays active (spec:
    /// never fall back to "no protection").
    pub fn reload(&self) -> anyhow::Result<()> {
        let _guard = self.write_lock.lock().unwrap();
        let snapshot = Self::build_snapshot(&self.config_dir)?;
        *self.inner.write().unwrap() = Arc::new(snapshot);
        Ok(())
    }

    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.inner.read().unwrap().clone()
    }

    pub fn config_dir(&self) -> &std::path::Path {
        &self.config_dir
    }

    /// Persist a "forever" verdict to the remembered overlay and publish a new
    /// snapshot so subsequent decisions see it. Config + paths are unchanged.
    pub fn set_remembered(&self, path: &str, program: PathBuf, allow: bool) -> anyhow::Result<()> {
        // Hold the write lock across the whole read-modify-persist-swap so two
        // concurrent "forever" verdicts can't lose each other's update or race
        // on the on-disk file.
        let _guard = self.write_lock.lock().unwrap();
        let current = self.snapshot();
        let mut remembered = current.remembered.clone();
        remembered.set(path, program, allow)?;
        let new_snapshot = Snapshot {
            config: current.config.clone(),
            rules: current.rules.clone(),
            remembered,
            pin_hashes: current.pin_hashes.clone(),
            managed_paths: current.managed_paths.clone(),
        };
        *self.inner.write().unwrap() = Arc::new(new_snapshot);
        Ok(())
    }

    /// Drop remembered verdicts for `path` (optionally only `program`'s) and
    /// publish a snapshot without them. Returns how many were removed.
    pub fn forget_remembered(&self, path: &str, program: Option<&Path>) -> anyhow::Result<usize> {
        let _guard = self.write_lock.lock().unwrap();
        let current = self.snapshot();
        let mut remembered = current.remembered.clone();
        let removed = remembered.remove_matching(path, program)?;
        if removed > 0 {
            let new_snapshot = Snapshot {
                config: current.config.clone(),
                rules: current.rules.clone(),
                remembered,
                pin_hashes: current.pin_hashes.clone(),
                managed_paths: current.managed_paths.clone(),
            };
            *self.inner.write().unwrap() = Arc::new(new_snapshot);
        }
        Ok(removed)
    }

    /// Add a CLI-managed path policy: append to the managed drop-in, rebuild,
    /// swap. On rebuild failure the file is restored and the old snapshot stays.
    pub fn add_managed_path(&self, policy: PathPolicy) -> anyhow::Result<()> {
        let _guard = self.write_lock.lock().unwrap();
        let file = managed_path(&self.config_dir);
        let before = std::fs::read(&file).ok();
        let mut managed = ManagedPaths::load(&file)?;
        managed.add(policy)?;
        managed.save()?;
        self.swap_or_revert(&file, before)
    }

    /// Remove the CLI-managed policy whose path equals `path`. Returns the
    /// removed path (so the caller can clear its pause), or None if no such
    /// managed policy existed.
    pub fn remove_managed_path(&self, path: &str) -> anyhow::Result<Option<String>> {
        let _guard = self.write_lock.lock().unwrap();
        let file = managed_path(&self.config_dir);
        let before = std::fs::read(&file).ok();
        let mut managed = ManagedPaths::load(&file)?;
        let Some(removed) = managed.remove(path) else {
            return Ok(None);
        };
        managed.save()?;
        self.swap_or_revert(&file, before)?;
        // Purge remembered "forever" verdicts for the removed path: a later
        // re-protect of the same path must start fresh — a resurrected
        // allow_forever would silently fail open.
        let current = self.snapshot();
        let mut remembered = current.remembered.clone();
        if remembered.remove_path(&removed.path)? {
            let new_snapshot = Snapshot {
                config: current.config.clone(),
                rules: current.rules.clone(),
                remembered,
                pin_hashes: current.pin_hashes.clone(),
                managed_paths: current.managed_paths.clone(),
            };
            *self.inner.write().unwrap() = Arc::new(new_snapshot);
        }
        Ok(Some(removed.path))
    }

    /// Read-modify-write a single CLI-managed policy in place (used by
    /// `allow`/`deny`/`protect`-merge to mutate a fixed entry or field).
    /// Applies `edit` to the disk-fresh policy whose path equals `path` — under
    /// `write_lock`, so a caller that re-derives its edit from that fresh value
    /// (rather than a pre-lock snapshot) can't lose a concurrent update — then
    /// rebuilds and swaps. On rebuild failure the file is restored and the old
    /// snapshot stays. Returns `NotManaged` if no managed policy has that path
    /// (caller reports "protect it first"); `Rejected(msg)` if `edit` errors
    /// (nothing was saved: only an in-memory `remove` happened, so the on-disk
    /// file is untouched and needs no revert).
    pub fn update_managed_path(
        &self,
        path: &str,
        edit: impl FnOnce(&mut PathPolicy) -> Result<(), String>,
    ) -> anyhow::Result<ManagedUpdate> {
        let _guard = self.write_lock.lock().unwrap();
        let file = managed_path(&self.config_dir);
        let before = std::fs::read(&file).ok();
        let mut managed = ManagedPaths::load(&file)?;
        // ManagedPaths has no in-place accessor; remove, mutate, re-add. The
        // path was just removed, so re-adding cannot collide.
        let Some(mut policy) = managed.remove(path) else {
            return Ok(ManagedUpdate::NotManaged);
        };
        if let Err(msg) = edit(&mut policy) {
            return Ok(ManagedUpdate::Rejected(msg));
        }
        managed.add(policy)?;
        managed.save()?;
        self.swap_or_revert(&file, before)?;
        Ok(ManagedUpdate::Updated)
    }

    /// Rebuild from disk and swap; on failure restore `path` to `before`.
    /// Caller holds `write_lock`.
    fn swap_or_revert(&self, path: &Path, before: Option<Vec<u8>>) -> anyhow::Result<()> {
        match Self::build_snapshot(&self.config_dir) {
            Ok(snapshot) => {
                *self.inner.write().unwrap() = Arc::new(snapshot);
                Ok(())
            }
            Err(err) => {
                // Restore the managed file (atomically) so the rejected change
                // can't come back to life on the next reload or daemon start.
                let revert = match before {
                    Some(bytes) => atomic_write(path, &bytes),
                    None => match std::fs::remove_file(path) {
                        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
                        _ => Ok(()),
                    },
                };
                if let Err(revert_err) = revert {
                    tracing::error!(
                        "failed to revert {} after a rejected change: {revert_err} — \
                         the file on disk may not match the active policies",
                        path.display()
                    );
                }
                Err(err)
            }
        }
    }

    fn build_snapshot(config_dir: &Path) -> anyhow::Result<Snapshot> {
        let mut config = Config::load(config_dir).context("loading config")?;
        // Resolve each protected path to the kernel-canonical form the daemon
        // sees via /proc/self/fd, so rules on symlinked paths match instead of
        // silently never firing. Idempotent for already-canonical CLI paths.
        // Two distinct configured paths can collapse to one canonical path (one
        // written through a symlink); `policy_for`'s tie-break would then
        // silently pick one mode over the other, so that is a config error.
        let mut originals: HashMap<String, String> = HashMap::new();
        for p in &mut config.paths {
            let original = p.path.clone();
            let canon = fsnitch_core::pathutil::canonicalize_lenient(Path::new(&p.path));
            let canon = canon.to_string_lossy();
            if canon != p.path {
                tracing::debug!(from = %p.path, to = %canon, "canonicalized protected path");
                p.path = canon.into_owned();
            }
            if let Some(first) = originals.insert(p.path.clone(), original.clone()) {
                anyhow::bail!(
                    "config error: protected paths {first:?} and {original:?} both resolve to \
                     {:?} — remove one of them",
                    p.path
                );
            }
        }
        let rules = CompiledPaths::compile(&config);
        Self::validate_self_protection(&config, &rules, config_dir)?;
        let remembered = RememberedStore::load(&config_dir.join("remembered.toml"))
            .context("loading remembered overlay")?;
        // Hash every pinned program now (reading the file). At startup this runs
        // before the fanotify marks exist; on reload it runs on the control
        // thread and the reads are covered by the enforcement loop's own-pid
        // auto-allow, so it never self-deadlocks.
        let pinned = config.paths.iter().flat_map(|p| {
            p.allow
                .iter()
                .chain(p.deny.iter())
                .filter(|e| e.sha256.is_some())
                .map(|e| e.program.as_path())
        });
        let pin_hashes = PinHashes::build(pinned);
        let managed_paths: HashSet<String> = ManagedPaths::load(&managed_path(config_dir))
            .context("loading managed paths")?
            .paths()
            .map(str::to_string)
            .collect();
        Ok(Snapshot {
            config,
            rules: Arc::new(rules),
            remembered,
            pin_hashes: Arc::new(pin_hashes),
            managed_paths,
        })
    }

    /// The daemon must never gate its own operational paths (deadlock guard).
    /// Checks the config dir actually in use (`--config`), not a hardcoded default.
    fn validate_self_protection(
        config: &Config,
        rules: &CompiledPaths,
        config_dir: &Path,
    ) -> anyhow::Result<()> {
        let own_paths = [
            config.general.log_file.as_path(),
            config_dir,
            Path::new("/run/fsnitch"),
        ];
        for p in own_paths {
            // Compare canonical-to-canonical: policy paths are canonicalized at
            // load, so checking the raw (possibly symlinked) operational path
            // here would silently bypass the guard.
            let canon = fsnitch_core::pathutil::canonicalize_lenient(p);
            if rules.policy_for(&canon).is_some() {
                anyhow::bail!(
                    "config error: {} is covered by a protected path — fsnitch cannot protect its own operational paths",
                    p.display()
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsnitch_core::config::Mode;

    fn write_config(dir: &Path, body: &str) {
        std::fs::write(dir.join("config.toml"), body).unwrap();
    }

    fn policy(path: &str) -> PathPolicy {
        PathPolicy {
            path: path.into(),
            mode: Mode::Ask,
            allow: vec![],
            deny: vec![],
        }
    }

    #[test]
    fn add_managed_path_persists_and_updates_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        write_config(dir.path(), "");
        let state = State::load(dir.path()).unwrap();
        state.add_managed_path(policy("/data/x")).unwrap();
        let snap = state.snapshot();
        assert_eq!(snap.config.paths.len(), 1);
        assert!(snap.managed_paths.contains("/data/x"));
        assert!(dir.path().join("paths.d/managed.toml").exists());
        // Duplicate path is rejected.
        assert!(state.add_managed_path(policy("/data/x")).is_err());
    }

    #[test]
    fn add_managed_path_covering_own_paths_reverts_file() {
        let dir = tempfile::tempdir().unwrap();
        write_config(dir.path(), "");
        let state = State::load(dir.path()).unwrap();
        let cfg_dir = dir.path().to_str().unwrap().to_string();
        assert!(state.add_managed_path(policy(&cfg_dir)).is_err());
        // The managed file was reverted (didn't exist before -> removed).
        assert!(!dir.path().join("paths.d/managed.toml").exists());
        assert!(state.snapshot().config.paths.is_empty());
    }

    #[test]
    fn remove_managed_path_by_path() {
        let dir = tempfile::tempdir().unwrap();
        write_config(dir.path(), "");
        let state = State::load(dir.path()).unwrap();
        state.add_managed_path(policy("/data/x")).unwrap();
        assert!(state.remove_managed_path("/data/nope").unwrap().is_none());
        assert_eq!(
            state.remove_managed_path("/data/x").unwrap().as_deref(),
            Some("/data/x")
        );
        assert!(state.snapshot().config.paths.is_empty());
        assert!(state.snapshot().managed_paths.is_empty());
    }

    #[test]
    fn update_managed_path_mutates_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        write_config(dir.path(), "");
        let state = State::load(dir.path()).unwrap();
        state.add_managed_path(policy("/data/x")).unwrap();
        let applied = state
            .update_managed_path("/data/x", |p| {
                p.allow.push(fsnitch_core::config::AllowEntry {
                    program: PathBuf::from("/usr/bin/cat"),
                    sha256: None,
                });
                Ok(())
            })
            .unwrap();
        assert!(matches!(applied, ManagedUpdate::Updated));
        // The appended entry is visible and persisted.
        let snap = state.snapshot();
        let p = snap
            .config
            .paths
            .iter()
            .find(|p| p.path == "/data/x")
            .unwrap();
        assert_eq!(p.allow.len(), 1);
        assert_eq!(p.allow[0].program, PathBuf::from("/usr/bin/cat"));
        let reloaded = State::load(dir.path()).unwrap();
        assert_eq!(
            reloaded
                .snapshot()
                .config
                .paths
                .iter()
                .find(|p| p.path == "/data/x")
                .unwrap()
                .allow
                .len(),
            1
        );
        // Unknown managed path -> NotManaged.
        assert!(matches!(
            state.update_managed_path("/data/nope", |_| Ok(())).unwrap(),
            ManagedUpdate::NotManaged
        ));
    }

    #[test]
    fn forget_remembered_filters_by_program_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        write_config(dir.path(), "");
        let state = State::load(dir.path()).unwrap();
        state
            .set_remembered("/p", std::path::PathBuf::from("/usr/bin/a"), true)
            .unwrap();
        state
            .set_remembered("/p", std::path::PathBuf::from("/usr/bin/b"), false)
            .unwrap();

        // Program-filtered: only that entry goes.
        assert_eq!(
            state
                .forget_remembered("/p", Some(std::path::Path::new("/usr/bin/a")))
                .unwrap(),
            1
        );
        let snap = state.snapshot();
        assert_eq!(
            snap.remembered
                .get("/p", std::path::Path::new("/usr/bin/a")),
            None
        );
        assert_eq!(
            snap.remembered
                .get("/p", std::path::Path::new("/usr/bin/b")),
            Some(false)
        );

        // Path-wide: the rest goes, persisted on disk.
        assert_eq!(state.forget_remembered("/p", None).unwrap(), 1);
        assert_eq!(state.forget_remembered("/p", None).unwrap(), 0);
        let reloaded = State::load(dir.path()).unwrap();
        assert!(reloaded.snapshot().remembered.is_empty());
    }

    #[test]
    fn remove_managed_path_purges_remembered_verdicts() {
        let dir = tempfile::tempdir().unwrap();
        write_config(dir.path(), "");
        let state = State::load(dir.path()).unwrap();
        state.add_managed_path(policy("/data/x")).unwrap();
        state
            .set_remembered("/data/x", std::path::PathBuf::from("/usr/bin/x"), true)
            .unwrap();
        assert_eq!(
            state.remove_managed_path("/data/x").unwrap().as_deref(),
            Some("/data/x")
        );
        // The allow_forever verdict must not survive the path (it would
        // silently resurrect on a later re-protect of the same path).
        assert_eq!(
            state
                .snapshot()
                .remembered
                .get("/data/x", std::path::Path::new("/usr/bin/x")),
            None
        );
        // Persisted, not just in-memory.
        let reloaded = State::load(dir.path()).unwrap();
        assert_eq!(
            reloaded
                .snapshot()
                .remembered
                .get("/data/x", std::path::Path::new("/usr/bin/x")),
            None
        );
    }

    #[test]
    fn reload_keeps_old_paths_on_broken_config() {
        let dir = tempfile::tempdir().unwrap();
        write_config(dir.path(), "[[path]]\npath = \"/a\"\nmode = \"block\"\n");
        let state = State::load(dir.path()).unwrap();
        assert_eq!(state.snapshot().config.paths.len(), 1);

        write_config(dir.path(), "this is not toml [");
        assert!(state.reload().is_err());
        // old snapshot still active
        assert_eq!(state.snapshot().config.paths.len(), 1);
        assert_eq!(state.snapshot().config.paths[0].path, "/a");
    }

    #[test]
    fn set_remembered_persists_and_is_visible_in_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("config.toml"),
            "[[path]]\npath = \"/vaults\"\nmode = \"ask\"\n",
        )
        .unwrap();
        let state = State::load(dir.path()).unwrap();
        state
            .set_remembered(
                "/vaults",
                std::path::PathBuf::from("/usr/bin/keepassxc"),
                true,
            )
            .unwrap();
        // visible in a fresh snapshot
        assert_eq!(
            state
                .snapshot()
                .remembered
                .get("/vaults", std::path::Path::new("/usr/bin/keepassxc")),
            Some(true)
        );
        // and persisted to disk
        let reloaded = State::load(dir.path()).unwrap();
        assert_eq!(
            reloaded
                .snapshot()
                .remembered
                .get("/vaults", std::path::Path::new("/usr/bin/keepassxc")),
            Some(true)
        );
    }

    #[test]
    fn snapshot_exposes_remembered_overlay() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("config.toml"),
            "[[path]]\npath = \"/vaults\"\nmode = \"ask\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("remembered.toml"),
            "[[entry]]\npath = \"/vaults\"\nprogram = \"/usr/bin/keepassxc\"\nallow = true\n",
        )
        .unwrap();
        let state = State::load(dir.path()).unwrap();
        let snap = state.snapshot();
        assert_eq!(
            snap.remembered
                .get("/vaults", std::path::Path::new("/usr/bin/keepassxc")),
            Some(true)
        );
    }

    #[test]
    fn rejects_paths_covering_own_paths() {
        // The guard must protect the config dir ACTUALLY in use (--config),
        // not a hardcoded /etc/fsnitch.
        let dir = tempfile::tempdir().unwrap();
        write_config(
            dir.path(),
            &format!(
                "[[path]]\npath = \"{}\"\nmode = \"block\"\n",
                dir.path().display()
            ),
        );
        assert!(State::load(dir.path()).is_err());

        // The runtime socket dir stays guarded too.
        let dir2 = tempfile::tempdir().unwrap();
        write_config(
            dir2.path(),
            "[[path]]\npath = \"/run/fsnitch\"\nmode = \"block\"\n",
        );
        assert!(State::load(dir2.path()).is_err());
    }

    #[test]
    fn self_protection_guard_fires_through_symlinked_config_dir() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real-cfg");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link-cfg");
        symlink(&real, &link).unwrap();
        // The policy covers the REAL config dir; the daemon is started with the
        // symlinked --config path. Both sides must be compared canonically or
        // the deadlock guard silently stops firing.
        let real_canon = real.canonicalize().unwrap();
        write_config(
            &real,
            &format!(
                "[[path]]\npath = \"{}\"\nmode = \"block\"\n",
                real_canon.display()
            ),
        );
        assert!(State::load(&link).is_err());
    }

    #[test]
    fn duplicate_canonical_paths_are_rejected_naming_both_originals() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir_all(real.join("vaults")).unwrap();
        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();
        // One entry via the symlink, one direct: distinct raw strings (so the
        // raw DuplicatePath check passes) that collapse to one canonical path.
        // Silently keeping only one would let the laxer mode win the tie-break.
        let via_link = format!("{}/vaults", link.display());
        let direct = real.join("vaults").canonicalize().unwrap();
        write_config(
            dir.path(),
            &format!(
                "[[path]]\npath = \"{via_link}\"\nmode = \"block\"\n\
                 [[path]]\npath = \"{}\"\nmode = \"ask\"\n",
                direct.display()
            ),
        );
        let err = match State::load(dir.path()) {
            Ok(_) => panic!("load unexpectedly succeeded with colliding paths"),
            Err(e) => e.to_string(),
        };
        // The error names both ORIGINAL paths so the user can find them.
        assert!(err.contains(&via_link), "missing symlink original: {err}");
        assert!(
            err.contains(&direct.display().to_string()),
            "missing direct original: {err}"
        );
    }

    #[test]
    fn drop_in_nonexistent_leaf_under_symlinked_dir_resolves_dir_and_keeps_leaf() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();
        // The spec's motivating case: protect a vault that does not exist yet,
        // through a symlinked directory. The dir resolves, the leaf is kept.
        std::fs::write(
            dir.path().join("config.toml"),
            format!(
                "[[path]]\npath = \"{}/newvault.kdbx\"\nmode = \"block\"\n",
                link.display()
            ),
        )
        .unwrap();

        let state = State::load(dir.path()).unwrap();
        let snap = state.snapshot();
        let expected = real.canonicalize().unwrap().join("newvault.kdbx");
        assert_eq!(
            snap.config.paths[0].path,
            expected.to_string_lossy().as_ref()
        );
        assert!(snap.rules.policy_for(&expected).is_some());
    }

    #[test]
    fn managed_entry_with_symlinked_ancestor_is_cli_and_removable() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        write_config(dir.path(), "");
        let real = dir.path().join("real");
        std::fs::create_dir_all(real.join("vaults")).unwrap();
        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();
        // A managed.toml whose stored path goes through the symlink (written
        // before canonicalization existed, or the ancestor became a symlink
        // later). It must still compare equal to the canonicalized config path.
        std::fs::create_dir_all(dir.path().join("paths.d")).unwrap();
        std::fs::write(
            dir.path().join("paths.d/managed.toml"),
            format!(
                "[[path]]\npath = \"{}/vaults\"\nmode = \"ask\"\n",
                link.display()
            ),
        )
        .unwrap();

        let state = State::load(dir.path()).unwrap();
        let snap = state.snapshot();
        let canonical = real.join("vaults").canonicalize().unwrap();
        let canonical_str = canonical.to_string_lossy().into_owned();
        // The managed set holds the canonical path, matching config.paths — so
        // `list` labels it "cli" and allow/deny accept it.
        assert_eq!(snap.config.paths[0].path, canonical_str);
        assert!(snap.managed_paths.contains(&canonical_str));
        // And it is removable by its canonical path (what the CLI sends).
        assert_eq!(
            state
                .remove_managed_path(&canonical_str)
                .unwrap()
                .as_deref(),
            Some(canonical_str.as_str())
        );
        assert!(state.snapshot().config.paths.is_empty());
        assert!(state.snapshot().managed_paths.is_empty());
    }

    #[test]
    fn drop_in_path_with_symlinked_ancestor_is_canonicalized() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        // real/vaults exists; link -> real; the drop-in protects link/vaults.
        let real = dir.path().join("real");
        std::fs::create_dir_all(real.join("vaults")).unwrap();
        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();

        std::fs::write(
            dir.path().join("config.toml"),
            format!(
                "[[path]]\npath = \"{}/vaults\"\nmode = \"block\"\n",
                link.display()
            ),
        )
        .unwrap();

        let state = State::load(dir.path()).unwrap();
        let snap = state.snapshot();
        // The compiled policy matches the CANONICAL (real) path, not the symlink.
        let canonical = real.join("vaults").canonicalize().unwrap();
        assert!(snap.rules.policy_for(&canonical).is_some());
        // And an access reported under the symlink path (which the kernel never
        // produces) is NOT how matching happens — canonical is what matches.
        assert!(
            snap.rules.policy_for(&link.join("vaults")).is_none()
                || canonical == link.join("vaults")
        );
    }
}
