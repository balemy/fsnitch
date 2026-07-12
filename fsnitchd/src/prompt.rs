//! Prompt subsystem: verdict cache (once verdicts) and the pending-prompt map.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// TTL cache of "once" verdicts, keyed by (path, program).
pub struct VerdictCache {
    ttl: Duration,
    map: Mutex<HashMap<(String, PathBuf), (bool, Instant)>>,
}

impl VerdictCache {
    pub fn new(ttl: Duration) -> VerdictCache {
        VerdictCache {
            ttl,
            map: Mutex::new(HashMap::new()),
        }
    }

    pub fn insert(&self, path: &str, program: &Path, allow: bool) {
        self.insert_with_ttl(path, program, allow, self.ttl);
    }

    /// Insert with a caller-chosen TTL (timed allows from the dialog).
    pub fn insert_with_ttl(&self, path: &str, program: &Path, allow: bool, ttl: Duration) {
        // Overflow-safe: a hostile/huge `secs` from the wire must not panic.
        let expiry = crate::snooze::deadline(ttl);
        self.map
            .lock()
            .unwrap()
            .insert((path.to_string(), program.to_path_buf()), (allow, expiry));
    }

    /// Active entries as (path, program, allow, remaining_secs); prunes expired.
    pub fn list(&self) -> Vec<(String, PathBuf, bool, u64)> {
        let now = Instant::now();
        let mut map = self.map.lock().unwrap();
        map.retain(|_, (_, expiry)| *expiry > now);
        map.iter()
            .map(|((path, program), (allow, expiry))| {
                (
                    path.clone(),
                    program.clone(),
                    *allow,
                    (*expiry - now).as_secs(),
                )
            })
            .collect()
    }

    /// Remove entries for `path` (all of them, or only `program`'s). Returns the count.
    pub fn remove(&self, path: &str, program: Option<&Path>) -> usize {
        let mut map = self.map.lock().unwrap();
        let before = map.len();
        map.retain(|(p, prog), _| !(p == path && program.is_none_or(|x| prog == x)));
        before - map.len()
    }

    /// Returns the cached verdict if present and not expired.
    pub fn get(&self, path: &str, program: &Path) -> Option<bool> {
        let mut map = self.map.lock().unwrap();
        let key = (path.to_string(), program.to_path_buf());
        match map.get(&key) {
            Some((allow, expiry)) if *expiry > Instant::now() => Some(*allow),
            Some(_) => {
                map.remove(&key);
                None
            }
            None => None,
        }
    }

    pub fn flush(&self) {
        self.map.lock().unwrap().clear();
    }
}

/// Dedupe key: one open prompt per (path, program).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PendingKey {
    pub program: PathBuf,
    pub path: String,
}

/// A parked set of events awaiting one verdict.
pub struct Pending<T> {
    pub key: PendingKey,
    pub tokens: Vec<T>,
    pub deadline: Instant,
}

/// Result of a park attempt.
pub enum Parked<T> {
    /// A new prompt was created with this id (send a PromptRequest).
    New(u64),
    /// An existing prompt for the same key absorbed this token (no new request).
    Deduped,
    /// The pending map is at capacity; the token is handed back so the caller
    /// can still answer the event (never drop a token without responding).
    Rejected(T),
}

pub struct PendingPrompts<T> {
    cap: usize,
    next_id: AtomicU64,
    map: Mutex<HashMap<u64, Pending<T>>>,
}

impl<T> PendingPrompts<T> {
    pub fn new(cap: usize) -> PendingPrompts<T> {
        PendingPrompts {
            cap,
            next_id: AtomicU64::new(1),
            map: Mutex::new(HashMap::new()),
        }
    }

    /// Park a token. If a prompt for the same key is open, append (dedupe);
    /// else create a new prompt unless at capacity. On capacity the token is
    /// returned via `Parked::Rejected` so the caller can still answer the event.
    pub fn park(&self, key: PendingKey, token: T, deadline: Instant) -> Parked<T> {
        let mut map = self.map.lock().unwrap();
        if let Some(p) = map.values_mut().find(|p| p.key == key) {
            p.tokens.push(token);
            return Parked::Deduped;
        }
        if map.len() >= self.cap {
            return Parked::Rejected(token);
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        map.insert(
            id,
            Pending {
                key,
                tokens: vec![token],
                deadline,
            },
        );
        Parked::New(id)
    }

    /// Remove and return a specific pending (exactly-once).
    pub fn take(&self, id: u64) -> Option<Pending<T>> {
        self.map.lock().unwrap().remove(&id)
    }

    /// Remove and return all pendings whose deadline is at or before `now`.
    pub fn take_expired(&self, now: Instant) -> Vec<Pending<T>> {
        let mut map = self.map.lock().unwrap();
        let expired_ids: Vec<u64> = map
            .iter()
            .filter(|(_, p)| p.deadline <= now)
            .map(|(id, _)| *id)
            .collect();
        expired_ids
            .into_iter()
            .filter_map(|id| map.remove(&id))
            .collect()
    }

    /// Remove and return everything (used on agent disconnect).
    pub fn take_all(&self) -> Vec<Pending<T>> {
        let mut map = self.map.lock().unwrap();
        map.drain().map(|(_, p)| p).collect()
    }
}

#[cfg(test)]
mod cache_tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Duration;

    #[test]
    fn hit_within_ttl_then_miss_after_expiry() {
        let cache = VerdictCache::new(Duration::from_millis(40));
        cache.insert("vaults", &PathBuf::from("/usr/bin/keepassxc"), true);
        assert_eq!(
            cache.get("vaults", &PathBuf::from("/usr/bin/keepassxc")),
            Some(true)
        );
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(
            cache.get("vaults", &PathBuf::from("/usr/bin/keepassxc")),
            None
        );
    }

    #[test]
    fn keys_are_rule_and_exe_specific() {
        let cache = VerdictCache::new(Duration::from_secs(60));
        cache.insert("r1", &PathBuf::from("/x"), false);
        assert_eq!(cache.get("r1", &PathBuf::from("/x")), Some(false));
        assert_eq!(cache.get("r2", &PathBuf::from("/x")), None);
        assert_eq!(cache.get("r1", &PathBuf::from("/y")), None);
    }

    #[test]
    fn custom_ttl_list_and_remove() {
        let cache = VerdictCache::new(Duration::from_secs(60));
        cache.insert("vaults", Path::new("/usr/bin/cat"), true);
        cache.insert_with_ttl("vaults", Path::new("/usr/bin/dd"), false, Duration::ZERO);
        cache.insert("other", Path::new("/usr/bin/cat"), false);

        // Zero-TTL entry is expired: not a hit, pruned from list.
        assert_eq!(cache.get("vaults", Path::new("/usr/bin/dd")), None);
        let listed = cache.list();
        assert_eq!(listed.len(), 2);
        assert!(listed
            .iter()
            .all(|(_, _, _, remaining)| *remaining <= 60 && *remaining > 0));

        // Program-filtered removal, then path-wide.
        assert_eq!(cache.remove("vaults", Some(Path::new("/usr/bin/cat"))), 1);
        assert_eq!(cache.remove("vaults", None), 0);
        assert_eq!(cache.remove("other", None), 1);
        assert!(cache.list().is_empty());
    }

    #[test]
    fn flush_clears_all() {
        let cache = VerdictCache::new(Duration::from_secs(60));
        cache.insert("r", &PathBuf::from("/x"), true);
        cache.flush();
        assert_eq!(cache.get("r", &PathBuf::from("/x")), None);
    }
}

#[cfg(test)]
mod pending_tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    fn key(program: &str, path: &str) -> PendingKey {
        PendingKey {
            program: PathBuf::from(program),
            path: path.to_string(),
        }
    }

    #[test]
    fn park_assigns_ids_and_take_returns_tokens() {
        let pending: PendingPrompts<u32> = PendingPrompts::new(128);
        let deadline = Instant::now() + Duration::from_secs(30);
        let a = pending.park(key("/x", "r"), 10, deadline);
        let id = match a {
            Parked::New(id) => id,
            _ => panic!("expected New"),
        };
        let taken = pending.take(id).unwrap();
        assert_eq!(taken.tokens, vec![10]);
        assert!(pending.take(id).is_none()); // exactly once
    }

    #[test]
    fn dedupe_same_key_appends_token() {
        let pending: PendingPrompts<u32> = PendingPrompts::new(128);
        let deadline = Instant::now() + Duration::from_secs(30);
        let id = match pending.park(key("/x", "r"), 10, deadline) {
            Parked::New(id) => id,
            _ => panic!("expected New"),
        };
        assert!(matches!(
            pending.park(key("/x", "r"), 11, deadline),
            Parked::Deduped
        ));
        let taken = pending.take(id).unwrap();
        assert_eq!(taken.tokens, vec![10, 11]);
    }

    #[test]
    fn take_expired_returns_only_past_deadline() {
        let pending: PendingPrompts<u32> = PendingPrompts::new(128);
        let now = Instant::now();
        let _ = pending.park(key("/a", "r"), 1, now - Duration::from_secs(1));
        let _ = pending.park(key("/b", "r"), 2, now + Duration::from_secs(30));
        let expired = pending.take_expired(now);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].tokens, vec![1]);
        // the future one is still parked
        assert_eq!(pending.take_all().len(), 1);
    }

    #[test]
    fn take_all_drains_everything() {
        let pending: PendingPrompts<u32> = PendingPrompts::new(128);
        let deadline = Instant::now() + Duration::from_secs(30);
        let _ = pending.park(key("/a", "r"), 1, deadline);
        let _ = pending.park(key("/b", "r"), 2, deadline);
        let all = pending.take_all();
        assert_eq!(all.len(), 2);
        assert!(pending.take_all().is_empty());
    }

    #[test]
    fn park_rejects_when_at_capacity_and_returns_token() {
        let pending: PendingPrompts<u32> = PendingPrompts::new(1);
        let deadline = Instant::now() + Duration::from_secs(30);
        let _ = pending.park(key("/a", "r"), 1, deadline);
        // second distinct key exceeds cap; the token is handed back
        assert!(matches!(
            pending.park(key("/b", "r"), 2, deadline),
            Parked::Rejected(2)
        ));
        // but deduping into an existing key is always allowed
        assert!(matches!(
            pending.park(key("/a", "r"), 3, deadline),
            Parked::Deduped
        ));
    }
}
