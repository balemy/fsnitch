//! Path pauses: temporarily suspend a path's policy (all programs allowed).
//! Memory-only by design — a daemon restart falls back to protection.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// `now + duration`, saturated far into the future instead of panicking on
/// overflow. A hostile/huge `secs` from the wire must never panic a store
/// method — a panic under a held lock would poison the mutex and take the
/// whole daemon down on the next event.
pub(crate) fn deadline(duration: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(duration)
        // ~100 years: effectively permanent, but a finite Instant that never
        // overflows in later arithmetic.
        .unwrap_or_else(|| now + Duration::from_secs(60 * 60 * 24 * 365 * 100))
}

struct Entry {
    path: String,
    /// None = global (root CLI); Some(uid) = only that user's processes.
    uid: Option<u32>,
    until: Instant,
}

#[derive(Default)]
pub struct SnoozeStore {
    entries: Mutex<Vec<Entry>>,
}

impl SnoozeStore {
    /// Set (or replace) the pause for (path, uid scope).
    pub fn set(&self, path: &str, uid: Option<u32>, duration: Duration) {
        // Compute the deadline (overflow-safe) BEFORE locking, so a hostile
        // `secs` can neither panic nor poison the mutex.
        let until = deadline(duration);
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|e| !(e.path == path && e.uid == uid));
        entries.push(Entry {
            path: path.to_string(),
            uid,
            until,
        });
    }

    /// Is `path` paused for an event by `event_uid`? A global entry matches
    /// any uid; a uid entry needs a known, equal uid.
    pub fn active(&self, path: &str, event_uid: Option<u32>) -> bool {
        let now = Instant::now();
        self.entries.lock().unwrap().iter().any(|e| {
            e.path == path
                && e.until > now
                && (e.uid.is_none() || (event_uid.is_some() && e.uid == event_uid))
        })
    }

    /// Active pauses as (path, uid, remaining_secs); prunes expired ones.
    pub fn list(&self) -> Vec<(String, Option<u32>, u64)> {
        let now = Instant::now();
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|e| e.until > now);
        entries
            .iter()
            .map(|e| (e.path.clone(), e.uid, (e.until - now).as_secs()))
            .collect()
    }

    /// Clear pauses for `path` (or all). Returns how many were removed.
    pub fn clear(&self, path: Option<&str>) -> usize {
        let mut entries = self.entries.lock().unwrap();
        let before = entries.len();
        match path {
            Some(path) => entries.retain(|e| e.path != path),
            None => entries.clear(),
        }
        before - entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: Duration = Duration::from_secs(60);

    #[test]
    fn set_and_active_with_uid_scoping() {
        let s = SnoozeStore::default();
        assert!(!s.active("/vaults", Some(1000)));

        // uid-scoped: only that uid, and only when the event uid is known.
        s.set("/vaults", Some(1000), MIN);
        assert!(s.active("/vaults", Some(1000)));
        assert!(!s.active("/vaults", Some(1001)));
        assert!(!s.active("/vaults", None));
        assert!(!s.active("/other", Some(1000)));

        // global: matches every uid, known or not.
        s.set("/vaults", None, MIN);
        assert!(s.active("/vaults", Some(1001)));
        assert!(s.active("/vaults", None));
    }

    #[test]
    fn expired_snooze_is_inactive_and_pruned() {
        let s = SnoozeStore::default();
        s.set("/vaults", None, Duration::ZERO);
        assert!(!s.active("/vaults", Some(1000)));
        assert!(s.list().is_empty());
    }

    #[test]
    fn set_replaces_same_scope() {
        let s = SnoozeStore::default();
        s.set("/vaults", Some(1000), MIN);
        s.set("/vaults", Some(1000), MIN * 2);
        assert_eq!(s.list().len(), 1);
        let (_, _, remaining) = s.list().remove(0);
        assert!(
            remaining > 60,
            "replacement should extend, got {remaining}s"
        );
    }

    #[test]
    fn huge_duration_does_not_panic() {
        // A hostile `secs` (from a modified agent or a fat-fingered CLI) must
        // saturate, never panic — a panic here would poison the mutex and
        // crash the daemon on the next event.
        let s = SnoozeStore::default();
        s.set("/vaults", None, Duration::from_secs(u64::MAX));
        assert!(s.active("/vaults", Some(1000)));
    }

    #[test]
    fn clear_one_and_all() {
        let s = SnoozeStore::default();
        s.set("/a", None, MIN);
        s.set("/a", Some(1000), MIN);
        s.set("/b", None, MIN);
        assert_eq!(s.clear(Some("/a")), 2);
        assert!(s.active("/b", None));
        assert_eq!(s.clear(None), 1);
        assert!(s.list().is_empty());
    }
}
