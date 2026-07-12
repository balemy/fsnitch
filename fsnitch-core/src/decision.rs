//! Pure decision logic: policy + subject program -> outcome. Hashing injected.

use crate::config::{AllowEntry, Mode, PathPolicy};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Allow,
    AllowWatch,
    Deny,
    Ask,
}

fn entry_matches(
    entry: &AllowEntry,
    program: &Path,
    hash_of: &impl Fn(&Path) -> Option<String>,
) -> bool {
    if entry.program != program {
        return false;
    }
    match &entry.sha256 {
        None => true,
        Some(pin) => hash_of(program).as_deref() == Some(pin.as_str()),
    }
}

pub fn evaluate(
    policy: &PathPolicy,
    program: &Path,
    hash_of: impl Fn(&Path) -> Option<String>,
) -> Outcome {
    // A pinned deny narrows to that program's content; an unverifiable pin
    // does NOT trigger the deny (fail-safe).
    if policy
        .deny
        .iter()
        .any(|e| entry_matches(e, program, &hash_of))
    {
        return Outcome::Deny;
    }
    if policy
        .allow
        .iter()
        .any(|e| entry_matches(e, program, &hash_of))
    {
        return Outcome::Allow;
    }
    match policy.mode {
        Mode::Block => Outcome::Deny,
        Mode::Watch => Outcome::AllowWatch,
        Mode::Ask => Outcome::Ask,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn policy(mode: Mode, allow: Vec<AllowEntry>, deny: Vec<AllowEntry>) -> PathPolicy {
        PathPolicy {
            path: "/x".into(),
            mode,
            allow,
            deny,
        }
    }

    fn entry(program: &str) -> AllowEntry {
        AllowEntry {
            program: PathBuf::from(program),
            sha256: None,
        }
    }

    fn no_hash(_: &Path) -> Option<String> {
        None
    }

    #[test]
    fn allowlisted_program_is_allowed() {
        let p = policy(Mode::Block, vec![entry("/usr/bin/keepassxc")], vec![]);
        assert_eq!(
            evaluate(&p, Path::new("/usr/bin/keepassxc"), no_hash),
            Outcome::Allow
        );
    }

    #[test]
    fn unlisted_program_follows_mode() {
        let p = |m| policy(m, vec![entry("/usr/bin/keepassxc")], vec![]);
        let evil = Path::new("/tmp/stealer");
        assert_eq!(evaluate(&p(Mode::Block), evil, no_hash), Outcome::Deny);
        assert_eq!(
            evaluate(&p(Mode::Watch), evil, no_hash),
            Outcome::AllowWatch
        );
        assert_eq!(evaluate(&p(Mode::Ask), evil, no_hash), Outcome::Ask);
    }

    #[test]
    fn deny_wins_and_pin_must_match() {
        let d = policy(
            Mode::Ask,
            vec![entry("/usr/bin/tool")],
            vec![entry("/usr/bin/tool")],
        );
        assert_eq!(
            evaluate(&d, Path::new("/usr/bin/tool"), no_hash),
            Outcome::Deny
        );

        let pinned = AllowEntry {
            program: PathBuf::from("/usr/bin/borg"),
            sha256: Some("goodhash".into()),
        };
        let a = policy(Mode::Block, vec![pinned], vec![]);
        let exe = Path::new("/usr/bin/borg");
        assert_eq!(
            evaluate(&a, exe, |_| Some("goodhash".into())),
            Outcome::Allow
        );
        assert_eq!(evaluate(&a, exe, |_| Some("bad".into())), Outcome::Deny);
        assert_eq!(evaluate(&a, exe, no_hash), Outcome::Deny);
    }
}
