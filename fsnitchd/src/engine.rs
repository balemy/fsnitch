//! Per-event decision wiring: pure classification into Resolved or Prompt.

use crate::hashing::PinHashes;
use crate::snooze::SnoozeStore;
use fsnitch_core::config::{FailAction, General, Mode};
use fsnitch_core::decision::{evaluate, Outcome};
use fsnitch_core::eventlog::EventRecord;
use fsnitch_core::remembered::RememberedStore;
use fsnitch_core::rules::CompiledPaths;
use std::path::{Path, PathBuf};

pub struct EventDecision {
    pub allow: bool,
    pub record: Option<EventRecord>,
}

/// A prompt that must be routed to the user's agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptContext {
    pub path: String,
    pub program: PathBuf,
    pub pid: i32,
    pub uid: u32,
}

#[derive(Debug)]
pub enum Decision {
    Resolved(EventDecision),
    Prompt(PromptContext),
}

// Manual Debug for EventDecision so Decision can derive it without dumping the
// whole record in test output.
impl std::fmt::Debug for EventDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventDecision")
            .field("allow", &self.allow)
            .field("has_record", &self.record.is_some())
            .finish()
    }
}

/// Build a log record for a resolved decision. `path` is the protected policy
/// path; `file` is the specific file the program tried to open.
#[allow(clippy::too_many_arguments)]
pub fn make_record(
    path: &str,
    file: &Path,
    program: Option<&Path>,
    pid: i32,
    uid: Option<u32>,
    allow: bool,
    source: &str,
) -> EventRecord {
    EventRecord {
        ts: EventRecord::now_ts(),
        path: path.to_string(),
        file: file.to_path_buf(),
        program: program.map(|p| p.to_path_buf()),
        pid,
        uid: uid.unwrap_or(u32::MAX),
        decision: if allow { "allow".into() } else { "deny".into() },
        source: source.into(),
    }
}

fn resolved(
    path: &str,
    file: &Path,
    program: Option<&Path>,
    pid: i32,
    uid: Option<u32>,
    allow: bool,
    source: &str,
) -> Decision {
    Decision::Resolved(EventDecision {
        allow,
        record: Some(make_record(path, file, program, pid, uid, allow, source)),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn decide_event(
    rules: &CompiledPaths,
    general: &General,
    overlay: &RememberedStore,
    snoozes: &SnoozeStore,
    pins: &PinHashes,
    path: &Path,
    program: Option<&Path>,
    pid: i32,
    uid: Option<u32>,
) -> Decision {
    let Some(policy) = rules.policy_for(path) else {
        return Decision::Resolved(EventDecision {
            allow: true,
            record: None,
        });
    };

    // An active pause suspends the whole path: allow anything, but log it.
    if snoozes.active(&policy.path, uid) {
        return resolved(&policy.path, path, program, pid, uid, true, "paused");
    }

    // A pinned allow/deny entry verifies against the subject program's hash,
    // looked up from the load-time pin cache (fresh per stat) — never read here.
    let outcome = match program {
        Some(program) => evaluate(policy, program, |e| pins.verify(e)),
        None => match policy.mode {
            Mode::Watch => Outcome::AllowWatch,
            Mode::Block => Outcome::Deny,
            Mode::Ask => Outcome::Ask,
        },
    };

    match outcome {
        Outcome::Allow => resolved(&policy.path, path, program, pid, uid, true, "policy"),
        Outcome::Deny => resolved(&policy.path, path, program, pid, uid, false, "policy"),
        Outcome::AllowWatch => resolved(&policy.path, path, program, pid, uid, true, "watch"),
        Outcome::Ask => {
            // Need a resolved subject (program + uid) to consult the overlay and
            // to route a prompt; otherwise fall back to on_no_agent.
            let (Some(program), Some(uid)) = (program, uid) else {
                let allow = general.on_no_agent == FailAction::Allow;
                return resolved(
                    &policy.path,
                    path,
                    program,
                    pid,
                    Some(uid.unwrap_or(u32::MAX)),
                    allow,
                    "no_agent",
                );
            };
            if let Some(allow) = overlay.get(&policy.path, program) {
                return resolved(
                    &policy.path,
                    path,
                    Some(program),
                    pid,
                    Some(uid),
                    allow,
                    "remembered",
                );
            }
            Decision::Prompt(PromptContext {
                path: policy.path.clone(),
                program: program.to_path_buf(),
                pid,
                uid,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsnitch_core::config::{Config, FailAction};
    use fsnitch_core::remembered::RememberedStore;
    use fsnitch_core::rules::CompiledPaths;
    use std::path::Path;

    fn setup(mode: &str) -> (Config, CompiledPaths) {
        let cfg = Config::parse_str(&format!(
            r#"
            [[path]]
            path = "/vaults"
            mode = "{mode}"
            allow = [{{ program = "/usr/bin/keepassxc" }}]
        "#
        ))
        .unwrap();
        let rules = CompiledPaths::compile(&cfg);
        (cfg, rules)
    }

    #[test]
    fn unprotected_path_allowed_without_record() {
        let (cfg, rules) = setup("block");
        let overlay = RememberedStore::default();
        let pins = PinHashes::default();
        let d = decide_event(
            &rules,
            &cfg.general,
            &overlay,
            &SnoozeStore::default(),
            &pins,
            Path::new("/etc/passwd"),
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

    #[test]
    fn allowlisted_program_allowed_with_record() {
        let (cfg, rules) = setup("block");
        let overlay = RememberedStore::default();
        let pins = PinHashes::default();
        let d = decide_event(
            &rules,
            &cfg.general,
            &overlay,
            &SnoozeStore::default(),
            &pins,
            Path::new("/vaults/a.kdbx"),
            Some(Path::new("/usr/bin/keepassxc")),
            1,
            Some(1000),
        );
        let Decision::Resolved(dec) = d else {
            panic!("expected Resolved")
        };
        assert!(dec.allow);
        let rec = dec.record.unwrap();
        assert_eq!(rec.decision, "allow");
        assert_eq!(rec.source, "policy");
    }

    #[test]
    fn block_denies_unlisted() {
        let (cfg, rules) = setup("block");
        let overlay = RememberedStore::default();
        let pins = PinHashes::default();
        let d = decide_event(
            &rules,
            &cfg.general,
            &overlay,
            &SnoozeStore::default(),
            &pins,
            Path::new("/vaults/a.kdbx"),
            Some(Path::new("/tmp/stealer")),
            1,
            Some(1000),
        );
        let Decision::Resolved(dec) = d else {
            panic!("expected Resolved")
        };
        assert!(!dec.allow);
        assert_eq!(dec.record.unwrap().source, "policy");
    }

    #[test]
    fn watch_allows_unlisted_with_watch_source() {
        let (cfg, rules) = setup("watch");
        let overlay = RememberedStore::default();
        let pins = PinHashes::default();
        let d = decide_event(
            &rules,
            &cfg.general,
            &overlay,
            &SnoozeStore::default(),
            &pins,
            Path::new("/vaults/a.kdbx"),
            Some(Path::new("/tmp/whatever")),
            1,
            Some(1000),
        );
        let Decision::Resolved(dec) = d else {
            panic!("expected Resolved")
        };
        assert!(dec.allow);
        assert_eq!(dec.record.unwrap().source, "watch");
    }

    #[test]
    fn unresolvable_program_is_never_allowlisted() {
        // Process died before we could read /proc/<pid>/exe -> unknown subject.
        let (cfg, rules) = setup("block");
        let overlay = RememberedStore::default();
        let pins = PinHashes::default();
        let d = decide_event(
            &rules,
            &cfg.general,
            &overlay,
            &SnoozeStore::default(),
            &pins,
            Path::new("/vaults/a.kdbx"),
            None,
            1,
            None,
        );
        let Decision::Resolved(dec) = d else {
            panic!("expected Resolved")
        };
        assert!(!dec.allow);
    }

    #[test]
    fn ask_mode_unlisted_returns_prompt() {
        let (cfg, rules) = setup("ask");
        let overlay = RememberedStore::default();
        let pins = PinHashes::default();
        let d = decide_event(
            &rules,
            &cfg.general,
            &overlay,
            &SnoozeStore::default(),
            &pins,
            Path::new("/vaults/a.kdbx"),
            Some(Path::new("/tmp/stealer")),
            42,
            Some(1000),
        );
        match d {
            Decision::Prompt(ctx) => {
                assert_eq!(ctx.path, "/vaults");
                assert_eq!(ctx.program, Path::new("/tmp/stealer"));
                assert_eq!(ctx.uid, 1000);
                assert_eq!(ctx.pid, 42);
            }
            other => panic!("expected Prompt, got {other:?}"),
        }
    }

    #[test]
    fn overlay_allow_short_circuits_prompt() {
        let (cfg, rules) = setup("ask");
        let mut overlay = RememberedStore::default();
        let pins = PinHashes::default();
        overlay
            .set("/vaults", std::path::PathBuf::from("/tmp/stealer"), true)
            .unwrap();
        let d = decide_event(
            &rules,
            &cfg.general,
            &overlay,
            &SnoozeStore::default(),
            &pins,
            Path::new("/vaults/a.kdbx"),
            Some(Path::new("/tmp/stealer")),
            42,
            Some(1000),
        );
        match d {
            Decision::Resolved(dec) => {
                assert!(dec.allow);
                assert_eq!(dec.record.unwrap().source, "remembered");
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn overlay_deny_short_circuits_prompt() {
        let (cfg, rules) = setup("ask");
        let mut overlay = RememberedStore::default();
        let pins = PinHashes::default();
        overlay
            .set("/vaults", std::path::PathBuf::from("/tmp/stealer"), false)
            .unwrap();
        let d = decide_event(
            &rules,
            &cfg.general,
            &overlay,
            &SnoozeStore::default(),
            &pins,
            Path::new("/vaults/a.kdbx"),
            Some(Path::new("/tmp/stealer")),
            42,
            Some(1000),
        );
        match d {
            Decision::Resolved(dec) => {
                assert!(!dec.allow);
                assert_eq!(dec.record.unwrap().source, "remembered");
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn prompt_without_program_falls_back_to_on_no_agent() {
        let (mut cfg, rules) = setup("ask");
        cfg.general.on_no_agent = FailAction::Deny;
        let overlay = RememberedStore::default();
        let pins = PinHashes::default();
        let d = decide_event(
            &rules,
            &cfg.general,
            &overlay,
            &SnoozeStore::default(),
            &pins,
            Path::new("/vaults/a.kdbx"),
            None,
            42,
            None,
        );
        match d {
            Decision::Resolved(dec) => {
                assert!(!dec.allow);
                assert_eq!(dec.record.unwrap().source, "no_agent");
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn block_and_watch_still_resolve() {
        let overlay = RememberedStore::default();
        let pins = PinHashes::default();
        let (cfg, rules) = setup("block");
        let d = decide_event(
            &rules,
            &cfg.general,
            &overlay,
            &SnoozeStore::default(),
            &pins,
            Path::new("/vaults/a.kdbx"),
            Some(Path::new("/tmp/x")),
            1,
            Some(1000),
        );
        assert!(matches!(d, Decision::Resolved(dec) if !dec.allow));

        let (cfg, rules) = setup("watch");
        let d = decide_event(
            &rules,
            &cfg.general,
            &overlay,
            &SnoozeStore::default(),
            &pins,
            Path::new("/vaults/a.kdbx"),
            Some(Path::new("/tmp/x")),
            1,
            Some(1000),
        );
        assert!(matches!(d, Decision::Resolved(dec) if dec.allow));
    }

    #[test]
    fn paused_path_allows_unlisted_program() {
        let (cfg, rules) = setup("block");
        let overlay = RememberedStore::default();
        let pins = PinHashes::default();
        let snoozes = SnoozeStore::default();
        snoozes.set("/vaults", None, std::time::Duration::from_secs(60));
        let d = decide_event(
            &rules,
            &cfg.general,
            &overlay,
            &snoozes,
            &pins,
            Path::new("/vaults/a.kdbx"),
            Some(Path::new("/tmp/stealer")),
            1,
            Some(1000),
        );
        let Decision::Resolved(dec) = d else {
            panic!("expected Resolved")
        };
        assert!(dec.allow);
        assert_eq!(dec.record.unwrap().source, "paused");
    }

    #[test]
    fn uid_scoped_pause_does_not_leak() {
        let (cfg, rules) = setup("block");
        let overlay = RememberedStore::default();
        let pins = PinHashes::default();
        let snoozes = SnoozeStore::default();
        snoozes.set("/vaults", Some(1000), std::time::Duration::from_secs(60));

        // Another uid stays protected.
        let d = decide_event(
            &rules,
            &cfg.general,
            &overlay,
            &snoozes,
            &pins,
            Path::new("/vaults/a.kdbx"),
            Some(Path::new("/tmp/stealer")),
            1,
            Some(1001),
        );
        assert!(matches!(d, Decision::Resolved(dec) if !dec.allow));

        // An unknown uid stays protected too.
        let d = decide_event(
            &rules,
            &cfg.general,
            &overlay,
            &snoozes,
            &pins,
            Path::new("/vaults/a.kdbx"),
            Some(Path::new("/tmp/stealer")),
            1,
            None,
        );
        assert!(matches!(d, Decision::Resolved(dec) if !dec.allow));

        // The pausing uid passes.
        let d = decide_event(
            &rules,
            &cfg.general,
            &overlay,
            &snoozes,
            &pins,
            Path::new("/vaults/a.kdbx"),
            Some(Path::new("/tmp/stealer")),
            1,
            Some(1000),
        );
        assert!(matches!(d, Decision::Resolved(dec) if dec.allow));
    }
}
