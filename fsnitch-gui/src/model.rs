//! GUI view model, kept free of GTK so it is unit-testable: daemon state is
//! folded into per-path views, health is derived for tray and banner, and user
//! actions are turned into `pkexec fsnitch …` command lines.

use fsnitch_core::eventlog::EventRecord;
use fsnitch_core::protocol::{PathSummary, PauseInfo, RememberedInfo, TemporaryInfo};
use std::path::{Path, PathBuf};

/// Everything the GUI shows, fetched in one poll.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Snapshot {
    pub version: String,
    pub agent_connected: bool,
    pub degraded_roots: Vec<PathBuf>,
    pub paths: Vec<PathView>,
    pub events: Vec<EventRecord>,
}

/// Overall protection state (tray icon, banner colour).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    /// Daemon reachable, agent connected, nothing paused or degraded.
    Protected,
    /// Enforcing, but with gaps; each reason is a user-facing sentence.
    Degraded(Vec<String>),
    /// The daemon could not be reached.
    Unprotected(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// Fixed allow/deny entry in the path policy.
    Fixed,
    /// A persisted "always" answer from a prompt.
    Remembered,
    /// A timed verdict; remaining seconds.
    Temporary(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramRow {
    pub program: String,
    pub pinned: bool,
    pub allow: bool,
    pub origin: Origin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathView {
    pub path: String,
    /// "ask" | "block" | "watch"
    pub mode: String,
    /// CLI-managed (changeable from the GUI) vs. defined in a drop-in file.
    pub editable: bool,
    /// Remaining seconds of the longest active pause, if any.
    pub paused_secs: Option<u64>,
    pub programs: Vec<ProgramRow>,
}

/// `home` only shortens paths in the reasons (`~/…`).
pub fn health(snapshot: &Result<Snapshot, String>, home: &Path) -> Health {
    let s = match snapshot {
        Ok(s) => s,
        Err(err) => return Health::Unprotected(err.clone()),
    };
    let mut reasons = Vec::new();
    if !s.agent_connected {
        reasons.push(
            "No prompt agent is running — accesses that should ask are decided without asking."
                .to_string(),
        );
    }
    for p in s.paths.iter().filter(|p| p.paused_secs.is_some()) {
        reasons.push(format!(
            "{} is paused — every program may access it.",
            display_path(&p.path, home)
        ));
    }
    for root in &s.degraded_roots {
        reasons.push(format!(
            "Move protection is off for {} (too many files).",
            root.display()
        ));
    }
    if reasons.is_empty() {
        Health::Protected
    } else {
        Health::Degraded(reasons)
    }
}

const PINNED_SUFFIX: &str = " [pinned]";

fn fixed_row(entry: &str, allow: bool) -> ProgramRow {
    let (program, pinned) = match entry.strip_suffix(PINNED_SUFFIX) {
        Some(program) => (program, true),
        None => (entry, false),
    };
    ProgramRow {
        program: program.to_string(),
        pinned,
        allow,
        origin: Origin::Fixed,
    }
}

/// Fold the daemon's path list and dynamic verdicts into one view per path.
/// Verdicts for a path that is no longer protected are dropped.
pub fn merge(
    paths: Vec<PathSummary>,
    pauses: Vec<PauseInfo>,
    temporary: Vec<TemporaryInfo>,
    remembered: Vec<RememberedInfo>,
) -> Vec<PathView> {
    paths
        .into_iter()
        .map(|p| {
            let mut programs: Vec<ProgramRow> = p
                .allow
                .iter()
                .map(|e| fixed_row(e, true))
                .chain(p.deny.iter().map(|e| fixed_row(e, false)))
                .collect();
            programs.extend(
                remembered
                    .iter()
                    .filter(|r| r.path == p.path)
                    .map(|r| ProgramRow {
                        program: r.program.display().to_string(),
                        pinned: false,
                        allow: r.allow,
                        origin: Origin::Remembered,
                    }),
            );
            programs.extend(
                temporary
                    .iter()
                    .filter(|t| t.path == p.path)
                    .map(|t| ProgramRow {
                        program: t.program.display().to_string(),
                        pinned: false,
                        allow: t.allow,
                        origin: Origin::Temporary(t.remaining_secs),
                    }),
            );
            let paused_secs = pauses
                .iter()
                .filter(|x| x.path == p.path)
                .map(|x| x.remaining_secs)
                .max();
            PathView {
                editable: p.source == "cli",
                path: p.path,
                mode: p.mode,
                paused_secs,
                programs,
            }
        })
        .collect()
}

/// A policy change, run as `pkexec fsnitch …`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Create the path policy, or change the mode of an existing one.
    Protect {
        path: String,
        mode: String,
    },
    /// Allow a program, optionally sha256-pinned, permanently or for `secs`.
    Allow {
        path: String,
        program: String,
        pin: bool,
        secs: Option<u64>,
    },
    Deny {
        path: String,
        program: String,
    },
    /// Remove a fixed allow/deny entry.
    RemoveFixed {
        path: String,
        program: String,
    },
    /// Drop remembered + temporary verdicts (one program's, or all).
    Forget {
        path: String,
        program: Option<String>,
    },
    Unprotect {
        path: String,
    },
    Pause {
        path: String,
        secs: u64,
    },
    /// Clear one path's pause, or all.
    Resume {
        path: Option<String>,
    },
}

impl Action {
    /// Toast text after the command succeeded.
    pub fn done_message(&self) -> String {
        let name = |p: &str| {
            Path::new(p)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| p.to_string())
        };
        match self {
            Action::Protect { path, mode } => format!("{} · mode {mode}", name(path)),
            Action::Allow { program, .. } => format!("{} allowed", name(program)),
            Action::Deny { program, .. } => format!("{} denied", name(program)),
            Action::RemoveFixed { program, .. } => format!("{} removed", name(program)),
            Action::Forget {
                program: Some(program),
                ..
            } => format!("{} forgotten", name(program)),
            Action::Forget { program: None, .. } => "Answers forgotten".into(),
            Action::Unprotect { path } => format!("{} is no longer protected", name(path)),
            Action::Pause { path, .. } => format!("{} paused", name(path)),
            Action::Resume { path: Some(path) } => format!("{} resumed", name(path)),
            Action::Resume { path: None } => "All paths resumed".into(),
        }
    }

    /// The command line: `pkexec <cli> [--socket S] <subcommand> …`. `socket`
    /// is only passed for a non-default control socket (dev runs).
    pub fn argv(&self, cli: &Path, socket: Option<&Path>) -> Vec<String> {
        let mut argv = vec!["pkexec".to_string(), cli.display().to_string()];
        if let Some(socket) = socket {
            argv.push("--socket".into());
            argv.push(socket.display().to_string());
        }
        let s = |x: &str| x.to_string();
        let rest: Vec<String> = match self {
            Action::Protect { path, mode } => vec![s("protect"), s(path), s("--mode"), s(mode)],
            Action::Allow {
                path,
                program,
                pin,
                secs,
            } => {
                let mut v = vec![s("protect"), s(path), s("--program"), s(program)];
                // The CLI rejects --pin with --for: a timed allow is never pinned.
                match secs {
                    Some(secs) => v.extend([s("--for"), format!("{secs}s")]),
                    None if *pin => v.extend([s("--pin"), s("auto")]),
                    None => {}
                }
                v
            }
            Action::Deny { path, program } => {
                vec![s("protect"), s(path), s("--deny"), s(program)]
            }
            Action::RemoveFixed { path, program } => {
                vec![s("unprotect"), s(path), s("--program"), s(program)]
            }
            Action::Forget { path, program } => {
                let mut v = vec![s("forget"), s(path)];
                if let Some(program) = program {
                    v.extend([s("--program"), s(program)]);
                }
                v
            }
            Action::Unprotect { path } => vec![s("unprotect"), s(path)],
            Action::Pause { path, secs } => vec![s("pause"), s(path), format!("{secs}s")],
            Action::Resume { path } => {
                let mut v = vec![s("resume")];
                v.extend(path.iter().cloned());
                v
            }
        };
        argv.extend(rest);
        argv
    }
}

impl Snapshot {
    pub fn any_paused(&self) -> bool {
        self.paths.iter().any(|p| p.paused_secs.is_some())
    }

    /// A copy with remaining times rounded the way `fmt_remaining` shows them,
    /// so polls that only tick a countdown don't rebuild (and re-scroll) views.
    pub fn coarse(&self) -> Snapshot {
        let round = |secs: u64| {
            if secs >= 60 {
                secs.div_ceil(60) * 60
            } else {
                secs
            }
        };
        let mut s = self.clone();
        for p in &mut s.paths {
            p.paused_secs = p.paused_secs.map(round);
            for r in &mut p.programs {
                if let Origin::Temporary(secs) = &mut r.origin {
                    *secs = round(*secs);
                }
            }
        }
        s
    }
}

/// `path` with the home directory shown as `~`.
pub fn display_path(path: &str, home: &Path) -> String {
    match Path::new(path).strip_prefix(home) {
        Ok(rest) if rest.as_os_str().is_empty() => "~".into(),
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => path.to_string(),
    }
}

/// User-facing reason for an event-log `source`.
pub fn reason_label(source: &str) -> &str {
    match source {
        "policy" => "rule",
        "watch" => "watch mode",
        "remembered" => "remembered answer",
        "cache" => "recent answer",
        "prompt" => "your answer",
        "no_agent" => "no prompt agent running",
        "paused" => "path paused",
        "timeout" => "prompt timed out",
        "overload" => "too many open prompts",
        "unresolved_path" => "unresolved path",
        other => other,
    }
}

/// Human-readable remaining time: "2h 5m", "12 min", "41 s".
pub fn fmt_remaining(secs: u64) -> String {
    if secs >= 3600 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{} min", secs.div_ceil(60))
    } else {
        format!("{secs} s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(path: &str, source: &str, allow: &[&str], deny: &[&str]) -> PathSummary {
        PathSummary {
            path: path.into(),
            mode: "ask".into(),
            source: source.into(),
            allow: allow.iter().map(|s| s.to_string()).collect(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn health_of(s: &Result<Snapshot, String>) -> Health {
        health(s, Path::new("/home/u"))
    }

    fn healthy() -> Snapshot {
        Snapshot {
            version: "0.6.0".into(),
            agent_connected: true,
            ..Snapshot::default()
        }
    }

    #[test]
    fn health_red_when_unreachable() {
        assert_eq!(
            health_of(&Err("connection refused".into())),
            Health::Unprotected("connection refused".into())
        );
    }

    #[test]
    fn health_green() {
        assert_eq!(health_of(&Ok(healthy())), Health::Protected);
    }

    #[test]
    fn health_yellow_without_agent() {
        let s = Snapshot {
            agent_connected: false,
            ..healthy()
        };
        match health_of(&Ok(s)) {
            Health::Degraded(reasons) => {
                assert_eq!(reasons.len(), 1);
                assert!(reasons[0].contains("agent"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn health_yellow_when_paused_or_degraded() {
        let mut s = healthy();
        s.paths = merge(
            vec![summary("/v", "cli", &[], &[])],
            vec![PauseInfo {
                path: "/v".into(),
                uid: None,
                remaining_secs: 60,
            }],
            vec![],
            vec![],
        );
        s.degraded_roots = vec!["/big".into()];
        match health_of(&Ok(s)) {
            Health::Degraded(reasons) => {
                assert_eq!(reasons.len(), 2);
                assert!(reasons[0].contains("/v is paused"));
                assert!(reasons[1].contains("/big"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn merge_strips_pinned_marker() {
        let views = merge(
            vec![summary(
                "/v",
                "cli",
                &["/usr/bin/ssh [pinned]", "/usr/bin/git"],
                &["/usr/bin/curl"],
            )],
            vec![],
            vec![],
            vec![],
        );
        assert_eq!(
            views[0].programs,
            vec![
                ProgramRow {
                    program: "/usr/bin/ssh".into(),
                    pinned: true,
                    allow: true,
                    origin: Origin::Fixed
                },
                ProgramRow {
                    program: "/usr/bin/git".into(),
                    pinned: false,
                    allow: true,
                    origin: Origin::Fixed
                },
                ProgramRow {
                    program: "/usr/bin/curl".into(),
                    pinned: false,
                    allow: false,
                    origin: Origin::Fixed
                },
            ]
        );
    }

    #[test]
    fn merge_attaches_dynamic_verdicts_to_their_path() {
        let views = merge(
            vec![
                summary("/a", "cli", &[], &[]),
                summary("/b", "cli", &[], &[]),
            ],
            vec![
                PauseInfo {
                    path: "/b".into(),
                    uid: None,
                    remaining_secs: 30,
                },
                PauseInfo {
                    path: "/b".into(),
                    uid: Some(1000),
                    remaining_secs: 90,
                },
            ],
            vec![TemporaryInfo {
                path: "/a".into(),
                program: "/usr/bin/git".into(),
                uid: None,
                allow: true,
                remaining_secs: 240,
            }],
            vec![
                RememberedInfo {
                    path: "/a".into(),
                    program: "/usr/bin/curl".into(),
                    uid: None,
                    allow: false,
                },
                RememberedInfo {
                    path: "/gone".into(),
                    program: "/usr/bin/cat".into(),
                    uid: None,
                    allow: true,
                },
            ],
        );
        assert_eq!(views.len(), 2);
        assert_eq!(
            views[0].programs,
            vec![
                ProgramRow {
                    program: "/usr/bin/curl".into(),
                    pinned: false,
                    allow: false,
                    origin: Origin::Remembered
                },
                ProgramRow {
                    program: "/usr/bin/git".into(),
                    pinned: false,
                    allow: true,
                    origin: Origin::Temporary(240)
                },
            ]
        );
        assert_eq!(views[0].paused_secs, None);
        assert_eq!(views[1].paused_secs, Some(90));
        assert!(views[1].programs.is_empty());
    }

    #[test]
    fn merge_marks_file_source_readonly() {
        let views = merge(
            vec![
                summary("/a", "cli", &[], &[]),
                summary("/b", "file", &[], &[]),
            ],
            vec![],
            vec![],
            vec![],
        );
        assert!(views[0].editable);
        assert!(!views[1].editable);
    }

    #[test]
    fn argv_for_each_action() {
        let cli = Path::new("/usr/bin/fsnitch");
        let p = || "/v".to_string();
        let prog = || "/usr/bin/git".to_string();
        let cases: Vec<(Action, &str)> = vec![
            (
                Action::Protect {
                    path: p(),
                    mode: "block".into(),
                },
                "protect /v --mode block",
            ),
            (
                Action::Allow {
                    path: p(),
                    program: prog(),
                    pin: false,
                    secs: None,
                },
                "protect /v --program /usr/bin/git",
            ),
            (
                Action::Allow {
                    path: p(),
                    program: prog(),
                    pin: true,
                    secs: None,
                },
                "protect /v --program /usr/bin/git --pin auto",
            ),
            (
                Action::Allow {
                    path: p(),
                    program: prog(),
                    pin: true,
                    secs: Some(900),
                },
                "protect /v --program /usr/bin/git --for 900s",
            ),
            (
                Action::Deny {
                    path: p(),
                    program: prog(),
                },
                "protect /v --deny /usr/bin/git",
            ),
            (
                Action::RemoveFixed {
                    path: p(),
                    program: prog(),
                },
                "unprotect /v --program /usr/bin/git",
            ),
            (
                Action::Forget {
                    path: p(),
                    program: Some(prog()),
                },
                "forget /v --program /usr/bin/git",
            ),
            (
                Action::Forget {
                    path: p(),
                    program: None,
                },
                "forget /v",
            ),
            (Action::Unprotect { path: p() }, "unprotect /v"),
            (
                Action::Pause {
                    path: p(),
                    secs: 3600,
                },
                "pause /v 3600s",
            ),
            (Action::Resume { path: Some(p()) }, "resume /v"),
            (Action::Resume { path: None }, "resume"),
        ];
        for (action, expected) in cases {
            let argv = action.argv(cli, None);
            assert_eq!(&argv[..2], &["pkexec", "/usr/bin/fsnitch"]);
            assert_eq!(argv[2..].join(" "), expected, "{action:?}");
        }
    }

    #[test]
    fn argv_passes_non_default_socket() {
        let argv = Action::Unprotect { path: "/v".into() }
            .argv(Path::new("fsnitch"), Some(Path::new("/dev/s.sock")));
        assert_eq!(
            argv.join(" "),
            "pkexec fsnitch --socket /dev/s.sock unprotect /v"
        );
    }

    #[test]
    fn coarse_ignores_sub_minute_ticks_above_a_minute() {
        let snap = |secs| Snapshot {
            paths: merge(
                vec![summary("/v", "cli", &[], &[])],
                vec![PauseInfo {
                    path: "/v".into(),
                    uid: None,
                    remaining_secs: secs,
                }],
                vec![],
                vec![],
            ),
            ..healthy()
        };
        assert_eq!(snap(600).coarse(), snap(597).coarse());
        assert_ne!(snap(600).coarse(), snap(530).coarse());
        assert_ne!(snap(30).coarse(), snap(27).coarse());
        assert!(snap(30).any_paused());
    }

    #[test]
    fn home_is_shown_as_tilde() {
        let home = Path::new("/home/u");
        assert_eq!(display_path("/home/u/.ssh", home), "~/.ssh");
        assert_eq!(display_path("/home/u", home), "~");
        assert_eq!(display_path("/home/user2/x", home), "/home/user2/x");
    }

    #[test]
    fn remaining_is_humanized() {
        assert_eq!(fmt_remaining(41), "41 s");
        assert_eq!(fmt_remaining(61), "2 min");
        assert_eq!(fmt_remaining(7500), "2h 5m");
    }
}
