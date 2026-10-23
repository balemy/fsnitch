//! Control-plane IPC: JSON-lines over a Unix socket. M2 adds agent messages.

use crate::config::Mode;
use crate::eventlog::EventRecord;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io::{BufRead, Write};
use std::path::PathBuf;

/// How an `--allow` entry is pinned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinArg {
    /// Daemon hashes the program at protect time.
    Auto,
    /// Explicit sha256 (64 hex chars; daemon validates).
    Sha256(String),
}

/// One `--allow` from the CLI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowArg {
    pub program: PathBuf,
    #[serde(default)]
    pub pin: Option<PinArg>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    Status,
    /// List every protected path and its policy.
    List,
    Check {
        path: PathBuf,
        program: Option<PathBuf>,
    },
    Reload,
    /// Create-or-merge a CLI-managed path policy (`path` already
    /// canonical/absolute). `mode: None` leaves an existing path's mode
    /// unchanged (or defaults to `Mode::Ask` when creating).
    Protect {
        path: PathBuf,
        mode: Option<Mode>,
        allow: Vec<AllowArg>,
    },
    /// Remove the CLI-managed path policy for `path`.
    Unprotect {
        path: PathBuf,
    },
    /// Add a fixed allow entry for `program` to `path`'s policy.
    Allow {
        path: PathBuf,
        program: PathBuf,
        pin: Option<PinArg>,
    },
    /// Add a fixed deny entry for `program` to `path`'s policy.
    Deny {
        path: PathBuf,
        program: PathBuf,
    },
    /// Remove a fixed allow/deny entry for `program` from `path`'s policy.
    RemoveEntry {
        path: PathBuf,
        program: PathBuf,
    },
    /// Inject a temporary (timed) allow verdict for `program` on `path`.
    AllowFor {
        path: PathBuf,
        program: PathBuf,
        secs: u64,
    },
    /// List all active dynamic verdicts (pauses, temporary, remembered).
    Verdicts,
    /// Pause a path for `secs` (path = an exact protected path).
    Pause {
        path: PathBuf,
        secs: u64,
    },
    /// Clear the pause on one path (or all when None).
    Resume {
        path: Option<PathBuf>,
    },
    /// Drop temporary + remembered verdicts for a path (optionally one program's).
    Forget {
        path: PathBuf,
        program: Option<PathBuf>,
    },
    /// The last `limit` event-log records (capped by the daemon). On the
    /// read-only status socket a non-root peer only gets its own uid's records.
    Events {
        limit: usize,
    },
}
// Note: there is no `Log` request for following — the CLI reads the log file directly, using
// `Status.log_file` to locate it (as today).

/// One protected path with its rendered policy (for `list`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathSummary {
    pub path: String,
    pub mode: String, // "block"|"ask"|"watch"
    /// "cli" (managed by `fsnitch protect`) or "file" (hand-written drop-in).
    pub source: String,
    pub allow: Vec<String>, // rendered programs, pinned ones get " [pinned]"
    pub deny: Vec<String>,
}

/// An active path pause.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PauseInfo {
    pub path: String,
    /// None = global (root CLI); Some(uid) = only that user's processes.
    pub uid: Option<u32>,
    pub remaining_secs: u64,
}

/// An active "once"/timed verdict from the in-memory cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporaryInfo {
    pub path: String,
    pub program: PathBuf,
    /// None = every user; Some(uid) = only that user's processes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    pub allow: bool,
    pub remaining_secs: u64,
}

/// A persisted "forever" verdict from the remembered store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RememberedInfo {
    pub path: String,
    pub program: PathBuf,
    /// None = every user; Some(uid) = only that user's processes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    pub allow: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Status {
        version: String,
        paths: usize,
        roots: Vec<PathBuf>,
        log_file: PathBuf,
        config_dir: PathBuf,
        /// Roots whose inode index exceeded `max_tracked_inodes` — move
        /// protection is off for them (path protection unchanged).
        #[serde(default)]
        degraded_roots: Vec<PathBuf>,
        /// Whether a prompt agent is connected — for the requesting uid on the
        /// status socket, for any uid on the control socket.
        #[serde(default)]
        agent_connected: bool,
    },
    Paths {
        paths: Vec<PathSummary>,
    },
    Check {
        protected: bool,
        path: Option<String>,
        outcome: Option<String>,
    },
    Protected {
        path: String,
        /// Human-readable caveat, e.g. another path also covers this one
        /// (the daemon says which policy actually wins longest-prefix).
        note: Option<String>,
    },
    Verdicts {
        pauses: Vec<PauseInfo>,
        temporary: Vec<TemporaryInfo>,
        remembered: Vec<RememberedInfo>,
    },
    /// How many verdicts a `Forget` removed.
    Forgotten {
        temporary: usize,
        remembered: usize,
    },
    Events {
        events: Vec<EventRecord>,
    },
    Ok,
    Error {
        message: String,
    },
}

/// A user's decision on a prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    AllowOnce,
    AllowForever,
    DenyOnce,
    DenyForever,
    /// Program-scoped timed allow: a once-verdict with a chosen TTL.
    AllowFor {
        secs: u64,
    },
    /// Program-scoped timed deny: a once-deny with a chosen TTL.
    DenyFor {
        secs: u64,
    },
    /// Path-wide pause: every access to the path is allowed for the duration
    /// (uid-scoped when set from the dialog, global from the root CLI).
    Pause {
        secs: u64,
    },
}

impl Verdict {
    /// Whether this verdict allows the access.
    pub fn allows(self) -> bool {
        matches!(
            self,
            Verdict::AllowOnce
                | Verdict::AllowForever
                | Verdict::AllowFor { .. }
                | Verdict::Pause { .. }
        )
    }
    /// Whether this verdict should be persisted to the remembered store.
    pub fn is_forever(self) -> bool {
        matches!(self, Verdict::AllowForever | Verdict::DenyForever)
    }
}

/// A pending decision the daemon needs a human to make.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptRequest {
    pub id: u64,
    /// The protected path whose policy triggered the prompt.
    pub path: String,
    /// The specific file the program tried to open (shown in the dialog).
    pub file: PathBuf,
    /// The program attempting the access.
    pub program: PathBuf,
    pub pid: i32,
    pub uid: u32,
    /// Seconds until the daemon auto-answers this prompt (from
    /// general.timeout). The agent uses it for the countdown and self-dismiss.
    pub timeout_secs: u64,
}

/// Agent -> daemon (on the agent connection).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentMsg {
    /// Register this connection as the prompt handler for the peer uid.
    Register,
    /// Answer a previously received PromptRequest.
    Respond { id: u64, verdict: Verdict },
}

/// Daemon -> agent (on the agent connection).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonMsg {
    Prompt(PromptRequest),
    /// Fire-and-forget FYI: the graphical agent may display it; a headless
    /// agent just records it.
    Event {
        kind: String,
        message: String,
    },
}

pub fn write_msg<W: Write, T: Serialize>(w: &mut W, msg: &T) -> std::io::Result<()> {
    serde_json::to_writer(&mut *w, msg)?;
    w.write_all(b"\n")?;
    w.flush()
}

/// Returns Ok(None) on clean EOF.
pub fn read_msg<R: BufRead, T: DeserializeOwned>(r: &mut R) -> std::io::Result<Option<T>> {
    let mut line = String::new();
    if r.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    let msg = serde_json::from_str(&line)?;
    Ok(Some(msg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    #[test]
    fn request_round_trip() {
        let reqs = vec![
            Request::Status,
            Request::List,
            Request::Check {
                path: "/x/a.kdbx".into(),
                program: Some("/usr/bin/cat".into()),
            },
            Request::Reload,
        ];
        let mut buf = Vec::new();
        for r in &reqs {
            write_msg(&mut buf, r).unwrap();
        }
        let mut reader = BufReader::new(buf.as_slice());
        for expected in &reqs {
            let got: Request = read_msg(&mut reader).unwrap().unwrap();
            assert_eq!(&got, expected);
        }
        assert!(read_msg::<_, Request>(&mut reader).unwrap().is_none()); // EOF
    }

    #[test]
    fn response_round_trip() {
        let resp = Response::Status {
            version: "0.1.0".into(),
            paths: 3,
            roots: vec!["/home/luke/vaults".into()],
            log_file: "/var/log/fsnitch/events.jsonl".into(),
            config_dir: "/etc/fsnitch".into(),
            degraded_roots: vec!["/big".into()],
            agent_connected: true,
        };
        let mut buf = Vec::new();
        write_msg(&mut buf, &resp).unwrap();
        let got: Response = read_msg(&mut BufReader::new(buf.as_slice()))
            .unwrap()
            .unwrap();
        assert_eq!(got, resp);
    }

    #[test]
    fn wire_format_is_json_lines() {
        let mut buf = Vec::new();
        write_msg(&mut buf, &Request::Status).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert_eq!(text, "{\"type\":\"status\"}\n");
    }

    #[test]
    fn verdict_serialises_snake_case() {
        assert_eq!(
            serde_json::to_string(&Verdict::AllowForever).unwrap(),
            "\"allow_forever\""
        );
        assert_eq!(
            serde_json::from_str::<Verdict>("\"deny_once\"").unwrap(),
            Verdict::DenyOnce
        );
    }

    #[test]
    fn verdict_allow_and_persist_flags() {
        assert!(Verdict::AllowOnce.allows());
        assert!(!Verdict::DenyOnce.allows());
        assert!(Verdict::AllowForever.is_forever());
        assert!(!Verdict::AllowOnce.is_forever());
        assert!(Verdict::AllowFor { secs: 300 }.allows());
        assert!(Verdict::Pause { secs: 300 }.allows());
        assert!(!Verdict::AllowFor { secs: 300 }.is_forever());
        assert!(!Verdict::Pause { secs: 300 }.is_forever());
    }

    #[test]
    fn timed_verdicts_round_trip() {
        for v in [
            Verdict::AllowFor { secs: 900 },
            Verdict::DenyFor { secs: 900 },
            Verdict::Pause { secs: 300 },
        ] {
            let json = serde_json::to_string(&v).unwrap();
            assert_eq!(serde_json::from_str::<Verdict>(&json).unwrap(), v);
        }
    }

    #[test]
    fn verdict_management_messages_round_trip() {
        let reqs = vec![
            Request::Verdicts,
            Request::Pause {
                path: "/home/u/vaults".into(),
                secs: 900,
            },
            Request::Resume { path: None },
            Request::Resume {
                path: Some("/home/u/vaults".into()),
            },
            Request::Forget {
                path: "/home/u/vaults".into(),
                program: Some("/usr/bin/cat".into()),
            },
            Request::Events { limit: 5 },
        ];
        let mut buf = Vec::new();
        for r in &reqs {
            write_msg(&mut buf, r).unwrap();
        }
        let mut reader = BufReader::new(buf.as_slice());
        for expected in &reqs {
            let got: Request = read_msg(&mut reader).unwrap().unwrap();
            assert_eq!(&got, expected);
        }

        let resps = vec![
            Response::Verdicts {
                pauses: vec![PauseInfo {
                    path: "/home/u/vaults".into(),
                    uid: Some(1000),
                    remaining_secs: 120,
                }],
                temporary: vec![TemporaryInfo {
                    path: "/home/u/vaults".into(),
                    program: "/usr/bin/cat".into(),
                    uid: None,
                    allow: true,
                    remaining_secs: 41,
                }],
                remembered: vec![RememberedInfo {
                    path: "/home/u/vaults".into(),
                    program: "/usr/bin/keepassxc".into(),
                    uid: None,
                    allow: true,
                }],
            },
            Response::Forgotten {
                temporary: 1,
                remembered: 2,
            },
            Response::Events {
                events: vec![EventRecord {
                    ts: "2026-10-14T12:00:00Z".into(),
                    path: "/home/u/vaults".into(),
                    file: "/home/u/vaults/a.kdbx".into(),
                    program: Some("/usr/bin/cat".into()),
                    pid: 7,
                    uid: 1000,
                    decision: "deny".into(),
                    source: "policy".into(),
                }],
            },
        ];
        let mut buf = Vec::new();
        for r in &resps {
            write_msg(&mut buf, r).unwrap();
        }
        let mut reader = BufReader::new(buf.as_slice());
        for expected in &resps {
            let got: Response = read_msg(&mut reader).unwrap().unwrap();
            assert_eq!(&got, expected);
        }
    }

    #[test]
    fn protect_request_round_trip() {
        let reqs = vec![
            Request::Protect {
                path: "/home/u/vaults".into(),
                mode: Some(Mode::Ask),
                allow: vec![
                    AllowArg {
                        program: "/usr/bin/keepassxc".into(),
                        pin: None,
                    },
                    AllowArg {
                        program: "/usr/bin/borg".into(),
                        pin: Some(PinArg::Auto),
                    },
                    AllowArg {
                        program: "/usr/bin/restic".into(),
                        pin: Some(PinArg::Sha256("ab".repeat(32))),
                    },
                ],
            },
            // `mode: None` — merge into an existing path without touching its mode.
            Request::Protect {
                path: "/home/u/vaults".into(),
                mode: None,
                allow: vec![],
            },
            Request::Unprotect {
                path: "/home/u/vaults".into(),
            },
        ];
        let mut buf = Vec::new();
        for r in &reqs {
            write_msg(&mut buf, r).unwrap();
        }
        let mut reader = BufReader::new(buf.as_slice());
        for expected in &reqs {
            let got: Request = read_msg(&mut reader).unwrap().unwrap();
            assert_eq!(&got, expected);
        }
    }

    #[test]
    fn allow_deny_request_round_trip() {
        let reqs = vec![
            Request::Allow {
                path: "/home/u/vaults".into(),
                program: "/usr/bin/keepassxc".into(),
                pin: None,
            },
            Request::Allow {
                path: "/home/u/vaults".into(),
                program: "/usr/bin/borg".into(),
                pin: Some(PinArg::Auto),
            },
            Request::Deny {
                path: "/home/u/vaults".into(),
                program: "/usr/bin/curl".into(),
            },
        ];
        let mut buf = Vec::new();
        for r in &reqs {
            write_msg(&mut buf, r).unwrap();
        }
        let mut reader = BufReader::new(buf.as_slice());
        for expected in &reqs {
            let got: Request = read_msg(&mut reader).unwrap().unwrap();
            assert_eq!(&got, expected);
        }
    }

    #[test]
    fn protected_response_round_trip() {
        let resp = Response::Protected {
            path: "/home/u/vaults".into(),
            note: Some("also covered by \"/home/u\"".into()),
        };
        let mut buf = Vec::new();
        write_msg(&mut buf, &resp).unwrap();
        let got: Response = read_msg(&mut BufReader::new(buf.as_slice()))
            .unwrap()
            .unwrap();
        assert_eq!(got, resp);
    }

    #[test]
    fn agent_messages_round_trip() {
        let outbound = vec![
            AgentMsg::Register,
            AgentMsg::Respond {
                id: 7,
                verdict: Verdict::AllowForever,
            },
        ];
        let mut buf = Vec::new();
        for m in &outbound {
            write_msg(&mut buf, m).unwrap();
        }
        let mut r = BufReader::new(buf.as_slice());
        for expected in &outbound {
            let got: AgentMsg = read_msg(&mut r).unwrap().unwrap();
            assert_eq!(&got, expected);
        }

        let inbound = DaemonMsg::Prompt(PromptRequest {
            id: 7,
            path: "/vaults".into(),
            file: "/vaults/secret.kdbx".into(),
            program: "/tmp/stealer".into(),
            pid: 42,
            uid: 1000,
            timeout_secs: 30,
        });
        let mut buf = Vec::new();
        write_msg(&mut buf, &inbound).unwrap();
        let got: DaemonMsg = read_msg(&mut BufReader::new(buf.as_slice()))
            .unwrap()
            .unwrap();
        assert_eq!(got, inbound);
        if let DaemonMsg::Prompt(req) = got {
            assert_eq!(req.timeout_secs, 30);
        } else {
            panic!("expected Prompt");
        }
    }
}
