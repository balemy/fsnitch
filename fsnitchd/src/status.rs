//! Read-only status socket for unprivileged clients (the GUI tray).
//!
//! The control socket gives uid 0 the control role and treats every other peer
//! as a prompt agent, so a user-level status reader can't use it. This socket
//! answers only read-only requests, for any uid; data that is per-user (event
//! log, pauses) is filtered to the peer's uid unless the peer is root.

use crate::agent::{AgentRegistry, PromptRuntime};
use crate::backend::EnforcementBackend;
use crate::control::{events_response, handle_request, patch_agent_connected, peer_cred};
use crate::prompt::VerdictCache;
use crate::snooze::SnoozeStore;
use crate::state::State;
use fsnitch_core::protocol::{read_msg, write_msg, Request, Response};
use std::io::BufReader;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;

/// File name of the status socket, next to the control socket.
pub const STATUS_SOCKET_NAME: &str = "status.sock";

pub fn serve(listener: UnixListener, state: Arc<State>, rt: Arc<PromptRuntime>) {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let Some((uid, _pid)) = peer_cred(&stream) else {
                    let _ = write_msg(
                        &mut &stream,
                        &Response::Error {
                            message: "cannot read peer credentials".into(),
                        },
                    );
                    continue;
                };
                let state = state.clone();
                let rt = rt.clone();
                std::thread::spawn(move || handle_status_connection(stream, uid, &state, &rt));
            }
            Err(err) => tracing::warn!("status accept failed: {err}"),
        }
    }
}

fn handle_status_connection(stream: UnixStream, uid: u32, state: &State, rt: &PromptRuntime) {
    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let mut reader = BufReader::new(stream);
    loop {
        let req: Request = match read_msg(&mut reader) {
            Ok(Some(req)) => req,
            Ok(None) => return,
            Err(err) => {
                let _ = write_msg(
                    &mut writer,
                    &Response::Error {
                        message: err.to_string(),
                    },
                );
                return;
            }
        };
        let resp = handle_status_request(
            req,
            uid,
            state,
            &rt.cache,
            &rt.backend,
            &rt.snoozes,
            &rt.registry,
        );
        if write_msg(&mut writer, &resp).is_err() {
            return;
        }
    }
}

fn path_owner(path: &str) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| m.uid())
}

/// Answer one request from a peer with `uid`; everything that could change
/// state is refused.
pub(crate) fn handle_status_request(
    req: Request,
    uid: u32,
    state: &State,
    cache: &VerdictCache,
    backend: &Arc<dyn EnforcementBackend>,
    snoozes: &Arc<SnoozeStore>,
    registry: &AgentRegistry,
) -> Response {
    let root = uid == 0;
    match req {
        Request::Status => {
            let mut resp = handle_request(Request::Status, state, cache, backend, snoozes);
            let connected = if root {
                registry.any()
            } else {
                registry.has_agent(uid)
            };
            patch_agent_connected(&mut resp, connected);
            resp
        }
        Request::List => handle_request(Request::List, state, cache, backend, snoozes),
        Request::Verdicts => {
            let mut resp = handle_request(Request::Verdicts, state, cache, backend, snoozes);
            if let Response::Verdicts { pauses, .. } = &mut resp {
                if !root {
                    // Also show pauses set on another user's behalf (e.g. for
                    // root) on paths this user owns: they answered that prompt.
                    pauses.retain(|p| {
                        p.uid.is_none() || p.uid == Some(uid) || path_owner(&p.path) == Some(uid)
                    });
                }
            }
            resp
        }
        Request::Events { limit } => events_response(
            &state.snapshot().config.general.log_file,
            limit,
            (!root).then_some(uid),
        ),
        _ => Response::Error {
            message: "read-only socket: use the fsnitch CLI as root to change policy".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{AccessEvent, EventToken};
    use fsnitch_core::protocol::AllowArg;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    struct NoBackend;
    impl EnforcementBackend for NoBackend {
        fn next_events(&self) -> anyhow::Result<Vec<AccessEvent>> {
            anyhow::bail!("unused in status tests")
        }
        fn respond(&self, _token: EventToken, _allow: bool) -> anyhow::Result<()> {
            Ok(())
        }
        fn ensure_watched(&self, _root: &Path) -> anyhow::Result<()> {
            Ok(())
        }
    }

    struct Fixture {
        dir: tempfile::TempDir,
        state: State,
        cache: VerdictCache,
        backend: Arc<dyn EnforcementBackend>,
        snoozes: Arc<SnoozeStore>,
        registry: AgentRegistry,
    }

    impl Fixture {
        fn new() -> Fixture {
            let dir = tempfile::tempdir().unwrap();
            let log = dir.path().join("events.jsonl");
            std::fs::write(
                dir.path().join("config.toml"),
                format!(
                    "[general]\nlog_file = {log:?}\n\n[[path]]\npath = \"/vaults\"\nmode = \"ask\"\n"
                ),
            )
            .unwrap();
            let state = State::load(dir.path()).unwrap();
            Fixture {
                dir,
                state,
                cache: VerdictCache::new(Duration::from_secs(60)),
                backend: Arc::new(NoBackend),
                snoozes: Arc::new(SnoozeStore::default()),
                registry: AgentRegistry::default(),
            }
        }

        fn ask(&self, req: Request, uid: u32) -> Response {
            handle_status_request(
                req,
                uid,
                &self.state,
                &self.cache,
                &self.backend,
                &self.snoozes,
                &self.registry,
            )
        }

        fn write_events(&self, uids: &[u32]) {
            let mut log =
                fsnitch_core::eventlog::EventLog::open(&self.dir.path().join("events.jsonl"))
                    .unwrap();
            for (i, uid) in uids.iter().enumerate() {
                log.append(&crate::engine::make_record(
                    "/vaults",
                    Path::new("/vaults/a"),
                    Some(Path::new("/usr/bin/cat")),
                    i as i32,
                    Some(*uid),
                    false,
                    "policy",
                ))
                .unwrap();
            }
        }

        fn event_uids(&self, uid: u32) -> Vec<u32> {
            match self.ask(Request::Events { limit: 100 }, uid) {
                Response::Events { events } => events.iter().map(|e| e.uid).collect(),
                other => panic!("unexpected: {other:?}"),
            }
        }
    }

    #[test]
    fn rejects_every_mutating_request() {
        let f = Fixture::new();
        let p = || PathBuf::from("/vaults");
        let prog = || PathBuf::from("/usr/bin/cat");
        let reqs = vec![
            Request::Protect {
                path: "/data".into(),
                mode: None,
                allow: vec![AllowArg {
                    program: prog(),
                    pin: None,
                }],
            },
            Request::Unprotect { path: p() },
            Request::Allow {
                path: p(),
                program: prog(),
                pin: None,
            },
            Request::Deny {
                path: p(),
                program: prog(),
            },
            Request::RemoveEntry {
                path: p(),
                program: prog(),
            },
            Request::AllowFor {
                path: p(),
                program: prog(),
                secs: 60,
            },
            Request::Pause {
                path: p(),
                secs: 60,
            },
            Request::Resume { path: None },
            Request::Forget {
                path: p(),
                program: None,
            },
            Request::Reload,
            Request::Check {
                path: p(),
                program: None,
            },
        ];
        for req in reqs {
            match f.ask(req.clone(), 1000) {
                Response::Error { message } => {
                    assert!(message.contains("read-only"), "{req:?}: {message}")
                }
                other => panic!("{req:?} was not refused: {other:?}"),
            }
        }
        assert_eq!(f.state.snapshot().config.paths.len(), 1);
        assert!(f.snoozes.list().is_empty());
        assert!(f.cache.list().is_empty());
    }

    #[test]
    fn events_are_filtered_to_peer_uid() {
        let f = Fixture::new();
        f.write_events(&[1000, 1001, 0, 1000]);
        assert_eq!(f.event_uids(1000), vec![1000, 1000]);
        assert_eq!(f.event_uids(1001), vec![1001]);
    }

    #[test]
    fn root_peer_sees_all_events() {
        let f = Fixture::new();
        f.write_events(&[1000, 1001, 0]);
        assert_eq!(f.event_uids(0), vec![1000, 1001, 0]);
    }

    #[test]
    fn agent_connected_reflects_registry_for_peer_uid() {
        let f = Fixture::new();
        let connected = |uid| match f.ask(Request::Status, uid) {
            Response::Status {
                agent_connected, ..
            } => agent_connected,
            other => panic!("unexpected: {other:?}"),
        };
        assert!(!connected(1000));
        let (tx, _rx) = std::sync::mpsc::channel();
        assert!(f.registry.register(1000, tx));
        assert!(connected(1000));
        assert!(!connected(1001));
        assert!(connected(0));
    }

    #[test]
    fn pauses_filtered_to_peer() {
        let f = Fixture::new();
        let d = Duration::from_secs(600);
        f.snoozes.set("/vaults", None, d);
        f.snoozes.set("/vaults", Some(1000), d);
        f.snoozes.set("/vaults", Some(1001), d);
        let pauses = |uid| match f.ask(Request::Verdicts, uid) {
            Response::Verdicts { pauses, .. } => pauses.len(),
            other => panic!("unexpected: {other:?}"),
        };
        assert_eq!(pauses(1000), 2);
        assert_eq!(pauses(0), 3);
    }

    #[test]
    fn owner_sees_pauses_set_on_others_behalf() {
        use std::os::unix::fs::MetadataExt;
        let f = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let owned = dir.path().to_str().unwrap();
        let me = std::fs::metadata(owned).unwrap().uid();
        let other = me.wrapping_add(1);
        f.snoozes.set(owned, Some(0), Duration::from_secs(600));
        let pauses = |uid| match f.ask(Request::Verdicts, uid) {
            Response::Verdicts { pauses, .. } => pauses.len(),
            other => panic!("unexpected: {other:?}"),
        };
        assert_eq!(pauses(me), 1);
        assert_eq!(pauses(other), 0);
    }

    #[test]
    fn list_is_readable() {
        let f = Fixture::new();
        assert!(
            matches!(f.ask(Request::List, 1000), Response::Paths { paths } if paths.len() == 1)
        );
    }
}
