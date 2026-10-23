//! Agent-role connection handling and the uid -> agent registry.

use crate::backend::{EnforcementBackend, EventToken};
use crate::engine::make_record;
use crate::procinfo;
use crate::prompt::{PendingKey, PendingPrompts, VerdictCache};
use crate::snooze::SnoozeStore;
use crate::state::State;
use fsnitch_core::eventlog::EventLog;
use fsnitch_core::protocol::{read_msg, write_msg, AgentMsg, DaemonMsg, Verdict};
use std::collections::HashMap;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};

/// uid -> channel to that uid's agent writer thread.
#[derive(Default)]
pub struct AgentRegistry {
    agents: Mutex<HashMap<u32, Sender<DaemonMsg>>>,
}

impl AgentRegistry {
    /// Register an agent for a uid. Returns false if one is already registered.
    pub fn register(&self, uid: u32, tx: Sender<DaemonMsg>) -> bool {
        let mut agents = self.agents.lock().unwrap();
        if agents.contains_key(&uid) {
            return false;
        }
        agents.insert(uid, tx);
        true
    }

    pub fn unregister(&self, uid: u32) {
        self.agents.lock().unwrap().remove(&uid);
    }

    pub fn has_agent(&self, uid: u32) -> bool {
        self.agents.lock().unwrap().contains_key(&uid)
    }

    /// Pick the agent to ask about an access by `uid`: that user's own agent,
    /// else the agent of the protected path's `owner` (e.g. a root backup
    /// reading files under /home/luke asks luke). Returns (agent uid, scope),
    /// where scope is Some(uid) when asking on another user's behalf.
    pub fn route(
        &self,
        uid: u32,
        owner: impl FnOnce() -> Option<u32>,
    ) -> Option<(u32, Option<u32>)> {
        if self.has_agent(uid) {
            return Some((uid, None));
        }
        owner()
            .filter(|&o| o != uid && self.has_agent(o))
            .map(|o| (o, Some(uid)))
    }

    /// Whether an agent is registered for any uid.
    pub fn any(&self) -> bool {
        !self.agents.lock().unwrap().is_empty()
    }

    /// Send a message to the agent for `uid`. Returns false if none registered
    /// or the channel is closed.
    pub fn send(&self, uid: u32, msg: DaemonMsg) -> bool {
        let agents = self.agents.lock().unwrap();
        match agents.get(&uid) {
            Some(tx) => tx.send(msg).is_ok(),
            None => false,
        }
    }
}

/// Everything an agent connection needs to resolve prompts.
pub struct PromptRuntime {
    pub backend: Arc<dyn EnforcementBackend>,
    pub pending: Arc<PendingPrompts<EventToken>>,
    pub cache: Arc<VerdictCache>,
    pub snoozes: Arc<SnoozeStore>,
    pub registry: Arc<AgentRegistry>,
    pub state: Arc<State>,
    pub log: Arc<Mutex<EventLog>>,
    pub agent: PathBuf,
    pub require_agent_session: bool,
}

/// Handle one agent-role connection: verify exe, register, spawn writer, read replies.
pub fn handle_agent_connection(
    stream: UnixStream,
    peer_pid: i32,
    peer_uid: u32,
    rt: Arc<PromptRuntime>,
) {
    // Pin the peer via a pidfd so the pid can't be reused mid-check; fall back
    // to the SO_PEERCRED pid on kernels without SO_PEERPIDFD.
    let pidfd = crate::agent_trust::peer_pidfd(&stream);
    let pid = match pidfd.as_ref().and_then(crate::agent_trust::pid_from_pidfd) {
        Some(pid) => pid,
        None => {
            // Either the kernel lacks SO_PEERPIDFD (pidfd None) or the pidfd's
            // pid couldn't be derived; both degrade to the SO_PEERCRED pid.
            tracing::warn!(
                have_pidfd = pidfd.is_some(),
                "could not pin the peer via SO_PEERPIDFD; using SO_PEERCRED pid (TOCTOU pinning degraded)"
            );
            peer_pid
        }
    };

    // (1) exe must be the configured agent binary.
    match procinfo::exe_of(pid) {
        Some(exe) if exe == rt.agent => {}
        other => {
            tracing::warn!(?other, expected = ?rt.agent, uid = peer_uid, "agent exe mismatch; rejecting");
            let _ = write_msg(
                &mut &stream,
                &DaemonMsg::Event {
                    kind: "error".into(),
                    message: "agent binary not trusted".into(),
                },
            );
            return;
        }
    }

    // (2) if required, the peer's uid must have an active graphical logind
    // session (binds to the user's graphical seat, not the agent process — so a
    // systemd user service works).
    if crate::agent_trust::session_gate(peer_uid, rt.require_agent_session) {
        let _ = write_msg(
            &mut &stream,
            &DaemonMsg::Event {
                kind: "error".into(),
                message: "no active graphical session for your user".into(),
            },
        );
        return;
    }
    // Keep `pidfd` alive until here.
    drop(pidfd);

    // Expect Register as the first message.
    let mut reader = std::io::BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    match read_msg::<_, AgentMsg>(&mut reader) {
        Ok(Some(AgentMsg::Register)) => {}
        _ => {
            tracing::warn!(uid = peer_uid, "agent did not Register first; closing");
            return;
        }
    }

    let (tx, rx) = channel::<DaemonMsg>();
    if !rt.registry.register(peer_uid, tx) {
        tracing::warn!(
            uid = peer_uid,
            "an agent is already registered for this uid; rejecting"
        );
        return;
    }
    tracing::info!(uid = peer_uid, "agent registered");

    // Writer thread: drains the channel to the socket.
    let writer_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => {
            rt.registry.unregister(peer_uid);
            return;
        }
    };
    let writer = std::thread::spawn(move || {
        let mut w = writer_stream;
        while let Ok(msg) = rx.recv() {
            if write_msg(&mut w, &msg).is_err() {
                break;
            }
        }
    });

    // Reader loop: process verdicts until EOF/error.
    loop {
        match read_msg::<_, AgentMsg>(&mut reader) {
            Ok(Some(AgentMsg::Respond { id, verdict })) => {
                resolve_prompt(&rt, id, verdict, peer_uid)
            }
            Ok(Some(AgentMsg::Register)) => {} // ignore duplicate register
            Ok(None) | Err(_) => break,
        }
    }

    // Disconnect cleanup: unregister and fail any still-pending prompts routed
    // here (the design assumes effectively one agent per uid) with on_no_agent.
    rt.registry.unregister(peer_uid);
    drop(reader); // let the writer thread's rx close
    let _ = writer.join();
    let allow_default =
        rt.state.snapshot().config.general.on_no_agent == fsnitch_core::config::FailAction::Allow;
    for p in rt.pending.take_all() {
        finish(&rt, &p.key, p.tokens, allow_default, "no_agent");
    }
    tracing::info!(uid = peer_uid, "agent disconnected");
}

fn resolve_prompt(rt: &Arc<PromptRuntime>, id: u64, verdict: Verdict, peer_uid: u32) {
    let Some(p) = rt.pending.take(id) else {
        tracing::warn!(id, "verdict for unknown/expired prompt id; ignoring");
        return;
    };
    let allow = verdict.allows();
    match verdict {
        Verdict::Pause { secs } => {
            // Scoped to the accessing user's uid (the answering user's own,
            // unless asked on someone else's behalf): other users stay protected.
            rt.snoozes.set(
                &p.key.path,
                Some(p.key.uid.unwrap_or(peer_uid)),
                std::time::Duration::from_secs(secs),
            );
        }
        Verdict::AllowFor { secs } => {
            rt.cache.insert_with_ttl(
                &p.key.path,
                &p.key.program,
                p.key.uid,
                true,
                std::time::Duration::from_secs(secs),
            );
        }
        Verdict::DenyFor { secs } => {
            rt.cache.insert_with_ttl(
                &p.key.path,
                &p.key.program,
                p.key.uid,
                false,
                std::time::Duration::from_secs(secs),
            );
        }
        v if v.is_forever() => {
            if let Err(err) =
                rt.state
                    .set_remembered(&p.key.path, p.key.program.clone(), p.key.uid, allow)
            {
                tracing::error!("failed to persist remembered verdict: {err}");
            }
        }
        _ => {
            rt.cache
                .insert(&p.key.path, &p.key.program, p.key.uid, allow);
        }
    }
    finish(rt, &p.key, p.tokens, allow, "prompt");
}

/// Respond to all tokens for a resolved prompt and write one log record.
fn finish(
    rt: &Arc<PromptRuntime>,
    key: &PendingKey,
    tokens: Vec<EventToken>,
    allow: bool,
    source: &str,
) {
    for token in tokens {
        if let Err(err) = rt.backend.respond(token, allow) {
            tracing::error!("fanotify respond failed: {err}");
        }
    }
    // A prompt covers many (file, pid) events for one (path, program); log the
    // protected path and subject/verdict with a placeholder file.
    let record = make_record(
        &key.path,
        std::path::Path::new("<prompt>"),
        Some(&key.program),
        0,
        None,
        allow,
        source,
    );
    if let Ok(mut log) = rt.log.lock() {
        let _ = log.append(&record);
    }
    tracing::info!(path = %key.path, program = ?key.program, allow, source, "prompt resolved");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;

    #[test]
    fn register_is_one_per_uid() {
        let reg = AgentRegistry::default();
        let (tx1, _rx1) = channel();
        assert!(reg.register(1000, tx1));
        let (tx2, _rx2) = channel();
        // second registration for the same uid is refused
        assert!(!reg.register(1000, tx2));
        // a different uid is fine
        let (tx3, _rx3) = channel();
        assert!(reg.register(1001, tx3));
    }

    #[test]
    fn send_routes_to_registered_uid() {
        let reg = AgentRegistry::default();
        let (tx, rx) = channel();
        reg.register(1000, tx);
        let msg = DaemonMsg::Event {
            kind: "test".into(),
            message: "hi".into(),
        };
        assert!(reg.send(1000, msg.clone()));
        assert_eq!(rx.recv().unwrap(), msg);
        // unknown uid -> false
        assert!(!reg.send(9999, msg));
    }

    #[test]
    fn route_prefers_own_agent_then_path_owner() {
        let reg = AgentRegistry::default();
        let (tx, _rx) = channel();
        reg.register(1000, tx);
        // Own agent: asked directly, verdict unscoped.
        assert_eq!(reg.route(1000, || Some(1000)), Some((1000, None)));
        // root has no agent: the path owner is asked, verdict scoped to root.
        assert_eq!(reg.route(0, || Some(1000)), Some((1000, Some(0))));
        // Owner without an agent, or no owner known: nobody to ask.
        assert_eq!(reg.route(0, || Some(1001)), None);
        assert_eq!(reg.route(0, || None), None);
        // The owner itself without an agent never routes to itself.
        assert_eq!(reg.route(1001, || Some(1001)), None);
    }

    #[test]
    fn unregister_removes_the_agent() {
        let reg = AgentRegistry::default();
        let (tx, _rx) = channel();
        reg.register(1000, tx);
        reg.unregister(1000);
        let (tx2, _rx2) = channel();
        assert!(reg.register(1000, tx2)); // slot free again
    }
}
