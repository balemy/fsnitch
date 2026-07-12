mod agent;
mod agent_trust;
mod backend;
mod control;
mod engine;
mod fanotify;
mod hashing;
mod procinfo;
mod prompt;
mod snooze;
mod state;

use agent::{AgentRegistry, PromptRuntime};
use anyhow::Context;
use backend::{EnforcementBackend, EventToken};
use fsnitch_core::config::FailAction;
use fsnitch_core::eventlog::{EventLog, EventRecord};
use fsnitch_core::protocol::{DaemonMsg, PromptRequest};
use prompt::{PendingKey, PendingPrompts, VerdictCache};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const CACHE_TTL: Duration = Duration::from_secs(60);
const REAPER_INTERVAL: Duration = Duration::from_millis(250);

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();

    let config_dir = std::env::args()
        .skip_while(|a| a != "--config")
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/fsnitch"));

    let socket_path = std::env::args()
        .skip_while(|a| a != "--socket")
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(control::SOCKET_PATH));
    let socket_dir = socket_path
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/"));

    if !nix::unistd::geteuid().is_root() {
        anyhow::bail!("fsnitchd must run as root (fanotify permission events need CAP_SYS_ADMIN)");
    }

    let state = Arc::new(
        state::State::load(&config_dir)
            .with_context(|| format!("loading config from {}", config_dir.display()))?,
    );
    let snapshot = state.snapshot();
    tracing::info!(
        paths = snapshot.config.paths.len(),
        roots = ?snapshot.rules.roots(),
        "fsnitchd starting"
    );

    #[cfg(not(feature = "session-hardening"))]
    if snapshot.config.general.require_agent_session {
        tracing::warn!(
            "require_agent_session = true but this build lacks the `session-hardening` \
             feature — the active-graphical-session check has NO effect. Rebuild with \
             `--features session-hardening`, or set require_agent_session = false to silence."
        );
    }

    // The event log is shared: the enforcement loop, the agent reply handler,
    // and the reaper all append. A Mutex serializes writes so records never
    // interleave.
    let log = Arc::new(Mutex::new(
        EventLog::open(&snapshot.config.general.log_file).context("opening event log")?,
    ));

    // Control socket. World-connectable (dir 0755, socket 0666); SO_PEERCRED
    // gates capabilities: uid 0 = control, else = agent. Path defaults to
    // /run/fsnitch/fsnitchd.sock; --socket overrides it (the dev-run keeps
    // everything repo-local).
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .mode(0o755)
            .recursive(true)
            .create(&socket_dir)?;
        // DirBuilder does not chmod a pre-existing directory (e.g. one systemd
        // created, or a leftover from an older 0700 build), so set it explicitly
        // — the non-root agent must be able to traverse here to reach the socket.
        std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o755))?;
    }
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("binding {}", socket_path.display()))?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o666))?;
    }

    // Enforcement backend, shared so prompts can be answered off the loop thread.
    let backend: Arc<dyn EnforcementBackend> = Arc::new(
        fanotify::FanotifyBackend::new(snapshot.rules.roots())
            .context("initializing fanotify backend")?,
    );

    // Prompt subsystem.
    let cache = Arc::new(VerdictCache::new(CACHE_TTL));
    let snoozes = Arc::new(snooze::SnoozeStore::default());
    let pending: Arc<PendingPrompts<EventToken>> =
        Arc::new(PendingPrompts::new(snapshot.config.general.max_pending));
    let registry = Arc::new(AgentRegistry::default());
    let rt = Arc::new(PromptRuntime {
        backend: backend.clone(),
        pending: pending.clone(),
        cache: cache.clone(),
        snoozes: snoozes.clone(),
        registry: registry.clone(),
        state: state.clone(),
        log: log.clone(),
        agent: snapshot.config.general.agent.clone(),
        require_agent_session: snapshot.config.general.require_agent_session,
    });

    // Control + agent server.
    {
        let state = state.clone();
        let rt = rt.clone();
        std::thread::spawn(move || control::serve(listener, state, rt));
    }

    // Timeout reaper: answers pending prompts that nobody decided in time.
    {
        let pending = pending.clone();
        let backend = backend.clone();
        let state = state.clone();
        let log = log.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(REAPER_INTERVAL);
            let allow = state.snapshot().config.general.on_no_answer == FailAction::Allow;
            for p in pending.take_expired(Instant::now()) {
                for token in p.tokens {
                    if let Err(err) = backend.respond(token, allow) {
                        tracing::error!("fanotify respond (timeout) failed: {err}");
                    }
                }
                let rec = engine::make_record(
                    &p.key.path,
                    std::path::Path::new("<prompt>"),
                    Some(&p.key.program),
                    0,
                    None,
                    allow,
                    "timeout",
                );
                if let Ok(mut log) = log.lock() {
                    let _ = log.append(&rec);
                }
                tracing::info!(path = %p.key.path, program = ?p.key.program, allow, "prompt timed out");
            }
        });
    }

    tracing::info!("enforcement active");
    let own_pid = std::process::id() as i32;
    loop {
        let events = backend.next_events()?;
        let snapshot = state.snapshot();
        let timeout = Duration::from_secs(snapshot.config.general.timeout);
        for event in events {
            // Every event holds a kernel open() blocked until answered. It MUST
            // be responded to exactly once — here for immediate decisions, or
            // later (agent reply / reaper) for parked prompts. No branch may
            // drop an event without responding or parking it.

            // The daemon must never gate its own file I/O — e.g. reload-time pin
            // hashing (on the control thread) reads binaries on the marked
            // filesystem. Without this, such a read would be subject to the
            // daemon's own policies: an `ask` path would stall the read for up to
            // general.timeout, and a `block` path could deny it outright
            // (so the pin silently fails to build). (Event-time reads would
            // deadlock outright, but load-time hashing avoids those.) The pid is kernel-
            // supplied, so another process can't forge it.
            if event.pid == own_pid {
                tracing::debug!(path = ?event.path, "allowing daemon's own file access");
                respond(&backend, event.token, true);
                continue;
            }

            let Some(path) = event.path.as_deref() else {
                // Unresolved target path: allow, but audit the fail-open.
                let rec = engine::make_record(
                    "",
                    std::path::Path::new("<unresolved>"),
                    event.exe.as_deref(),
                    event.pid,
                    event.uid,
                    true,
                    "unresolved_path",
                );
                log_record(&log, &rec);
                respond(&backend, event.token, true);
                continue;
            };

            match engine::decide_event(
                &snapshot.rules,
                &snapshot.config.general,
                &snapshot.remembered,
                &snoozes,
                &snapshot.pin_hashes,
                path,
                event.exe.as_deref(),
                event.pid,
                event.uid,
            ) {
                engine::Decision::Resolved(dec) => {
                    if let Some(record) = &dec.record {
                        log_record(&log, record);
                        tracing::info!(
                            path = %record.path,
                            program = ?record.program,
                            decision = %record.decision,
                            source = %record.source,
                            "protected access"
                        );
                    }
                    respond(&backend, event.token, dec.allow);
                }
                engine::Decision::Prompt(ctx) => {
                    // Once-cache first (time-based; checked here, not in decide_event).
                    if let Some(allow) = cache.get(&ctx.path, &ctx.program) {
                        let rec = engine::make_record(
                            &ctx.path,
                            path,
                            Some(&ctx.program),
                            ctx.pid,
                            Some(ctx.uid),
                            allow,
                            "cache",
                        );
                        log_record(&log, &rec);
                        respond(&backend, event.token, allow);
                        continue;
                    }
                    // No agent for this uid -> on_no_agent immediately.
                    if !registry.has_agent(ctx.uid) {
                        let allow = snapshot.config.general.on_no_agent == FailAction::Allow;
                        let rec = engine::make_record(
                            &ctx.path,
                            path,
                            Some(&ctx.program),
                            ctx.pid,
                            Some(ctx.uid),
                            allow,
                            "no_agent",
                        );
                        log_record(&log, &rec);
                        respond(&backend, event.token, allow);
                        continue;
                    }
                    // Park and prompt.
                    let key = PendingKey {
                        program: ctx.program.clone(),
                        path: ctx.path.clone(),
                    };
                    let deadline = Instant::now() + timeout;
                    match pending.park(key, event.token, deadline) {
                        prompt::Parked::New(id) => {
                            let req = PromptRequest {
                                id,
                                path: ctx.path.clone(),
                                file: path.to_path_buf(),
                                program: ctx.program.clone(),
                                pid: ctx.pid,
                                uid: ctx.uid,
                                timeout_secs: snapshot.config.general.timeout,
                            };
                            if !registry.send(ctx.uid, DaemonMsg::Prompt(req)) {
                                // Agent vanished between the has_agent check and
                                // send: reclaim the token and apply on_no_agent.
                                if let Some(p) = pending.take(id) {
                                    let allow =
                                        snapshot.config.general.on_no_agent == FailAction::Allow;
                                    for token in p.tokens {
                                        respond(&backend, token, allow);
                                    }
                                }
                            }
                        }
                        prompt::Parked::Deduped => { /* token joined an open prompt */ }
                        prompt::Parked::Rejected(token) => {
                            // Pending map at capacity: apply on_no_answer default,
                            // answering the handed-back token so it never hangs.
                            let allow = snapshot.config.general.on_no_answer == FailAction::Allow;
                            let rec = engine::make_record(
                                &ctx.path,
                                path,
                                Some(&ctx.program),
                                ctx.pid,
                                Some(ctx.uid),
                                allow,
                                "overload",
                            );
                            log_record(&log, &rec);
                            respond(&backend, token, allow);
                        }
                    }
                }
            }
        }
    }
}

fn log_record(log: &Arc<Mutex<EventLog>>, record: &EventRecord) {
    if let Ok(mut log) = log.lock() {
        if let Err(err) = log.append(record) {
            tracing::error!("event log write failed: {err}");
        }
    }
}

fn respond(backend: &Arc<dyn EnforcementBackend>, token: EventToken, allow: bool) {
    if let Err(err) = backend.respond(token, allow) {
        tracing::error!("fanotify respond failed: {err}");
    }
}
