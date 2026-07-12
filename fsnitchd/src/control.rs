//! Control socket: JSON-lines request/response for the CLI (root-only control plane).

use crate::backend::EnforcementBackend;
use crate::prompt::VerdictCache;
use crate::snooze::SnoozeStore;
use crate::state::{ManagedUpdate, Snapshot, State};
use fsnitch_core::config::{AllowEntry, Config, Mode, PathPolicy};
use fsnitch_core::decision::{evaluate, Outcome};
use fsnitch_core::protocol::{
    read_msg, write_msg, AllowArg, PathSummary, PauseInfo, PinArg, RememberedInfo, Request,
    Response, TemporaryInfo,
};
use std::io::BufReader;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Default control-socket path; `fsnitchd --socket` overrides it (the socket dir
/// is derived from this path in `main`).
pub const SOCKET_PATH: &str = "/run/fsnitch/fsnitchd.sock";

pub fn serve(listener: UnixListener, state: Arc<State>, rt: Arc<crate::agent::PromptRuntime>) {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let Some((uid, pid)) = peer_cred(&stream) else {
                    let _ = write_msg(
                        &mut &stream,
                        &Response::Error {
                            message: "cannot read peer credentials".into(),
                        },
                    );
                    continue;
                };
                if uid == 0 {
                    // Control role: policy mutation, reload, status, log.
                    let state = state.clone();
                    let cache = rt.cache.clone();
                    let backend = rt.backend.clone();
                    let snoozes = rt.snoozes.clone();
                    std::thread::spawn(move || {
                        handle_connection(stream, &state, &cache, &backend, &snoozes)
                    });
                } else {
                    // Agent role: prompt handler for this uid.
                    let rt = rt.clone();
                    std::thread::spawn(move || {
                        crate::agent::handle_agent_connection(stream, pid, uid, rt)
                    });
                }
            }
            Err(err) => tracing::warn!("control accept failed: {err}"),
        }
    }
}

/// (uid, pid) of the connected peer via SO_PEERCRED.
fn peer_cred(stream: &UnixStream) -> Option<(u32, i32)> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    let creds = getsockopt(stream, PeerCredentials).ok()?;
    Some((creds.uid(), creds.pid()))
}

fn handle_connection(
    stream: UnixStream,
    state: &State,
    cache: &VerdictCache,
    backend: &Arc<dyn EnforcementBackend>,
    snoozes: &Arc<SnoozeStore>,
) {
    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let mut reader = BufReader::new(stream);
    loop {
        let req: Request = match read_msg(&mut reader) {
            Ok(Some(req)) => req,
            Ok(None) => return, // EOF
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
        let resp = handle_request(req, state, cache, backend, snoozes);
        if write_msg(&mut writer, &resp).is_err() {
            return;
        }
    }
}

fn handle_request(
    req: Request,
    state: &State,
    cache: &VerdictCache,
    backend: &Arc<dyn EnforcementBackend>,
    snoozes: &Arc<SnoozeStore>,
) -> Response {
    let snapshot = state.snapshot();
    match req {
        Request::Status => Response::Status {
            version: env!("CARGO_PKG_VERSION").to_string(),
            paths: snapshot.config.paths.len(),
            roots: snapshot.rules.roots().to_vec(),
            log_file: snapshot.config.general.log_file.clone(),
            config_dir: state.config_dir().to_path_buf(),
        },
        Request::List => Response::Paths {
            paths: snapshot
                .config
                .paths
                .iter()
                .map(|p| PathSummary {
                    path: p.path.clone(),
                    mode: format!("{:?}", p.mode).to_lowercase(),
                    source: if snapshot.managed_paths.contains(&p.path) {
                        "cli".to_string()
                    } else {
                        "file".to_string()
                    },
                    allow: p.allow.iter().map(render_entry).collect(),
                    deny: p.deny.iter().map(render_entry).collect(),
                })
                .collect(),
        },
        Request::Check { path, program } => match snapshot.rules.policy_for(&path) {
            None => Response::Check {
                protected: false,
                path: None,
                outcome: None,
            },
            Some(policy) => {
                let outcome = program.as_deref().map(|program| {
                    // `check` is advisory: no hash verification (no-op hasher).
                    match evaluate(policy, program, |_| None) {
                        Outcome::Allow => "allow",
                        Outcome::AllowWatch => "allow_watch",
                        Outcome::Deny => "deny",
                        Outcome::Ask => "ask",
                    }
                    .to_string()
                });
                Response::Check {
                    protected: true,
                    path: Some(policy.path.clone()),
                    outcome,
                }
            }
        },
        Request::Reload => match state.reload() {
            Ok(()) => {
                // Flush the once-cache so stale verdicts don't outlive a change.
                cache.flush();
                Response::Ok
            }
            Err(err) => Response::Error {
                message: format!("reload failed, old policies still active: {err:#}"),
            },
        },
        Request::Verdicts => Response::Verdicts {
            pauses: snoozes
                .list()
                .into_iter()
                .map(|(path, uid, remaining_secs)| PauseInfo {
                    path,
                    uid,
                    remaining_secs,
                })
                .collect(),
            temporary: cache
                .list()
                .into_iter()
                .map(|(path, program, allow, remaining_secs)| TemporaryInfo {
                    path,
                    program,
                    allow,
                    remaining_secs,
                })
                .collect(),
            remembered: snapshot
                .remembered
                .entries()
                .into_iter()
                .map(|(path, program, allow)| RememberedInfo {
                    path,
                    program,
                    allow,
                })
                .collect(),
        },
        Request::Pause { path, secs } => match resolve_path(&snapshot, &path) {
            Some(protected) => {
                // Root CLI pause: global (all uids).
                snoozes.set(&protected, None, std::time::Duration::from_secs(secs));
                Response::Ok
            }
            None => Response::Error {
                message: format!("no protected path covers {}", path.display()),
            },
        },
        Request::Resume { path } => match path {
            None => {
                snoozes.clear(None);
                Response::Ok
            }
            Some(path) => match resolve_path(&snapshot, &path) {
                Some(protected) => {
                    snoozes.clear(Some(&protected));
                    Response::Ok
                }
                None => Response::Error {
                    message: format!("no protected path covers {}", path.display()),
                },
            },
        },
        Request::Forget { path, program } => {
            // Resolve to the governing protected path (dynamic state is keyed
            // there), same as pause/resume — so `forget <file-under-a-path>`
            // works and an unknown target errors instead of silently no-op'ing.
            match resolve_path(&snapshot, &path) {
                Some(protected) => {
                    let temporary = cache.remove(&protected, program.as_deref());
                    match state.forget_remembered(&protected, program.as_deref()) {
                        Ok(remembered) => Response::Forgotten {
                            temporary,
                            remembered,
                        },
                        Err(err) => Response::Error {
                            message: format!("forget failed: {err:#}"),
                        },
                    }
                }
                None => Response::Error {
                    message: format!("no protected path covers {}", path.display()),
                },
            }
        }
        Request::Protect { path, mode, allow } => {
            handle_protect(path, mode, allow, state, cache, backend, &snapshot)
        }
        Request::Allow { path, program, pin } => {
            handle_add_entry(path, program, pin, true, state, cache, &snapshot)
        }
        Request::Deny { path, program } => {
            handle_add_entry(path, program, None, false, state, cache, &snapshot)
        }
        Request::RemoveEntry { path, program } => {
            handle_remove_entry(path, program, state, cache, &snapshot)
        }
        Request::AllowFor {
            path,
            program,
            secs,
        } => handle_allow_for(path, program, secs, cache, &snapshot),
        Request::Unprotect { path } => {
            // Trim trailing slashes: canonicalized paths never carry one, but a
            // deleted target is passed through as typed and must still match
            // the stored path.
            let pattern = {
                let s = path.to_string_lossy();
                let trimmed = s.trim_end_matches('/');
                if trimmed.is_empty() {
                    "/".to_string()
                } else {
                    trimmed.to_string()
                }
            };
            match state.remove_managed_path(&pattern) {
                Ok(Some(_)) => {
                    // Flush the once-cache and any pause so stale verdicts don't
                    // outlive the policy — a re-protect of the same path must
                    // start fully fresh (remembered is purged inside
                    // remove_managed_path).
                    cache.flush();
                    snoozes.clear(Some(&pattern));
                    Response::Ok
                }
                Ok(None) => Response::Error {
                    message: match snapshot.rules.policy_for(Path::new(&pattern)) {
                        Some(policy) if snapshot.managed_paths.contains(&policy.path) => format!(
                            "no CLI-managed path exactly matches {pattern}; it is covered by \
                             CLI-managed path {:?} — unprotect that path instead",
                            policy.path
                        ),
                        Some(policy) => format!(
                            "no CLI-managed path protects {pattern}; it is covered by {:?} from \
                             your paths.d files — edit those to change it",
                            policy.path
                        ),
                        None => format!("no protected path matches {pattern}"),
                    },
                },
                Err(err) => Response::Error {
                    message: format!("unprotect failed: {err:#}"),
                },
            }
        }
    }
}

/// Resolve a CLI-supplied path to the protected path that governs it
/// (longest-prefix). `None` = not under any protected path.
fn resolve_path(snapshot: &Snapshot, path: &Path) -> Option<String> {
    snapshot.rules.policy_for(path).map(|p| p.path.clone())
}

/// Render a config allow/deny entry for `list -v` (pins marked).
fn render_entry(entry: &AllowEntry) -> String {
    if entry.sha256.is_some() {
        format!("{} [pinned]", entry.program.display())
    } else {
        entry.program.display().to_string()
    }
}

/// Resolve a pin arg into a stored sha256 (or None). `Auto` hashes the program.
fn resolve_pin(program: &Path, pin: Option<PinArg>) -> Result<Option<String>, String> {
    match pin {
        None => Ok(None),
        Some(PinArg::Auto) => crate::hashing::hash_file(program)
            .map(Some)
            .map_err(|err| format!("cannot hash {}: {err}", program.display())),
        Some(PinArg::Sha256(hex)) => Ok(Some(hex.to_ascii_lowercase())),
    }
}

/// Merge `entries` into a copy of `current`, applying `mode` only if `Some`.
/// Per-program semantics: re-adding an identical entry (same program AND same
/// pin) is an idempotent no-op; re-adding a program that is already listed with
/// a DIFFERENT pin state is rejected — silently replacing/adding would weaken or
/// nullify an existing hash pin (evaluate() allows on any matching entry).
fn plan_protect_merge(
    current: &PathPolicy,
    mode: Option<Mode>,
    entries: &[AllowEntry],
) -> Result<PathPolicy, String> {
    let mut merged = current.clone();
    if let Some(m) = mode {
        merged.mode = m;
    }
    for e in entries {
        match merged.allow.iter().find(|x| x.program == e.program) {
            Some(existing) if existing == e => {} // identical → no-op
            Some(_) => {
                return Err(format!(
                    "{} is already allowed on {} with a different pin; run \
                     `fsnitch unprotect {} --program {}` first to change it",
                    e.program.display(),
                    current.path,
                    current.path,
                    e.program.display()
                ));
            }
            None => merged.allow.push(e.clone()),
        }
    }
    Ok(merged)
}

/// `fsnitch protect`: create a new CLI-managed policy, or merge into an
/// existing one — dedup-appending entries and (only when `mode` is `Some`)
/// updating the mode. Re-protecting an already-managed path with identical
/// entries is how programs get added incrementally; re-adding a program with
/// a *different* pin state is rejected rather than silently changing it (see
/// `plan_protect_merge`).
fn handle_protect(
    path: PathBuf,
    mode: Option<Mode>,
    allow: Vec<AllowArg>,
    state: &State,
    cache: &VerdictCache,
    backend: &Arc<dyn EnforcementBackend>,
    snapshot: &Snapshot,
) -> Response {
    let pattern = path.to_string_lossy().into_owned();

    // Resolve pins into entries (unchanged).
    let mut entries = Vec::with_capacity(allow.len());
    for arg in allow {
        let sha256 = match resolve_pin(&arg.program, arg.pin) {
            Ok(s) => s,
            Err(message) => return Response::Error { message },
        };
        entries.push(AllowEntry {
            program: arg.program,
            sha256,
        });
    }

    // MERGE path: already a CLI-managed path -> dedup-append entries, optionally
    // update mode; rejects a conflicting re-add of a program with a different
    // pin instead of silently changing it (see plan_protect_merge).
    if snapshot.managed_paths.contains(&pattern) {
        // ensure_watched is idempotent and independent of the merge, so it can
        // run before the lock.
        if let Err(err) = backend.ensure_watched(&path) {
            return Response::Error {
                message: format!("cannot watch {}: {err:#}", path.display()),
            };
        }
        // Merge (conflict-reject + validation) runs on the disk-fresh policy
        // under the write lock, so a concurrent `protect` can't lose an update
        // (see plan_protect_merge).
        let result = state.update_managed_path(&pattern, move |p| {
            let merged = plan_protect_merge(p, mode, &entries)?;
            Config::validate_policies(std::slice::from_ref(&merged)).map_err(|e| e.to_string())?;
            *p = merged;
            Ok(())
        });
        return match result {
            Ok(ManagedUpdate::Updated) => {
                cache.flush();
                let count = state
                    .snapshot()
                    .config
                    .paths
                    .iter()
                    .find(|p| p.path == pattern)
                    .map(|p| p.allow.len())
                    .unwrap_or(0);
                Response::Protected {
                    path: pattern,
                    note: Some(format!("updated: {count} program(s) allowed")),
                }
            }
            Ok(ManagedUpdate::Rejected(message)) => Response::Error { message },
            Ok(ManagedUpdate::NotManaged) => Response::Error {
                message: format!("{pattern} is no longer a CLI-managed protected path"),
            },
            Err(err) => Response::Error {
                message: format!("protect failed: {err:#}"),
            },
        };
    }

    // CREATE path (as before), mode defaults to Ask when unset.
    let covered_before = snapshot.rules.policy_for(&path).map(|p| p.path.clone());
    let policy = PathPolicy {
        path: pattern.clone(),
        mode: mode.unwrap_or(Mode::Ask),
        allow: entries,
        deny: Vec::new(),
    };
    if let Err(err) = Config::validate_policies(std::slice::from_ref(&policy)) {
        return Response::Error {
            message: err.to_string(),
        };
    }
    if let Err(err) = backend.ensure_watched(&path) {
        return Response::Error {
            message: format!("cannot watch {}: {err:#}", path.display()),
        };
    }
    if let Err(err) = state.add_managed_path(policy) {
        return Response::Error {
            message: format!("protect failed: {err:#}"),
        };
    }
    cache.flush();
    let note = covered_before
        .map(|a| format!("also covered by {a:?}; the most specific path takes precedence"));
    Response::Protected {
        path: pattern,
        note,
    }
}

/// `fsnitch allow` / `fsnitch deny`: append a fixed entry to a CLI-managed
/// path's policy. Hand-written or unprotected paths are refused.
fn handle_add_entry(
    path: PathBuf,
    program: PathBuf,
    pin: Option<PinArg>,
    allow_flag: bool,
    state: &State,
    cache: &VerdictCache,
    snapshot: &Snapshot,
) -> Response {
    let pattern = path.to_string_lossy().into_owned();
    let verb = if allow_flag { "allow" } else { "deny" };
    if !snapshot.managed_paths.contains(&pattern) {
        let message = if snapshot.config.paths.iter().any(|p| p.path == pattern) {
            format!(
                "{pattern} is a hand-written protected path — edit its paths.d drop-in to \
                 change its {verb} list"
            )
        } else {
            format!("{pattern} is not protected — run `fsnitch protect {pattern}` first")
        };
        return Response::Error { message };
    }
    let sha256 = match resolve_pin(&program, pin) {
        Ok(s) => s,
        Err(message) => return Response::Error { message },
    };
    let entry = AllowEntry { program, sha256 };
    // Validate the candidate policy before touching disk (clear early error).
    let Some(current) = snapshot.config.paths.iter().find(|p| p.path == pattern) else {
        return Response::Error {
            message: format!("{pattern} is not protected"),
        };
    };
    // Idempotent: an identical entry already present is a no-op success
    // (avoids duplicate rows piling up in managed.toml).
    let existing = if allow_flag {
        &current.allow
    } else {
        &current.deny
    };
    if existing.contains(&entry) {
        return Response::Ok;
    }
    let mut candidate = current.clone();
    if allow_flag {
        candidate.allow.push(entry.clone());
    } else {
        candidate.deny.push(entry.clone());
    }
    if let Err(err) = Config::validate_policies(std::slice::from_ref(&candidate)) {
        return Response::Error {
            message: err.to_string(),
        };
    }
    match state.update_managed_path(&pattern, move |p| {
        if allow_flag {
            p.allow.push(entry);
        } else {
            p.deny.push(entry);
        }
        Ok(())
    }) {
        Ok(ManagedUpdate::Updated) => {
            // A stale once-verdict must not outlive a policy change.
            cache.flush();
            Response::Ok
        }
        Ok(ManagedUpdate::NotManaged) => Response::Error {
            message: format!("{pattern} is no longer a CLI-managed protected path"),
        },
        Ok(ManagedUpdate::Rejected(message)) => Response::Error { message },
        Err(err) => Response::Error {
            message: format!("{verb} failed: {err:#}"),
        },
    }
}

/// `fsnitch remove`: delete a fixed allow/deny entry from a CLI-managed path's
/// policy (the inverse of `allow`/`deny`). Hand-written or unprotected paths
/// are refused, same as `allow`/`deny`.
fn handle_remove_entry(
    path: PathBuf,
    program: PathBuf,
    state: &State,
    cache: &VerdictCache,
    snapshot: &Snapshot,
) -> Response {
    let pattern = path.to_string_lossy().into_owned();
    // If the program has a temporary/remembered verdict here, the user likely
    // wants `forget`, not `remove` (which only edits fixed entries).
    let gov = resolve_path(snapshot, &path).unwrap_or_else(|| pattern.clone());
    let has_dynamic =
        cache.get(&gov, &program).is_some() || snapshot.remembered.get(&gov, &program).is_some();
    let forget_hint = if has_dynamic {
        format!(
            " — {} has an active temporary/remembered verdict here; \
             use `fsnitch forget {} --program {}` to clear it",
            program.display(),
            path.display(),
            program.display()
        )
    } else {
        String::new()
    };
    if !snapshot.managed_paths.contains(&pattern) {
        let message = if snapshot.config.paths.iter().any(|p| p.path == pattern) {
            format!(
                "{pattern} is a hand-written protected path — edit its paths.d drop-in to \
                 change its entries{forget_hint}"
            )
        } else {
            format!("{pattern} is not protected{forget_hint}")
        };
        return Response::Error { message };
    }
    let Some(current) = snapshot.config.paths.iter().find(|p| p.path == pattern) else {
        return Response::Error {
            message: format!("{pattern} is not protected"),
        };
    };
    let in_allow = current.allow.iter().any(|e| e.program == program);
    let in_deny = current.deny.iter().any(|e| e.program == program);
    if !in_allow && !in_deny {
        return Response::Error {
            message: format!(
                "no fixed allow/deny entry for {} on {pattern}{forget_hint}",
                program.display()
            ),
        };
    }
    let needle = program.clone();
    match state.update_managed_path(&pattern, move |p| {
        // A program may legitimately be in both lists (a hash-pinned allow can
        // coexist with a deny of the same program — validate_policies only
        // rejects the unpinned conflict). `remove` names a program, not an
        // entry, so retain drops it from whichever list(s) contain it.
        p.allow.retain(|e| e.program != needle);
        p.deny.retain(|e| e.program != needle);
        Ok(())
    }) {
        Ok(ManagedUpdate::Updated) => {
            cache.flush(); // a policy change must not leave a stale once-verdict
            Response::Ok
        }
        Ok(ManagedUpdate::NotManaged) => Response::Error {
            message: format!("{pattern} is no longer a CLI-managed protected path"),
        },
        Ok(ManagedUpdate::Rejected(message)) => Response::Error { message },
        Err(err) => Response::Error {
            message: format!("remove failed: {err:#}"),
        },
    }
}

/// `fsnitch protect <path> --program P --for D`: inject an in-memory temporary
/// allow verdict for `program` on the protected path governing `path` — the
/// same primitive the prompt dialog's AllowFor uses. Unlike `handle_add_entry`,
/// this never touches disk and works on any protected path (CLI-managed or
/// hand-written).
fn handle_allow_for(
    path: PathBuf,
    program: PathBuf,
    secs: u64,
    cache: &VerdictCache,
    snapshot: &Snapshot,
) -> Response {
    let Some(policy) = snapshot.rules.policy_for(&path) else {
        return Response::Error {
            message: format!("{} is not under any protected path", path.display()),
        };
    };
    // The once-cache is only consulted on the ask/prompt path, so where the
    // fixed policy already resolves the access to deny the timed allow would
    // be a silent no-op: refuse instead of lying with Ok. Advisory evaluation,
    // same as `check`: no hash verification (no-op hasher).
    if evaluate(policy, &program, |_| None) == Outcome::Deny {
        return Response::Error {
            message: format!(
                "{} on {} currently resolves to deny (fixed deny or block mode); a timed \
                 allow only applies to ask-mode access and cannot override a deny — remove \
                 the deny entry or change the mode",
                program.display(),
                policy.path
            ),
        };
    }
    // Allow/AllowWatch: redundant but harmless. Ask: the case this exists for.
    // Same primitive the dialog's AllowFor uses; insert_with_ttl is overflow-safe.
    cache.insert_with_ttl(
        &policy.path,
        &program,
        true,
        std::time::Duration::from_secs(secs),
    );
    Response::Ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{AccessEvent, EventToken};
    use crate::state::State;
    use fsnitch_core::protocol::{read_msg, write_msg, Request, Response};
    use std::io::BufReader;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex as StdMutex;

    #[derive(Default)]
    struct MockBackend {
        watched: StdMutex<Vec<PathBuf>>,
    }
    impl EnforcementBackend for MockBackend {
        fn next_events(&self) -> anyhow::Result<Vec<AccessEvent>> {
            anyhow::bail!("unused in control tests")
        }
        fn respond(&self, _token: EventToken, _allow: bool) -> anyhow::Result<()> {
            Ok(())
        }
        fn ensure_watched(&self, root: &Path) -> anyhow::Result<()> {
            self.watched.lock().unwrap().push(root.to_path_buf());
            Ok(())
        }
    }

    /// A live control plane over a tempdir config: shared state, cache, backend.
    struct Ctl {
        _dir: tempfile::TempDir,
        state: std::sync::Arc<State>,
        cache: VerdictCache,
        snoozes: std::sync::Arc<SnoozeStore>,
        backend: std::sync::Arc<MockBackend>,
        dyn_backend: std::sync::Arc<dyn EnforcementBackend>,
    }

    fn ctl(config_toml: &str) -> Ctl {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.toml"), config_toml).unwrap();
        let state = std::sync::Arc::new(State::load(dir.path()).unwrap());
        let backend = std::sync::Arc::new(MockBackend::default());
        Ctl {
            state,
            cache: VerdictCache::new(std::time::Duration::from_secs(60)),
            snoozes: std::sync::Arc::new(SnoozeStore::default()),
            dyn_backend: backend.clone(),
            backend,
            _dir: dir,
        }
    }

    fn protect_req(path: &str) -> Request {
        Request::Protect {
            path: path.into(),
            mode: Some(Mode::Ask),
            allow: vec![],
        }
    }

    fn test_state() -> State {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("config.toml"),
            r#"
            [[path]]
            path = "/vaults"
            mode = "block"
            allow = [{ program = "/usr/bin/keepassxc" }]
        "#,
        )
        .unwrap();
        State::load(dir.path()).unwrap()
    }

    fn roundtrip(state: &State, req: &Request) -> Response {
        use std::time::Duration;
        let (client, server) = UnixStream::pair().unwrap();
        let state = std::sync::Arc::new(state_clone_for_test(state));
        let handle = {
            let state = state.clone();
            std::thread::spawn(move || {
                let cache = VerdictCache::new(Duration::from_secs(60));
                let backend: Arc<dyn EnforcementBackend> = Arc::new(MockBackend::default());
                let snoozes = Arc::new(SnoozeStore::default());
                handle_connection(server, &state, &cache, &backend, &snoozes)
            })
        };
        let mut w = client.try_clone().unwrap();
        write_msg(&mut w, req).unwrap();
        drop(w); // EOF so the handler returns
        let resp: Response = read_msg(&mut BufReader::new(client)).unwrap().unwrap();
        handle.join().unwrap();
        resp
    }

    // State has no Clone; rebuild an equivalent one for thread ownership in tests.
    fn state_clone_for_test(_state: &State) -> State {
        test_state()
    }

    const VAULTS_FILE: &str = r#"
            [[path]]
            path = "/vaults"
            mode = "block"
        "#;

    #[test]
    fn protect_creates_managed_path_and_marks() {
        let c = ctl("");
        let resp = handle_request(
            protect_req("/data/x"),
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        match resp {
            Response::Protected { path, note } => {
                assert_eq!(path, "/data/x");
                assert!(note.is_none());
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert_eq!(
            c.backend.watched.lock().unwrap().as_slice(),
            &[PathBuf::from("/data/x")]
        );
        // Listed with source "cli".
        match handle_request(
            Request::List,
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        ) {
            Response::Paths { paths } => {
                assert_eq!(paths.len(), 1);
                assert_eq!(paths[0].source, "cli");
                assert_eq!(paths[0].mode, "ask");
            }
            other => panic!("unexpected: {other:?}"),
        }
        // Re-protecting the same path is a merge (no-op here, no new entries),
        // not an error — protect is additive (see the protect_merge_* tests).
        assert!(matches!(
            handle_request(
                protect_req("/data/x"),
                &c.state,
                &c.cache,
                &c.dyn_backend,
                &c.snoozes
            ),
            Response::Protected { .. }
        ));
    }

    #[test]
    fn protect_note_reports_broader_coverage() {
        // A hand-written broad path covers the new, more-specific managed path;
        // the note flags that (longest-prefix means the new one takes precedence).
        let c = ctl(VAULTS_FILE);
        match handle_request(
            protect_req("/vaults/sub"),
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        ) {
            Response::Protected { note, .. } => {
                let note = note.expect("note expected");
                assert!(note.contains("/vaults"), "{note}");
                assert!(note.contains("precedence"), "{note}");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn protect_most_specific_wins_for_managed_pair() {
        // Protect broad then narrow; a check under the narrow path resolves to it.
        let c = ctl("");
        handle_request(
            protect_req("/data"),
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        match handle_request(
            protect_req("/data/secret"),
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        ) {
            Response::Protected { note, .. } => {
                let note = note.expect("note expected");
                assert!(note.contains("/data"), "{note}");
            }
            other => panic!("unexpected: {other:?}"),
        }
        // Check under the narrow path reports the narrow path as governing.
        match handle_request(
            Request::Check {
                path: "/data/secret/x".into(),
                program: None,
            },
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        ) {
            Response::Check { path, .. } => assert_eq!(path.as_deref(), Some("/data/secret")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn protect_merges_into_existing_managed_path() {
        // Re-protecting an already CLI-managed path must merge (dedup-append
        // entries), not error on "duplicate" — that is the whole point of the
        // additive model.
        let c = ctl("");
        handle_request(
            protect_req("/data"),
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        let resp = handle_request(
            Request::Protect {
                path: "/data".into(),
                mode: None,
                allow: vec![AllowArg {
                    program: "/usr/bin/cat".into(),
                    pin: None,
                }],
            },
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        match resp {
            Response::Protected { path, note } => {
                assert_eq!(path, "/data");
                let note = note.expect("update note expected");
                assert!(note.contains("updated"), "{note}");
            }
            other => panic!("unexpected: {other:?}"),
        }
        let snap = c.state.snapshot();
        assert_eq!(
            snap.config
                .paths
                .iter()
                .filter(|p| p.path == "/data")
                .count(),
            1,
            "must still be exactly one policy for /data"
        );
        let policy = snap
            .config
            .paths
            .iter()
            .find(|p| p.path == "/data")
            .unwrap();
        assert!(
            policy
                .allow
                .iter()
                .any(|e| e.program == Path::new("/usr/bin/cat")),
            "{policy:?}"
        );

        // Re-adding the same program again is a no-op, not a duplicate row.
        handle_request(
            Request::Protect {
                path: "/data".into(),
                mode: None,
                allow: vec![AllowArg {
                    program: "/usr/bin/cat".into(),
                    pin: None,
                }],
            },
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        let snap = c.state.snapshot();
        let policy = snap
            .config
            .paths
            .iter()
            .find(|p| p.path == "/data")
            .unwrap();
        assert_eq!(
            policy
                .allow
                .iter()
                .filter(|e| e.program == Path::new("/usr/bin/cat"))
                .count(),
            1,
            "duplicate program must not add a second row: {policy:?}"
        );
    }

    #[test]
    fn protect_merge_runs_on_fresh_policy() {
        // The merge must be computed on the disk-fresh policy loaded INSIDE
        // update_managed_path's write-lock, not on the pre-lock `snapshot`
        // argument handle_protect receives — otherwise a concurrent update
        // landing between the caller's snapshot and the lock acquisition
        // would be silently discarded (the atomic-merge fix). Simulate that
        // staleness without real threads: take a snapshot, apply another
        // update through `state` directly (as a concurrent writer would),
        // then call handle_protect with the now-STALE snapshot and confirm
        // nothing is lost.
        let c = ctl("");
        handle_request(
            Request::Protect {
                path: "/data".into(),
                mode: None,
                allow: vec![AllowArg {
                    program: "/usr/bin/cat".into(),
                    pin: None,
                }],
            },
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        // Captured before the "concurrent" update below -> stale by the time
        // it's used.
        let stale_snapshot = c.state.snapshot();

        // A "concurrent" update lands on disk after the snapshot was taken.
        let updated = c
            .state
            .update_managed_path("/data", |p| {
                p.allow.push(AllowEntry {
                    program: "/usr/bin/ls".into(),
                    sha256: None,
                });
                Ok(())
            })
            .unwrap();
        assert!(matches!(updated, ManagedUpdate::Updated));

        // handle_protect merges a THIRD program, called with the STALE
        // snapshot (as if it had been captured before the concurrent update).
        let resp = handle_protect(
            "/data".into(),
            None,
            vec![AllowArg {
                program: "/usr/bin/echo".into(),
                pin: None,
            }],
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &stale_snapshot,
        );
        assert!(matches!(resp, Response::Protected { .. }), "{resp:?}");

        let snap = c.state.snapshot();
        let policy = snap
            .config
            .paths
            .iter()
            .find(|p| p.path == "/data")
            .unwrap();
        // All three must survive: the original, the "concurrent" one the
        // stale snapshot never saw, and the new one from this call. Losing
        // "ls" would mean the merge overwrote with the stale, pre-concurrent
        // policy instead of the fresh on-disk one.
        for prog in ["/usr/bin/cat", "/usr/bin/ls", "/usr/bin/echo"] {
            assert!(
                policy.allow.iter().any(|e| e.program == Path::new(prog)),
                "missing {prog}: {policy:?}"
            );
        }
    }

    #[test]
    fn protect_merge_without_mode_keeps_mode() {
        // The additive merge must NOT downgrade the mode when --mode is absent.
        let c = ctl("");
        handle_request(
            Request::Protect {
                path: "/data".into(),
                mode: Some(Mode::Block),
                allow: vec![],
            },
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        handle_request(
            Request::Protect {
                path: "/data".into(),
                mode: None,
                allow: vec![AllowArg {
                    program: "/usr/bin/cat".into(),
                    pin: None,
                }],
            },
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        let snap = c.state.snapshot();
        let policy = snap
            .config
            .paths
            .iter()
            .find(|p| p.path == "/data")
            .unwrap();
        assert_eq!(policy.mode, Mode::Block);
    }

    #[test]
    fn protect_merge_with_mode_updates_mode() {
        // An explicit --mode on a merge does apply.
        let c = ctl("");
        handle_request(
            protect_req("/data"), // mode ask
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        handle_request(
            Request::Protect {
                path: "/data".into(),
                mode: Some(Mode::Block),
                allow: vec![],
            },
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        let snap = c.state.snapshot();
        let policy = snap
            .config
            .paths
            .iter()
            .find(|p| p.path == "/data")
            .unwrap();
        assert_eq!(policy.mode, Mode::Block);
    }

    #[test]
    fn protect_merge_dedups_identical_program() {
        // Re-adding the exact same (program, pin) pair is an idempotent no-op:
        // still exactly one row for that program.
        let c = ctl("");
        handle_request(
            protect_req("/data"),
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        let add_cat = || Request::Protect {
            path: "/data".into(),
            mode: None,
            allow: vec![AllowArg {
                program: "/usr/bin/cat".into(),
                pin: None,
            }],
        };
        assert!(matches!(
            handle_request(add_cat(), &c.state, &c.cache, &c.dyn_backend, &c.snoozes),
            Response::Protected { .. }
        ));
        assert!(matches!(
            handle_request(add_cat(), &c.state, &c.cache, &c.dyn_backend, &c.snoozes),
            Response::Protected { .. }
        ));
        let snap = c.state.snapshot();
        let policy = snap
            .config
            .paths
            .iter()
            .find(|p| p.path == "/data")
            .unwrap();
        assert_eq!(
            policy
                .allow
                .iter()
                .filter(|e| e.program == Path::new("/usr/bin/cat"))
                .count(),
            1,
            "identical re-add must not add a second row: {policy:?}"
        );
    }

    #[test]
    fn protect_merge_rejects_conflicting_pin() {
        // Regression for the additive-merge pin bypass: re-protecting an
        // already-pinned program WITHOUT the pin must be rejected, not
        // silently appended as a second, unpinned row (which would nullify
        // the pin since evaluate() allows on ANY matching entry).
        let c = ctl("");
        let pin = "a".repeat(64);
        assert!(matches!(
            handle_request(
                Request::Protect {
                    path: "/data".into(),
                    mode: Some(Mode::Ask),
                    allow: vec![AllowArg {
                        program: "/usr/bin/cat".into(),
                        pin: Some(PinArg::Sha256(pin.clone())),
                    }],
                },
                &c.state,
                &c.cache,
                &c.dyn_backend,
                &c.snoozes,
            ),
            Response::Protected { .. }
        ));

        let resp = handle_request(
            Request::Protect {
                path: "/data".into(),
                mode: None,
                allow: vec![AllowArg {
                    program: "/usr/bin/cat".into(),
                    pin: None,
                }],
            },
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        match resp {
            Response::Error { message } => {
                assert!(message.contains("different pin"), "{message}");
            }
            other => panic!("expected rejection, got: {other:?}"),
        }

        // The pin must NOT have been nullified: exactly one cat entry, still pinned.
        let snap = c.state.snapshot();
        let policy = snap
            .config
            .paths
            .iter()
            .find(|p| p.path == "/data")
            .unwrap();
        let cat_entries: Vec<_> = policy
            .allow
            .iter()
            .filter(|e| e.program == Path::new("/usr/bin/cat"))
            .collect();
        assert_eq!(cat_entries.len(), 1, "{policy:?}");
        assert_eq!(cat_entries[0].sha256.as_deref(), Some(pin.as_str()));
    }

    #[test]
    fn allow_and_deny_on_managed_path() {
        let c = ctl("");
        handle_request(
            protect_req("/data/x"),
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        assert!(matches!(
            handle_request(
                Request::Allow {
                    path: "/data/x".into(),
                    program: "/usr/bin/cat".into(),
                    pin: None,
                },
                &c.state,
                &c.cache,
                &c.dyn_backend,
                &c.snoozes
            ),
            Response::Ok
        ));
        assert!(matches!(
            handle_request(
                Request::Deny {
                    path: "/data/x".into(),
                    program: "/usr/bin/curl".into(),
                },
                &c.state,
                &c.cache,
                &c.dyn_backend,
                &c.snoozes
            ),
            Response::Ok
        ));
        // Both reflected in List.
        match handle_request(
            Request::List,
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        ) {
            Response::Paths { paths } => {
                let p = paths.iter().find(|p| p.path == "/data/x").unwrap();
                assert!(p.allow.iter().any(|a| a.contains("/usr/bin/cat")), "{p:?}");
                assert!(p.deny.iter().any(|d| d.contains("/usr/bin/curl")), "{p:?}");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn allow_rejects_handwritten_and_absent_path() {
        let c = ctl(VAULTS_FILE);
        // Hand-written path: refused (edit the file).
        assert!(matches!(
            handle_request(
                Request::Allow {
                    path: "/vaults".into(),
                    program: "/usr/bin/cat".into(),
                    pin: None,
                },
                &c.state,
                &c.cache,
                &c.dyn_backend,
                &c.snoozes
            ),
            Response::Error { .. }
        ));
        // Absent path: refused (protect it first).
        assert!(matches!(
            handle_request(
                Request::Deny {
                    path: "/nope".into(),
                    program: "/usr/bin/cat".into(),
                },
                &c.state,
                &c.cache,
                &c.dyn_backend,
                &c.snoozes
            ),
            Response::Error { .. }
        ));
    }

    #[test]
    fn remove_entry_deletes_fixed_allow() {
        let c = ctl("");
        handle_request(
            protect_req("/data"),
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        // Give it a fixed allow entry the same way `fsnitch allow` would.
        assert!(matches!(
            handle_request(
                Request::Allow {
                    path: "/data".into(),
                    program: "/usr/bin/head".into(),
                    pin: None,
                },
                &c.state,
                &c.cache,
                &c.dyn_backend,
                &c.snoozes
            ),
            Response::Ok
        ));

        let resp = handle_request(
            Request::RemoveEntry {
                path: "/data".into(),
                program: "/usr/bin/head".into(),
            },
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        assert!(matches!(resp, Response::Ok), "unexpected: {resp:?}");
        let snap = c.state.snapshot();
        let policy = snap
            .config
            .paths
            .iter()
            .find(|p| p.path == "/data")
            .unwrap();
        assert!(policy.allow.is_empty(), "allow entry not removed");

        // Removing a program that is not an entry errors clearly.
        let resp = handle_request(
            Request::RemoveEntry {
                path: "/data".into(),
                program: "/usr/bin/nope".into(),
            },
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        assert!(matches!(resp, Response::Error { .. }));
    }

    #[test]
    fn remove_entry_rejects_handwritten_path() {
        let c = ctl(VAULTS_FILE);
        let resp = handle_request(
            Request::RemoveEntry {
                path: "/vaults".into(),
                program: "/usr/bin/keepassxc".into(),
            },
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        assert!(matches!(resp, Response::Error { .. }));
    }

    #[test]
    fn remove_entry_hints_forget_for_dynamic_verdict() {
        let c = ctl("");
        handle_request(
            protect_req("/data"),
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        // No fixed entry for /usr/bin/cat, but it has a temporary verdict (as
        // `fsnitch protect <path> --program P --for D` would leave behind).
        c.cache
            .insert("/data", std::path::Path::new("/usr/bin/cat"), true);

        let resp = handle_request(
            Request::RemoveEntry {
                path: "/data".into(),
                program: "/usr/bin/cat".into(),
            },
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        match resp {
            Response::Error { message } => {
                assert!(message.contains("forget"), "want forget hint: {message}")
            }
            other => panic!("unexpected: {other:?}"),
        }

        // A program with no dynamic verdict at all still gets the plain error,
        // with no `forget` noise.
        let resp = handle_request(
            Request::RemoveEntry {
                path: "/data".into(),
                program: "/usr/bin/never".into(),
            },
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        match resp {
            Response::Error { message } => assert!(
                !message.contains("forget"),
                "unexpected forget hint: {message}"
            ),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn allow_for_inserts_temporary_verdict() {
        // Ask-mode hand-written path: a timed allow works on any protected
        // path (it is an in-memory verdict, not a fixed entry).
        let c = ctl(r#"
            [[path]]
            path = "/vaults"
            mode = "ask"
        "#);
        let resp = handle_request(
            Request::AllowFor {
                path: "/vaults".into(),
                program: "/usr/bin/cat".into(),
                secs: 60,
            },
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        assert!(matches!(resp, Response::Ok), "unexpected: {resp:?}");

        // The temporary verdict is now visible via Verdicts.
        match handle_request(
            Request::Verdicts,
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        ) {
            Response::Verdicts { temporary, .. } => {
                assert!(
                    temporary.iter().any(|t| t.path == "/vaults"
                        && t.program == Path::new("/usr/bin/cat")
                        && t.allow),
                    "{temporary:?}"
                );
            }
            other => panic!("unexpected: {other:?}"),
        }

        // An unprotected path errors.
        let resp = handle_request(
            Request::AllowFor {
                path: "/not/protected".into(),
                program: "/usr/bin/cat".into(),
                secs: 60,
            },
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        assert!(matches!(resp, Response::Error { .. }));
    }

    #[test]
    fn allow_for_rejects_deny_and_block_paths() {
        // The once-cache is only consulted on the ask/prompt path, so a timed
        // allow over a fixed deny or a block-mode path would be a silent no-op:
        // the handler must refuse instead of lying with Ok.
        let c = ctl("");
        handle_request(
            protect_req("/data"),
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        assert!(matches!(
            handle_request(
                Request::Deny {
                    path: "/data".into(),
                    program: "/usr/bin/curl".into(),
                },
                &c.state,
                &c.cache,
                &c.dyn_backend,
                &c.snoozes
            ),
            Response::Ok
        ));
        let resp = handle_request(
            Request::AllowFor {
                path: "/data".into(),
                program: "/usr/bin/curl".into(),
                secs: 600,
            },
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        assert!(
            matches!(resp, Response::Error { .. }),
            "unexpected: {resp:?}"
        );

        // Block mode with no matching allow entry is equally dead on arrival.
        handle_request(
            Request::Protect {
                path: "/blocked".into(),
                mode: Some(Mode::Block),
                allow: vec![],
            },
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        let resp = handle_request(
            Request::AllowFor {
                path: "/blocked".into(),
                program: "/usr/bin/cat".into(),
                secs: 600,
            },
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        assert!(
            matches!(resp, Response::Error { .. }),
            "unexpected: {resp:?}"
        );

        // Neither rejected request may leave a temporary verdict behind.
        match handle_request(
            Request::Verdicts,
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        ) {
            Response::Verdicts { temporary, .. } => {
                assert!(temporary.is_empty(), "{temporary:?}")
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn remove_entry_clears_pinned_allow_plus_deny() {
        // A hash-pinned allow may legitimately coexist with a deny of the same
        // program (validate_policies only rejects the unpinned conflict).
        // `remove` names a program, not an entry, so it clears both.
        let c = ctl("");
        handle_request(
            protect_req("/data"),
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        assert!(matches!(
            handle_request(
                Request::Allow {
                    path: "/data".into(),
                    program: "/usr/bin/tool".into(),
                    pin: Some(PinArg::Sha256("ab".repeat(32))),
                },
                &c.state,
                &c.cache,
                &c.dyn_backend,
                &c.snoozes
            ),
            Response::Ok
        ));
        assert!(matches!(
            handle_request(
                Request::Deny {
                    path: "/data".into(),
                    program: "/usr/bin/tool".into(),
                },
                &c.state,
                &c.cache,
                &c.dyn_backend,
                &c.snoozes
            ),
            Response::Ok
        ));
        {
            let snap = c.state.snapshot();
            let policy = snap
                .config
                .paths
                .iter()
                .find(|p| p.path == "/data")
                .unwrap();
            assert_eq!(policy.allow.len(), 1, "{policy:?}");
            assert_eq!(policy.deny.len(), 1, "{policy:?}");
        }

        let resp = handle_request(
            Request::RemoveEntry {
                path: "/data".into(),
                program: "/usr/bin/tool".into(),
            },
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        assert!(matches!(resp, Response::Ok), "unexpected: {resp:?}");
        let snap = c.state.snapshot();
        let policy = snap
            .config
            .paths
            .iter()
            .find(|p| p.path == "/data")
            .unwrap();
        assert!(policy.allow.is_empty(), "pinned allow not removed");
        assert!(policy.deny.is_empty(), "deny not removed");
    }

    #[test]
    fn remove_entry_deletes_fixed_deny() {
        let c = ctl("");
        handle_request(
            protect_req("/data"),
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        assert!(matches!(
            handle_request(
                Request::Deny {
                    path: "/data".into(),
                    program: "/usr/bin/curl".into(),
                },
                &c.state,
                &c.cache,
                &c.dyn_backend,
                &c.snoozes
            ),
            Response::Ok
        ));
        let resp = handle_request(
            Request::RemoveEntry {
                path: "/data".into(),
                program: "/usr/bin/curl".into(),
            },
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        assert!(matches!(resp, Response::Ok), "unexpected: {resp:?}");
        let snap = c.state.snapshot();
        let policy = snap
            .config
            .paths
            .iter()
            .find(|p| p.path == "/data")
            .unwrap();
        assert!(policy.deny.is_empty(), "deny entry not removed");
    }

    #[test]
    fn remove_entry_rejects_never_protected_path() {
        let c = ctl("");
        let resp = handle_request(
            Request::RemoveEntry {
                path: "/never".into(),
                program: "/usr/bin/cat".into(),
            },
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        assert!(
            matches!(resp, Response::Error { .. }),
            "unexpected: {resp:?}"
        );
    }

    #[test]
    fn unprotect_trailing_slash_matches_managed() {
        let c = ctl("");
        handle_request(
            protect_req("/data/x"),
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        assert!(matches!(
            handle_request(
                Request::Unprotect {
                    path: "/data/x/".into()
                },
                &c.state,
                &c.cache,
                &c.dyn_backend,
                &c.snoozes
            ),
            Response::Ok
        ));
    }

    #[test]
    fn unprotect_removes_managed_only() {
        let c = ctl(VAULTS_FILE);
        handle_request(
            protect_req("/data/x"),
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        // Managed path: removed.
        assert!(matches!(
            handle_request(
                Request::Unprotect {
                    path: "/data/x".into()
                },
                &c.state,
                &c.cache,
                &c.dyn_backend,
                &c.snoozes
            ),
            Response::Ok
        ));
        // Hand-written path: refused with a hint.
        match handle_request(
            Request::Unprotect {
                path: "/vaults".into(),
            },
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        ) {
            Response::Error { message } => assert!(message.contains("vaults")),
            other => panic!("unexpected: {other:?}"),
        }
        // Unknown path: refused.
        assert!(matches!(
            handle_request(
                Request::Unprotect {
                    path: "/nope".into()
                },
                &c.state,
                &c.cache,
                &c.dyn_backend,
                &c.snoozes
            ),
            Response::Error { .. }
        ));
    }

    #[test]
    fn protect_with_bad_pin_errors() {
        let c = ctl("");
        let req = Request::Protect {
            path: "/data/x".into(),
            mode: Some(Mode::Block),
            allow: vec![AllowArg {
                program: "/usr/bin/cat".into(),
                pin: Some(PinArg::Sha256("nothex".into())),
            }],
        };
        assert!(matches!(
            handle_request(req, &c.state, &c.cache, &c.dyn_backend, &c.snoozes),
            Response::Error { .. }
        ));
    }

    #[test]
    fn list_reports_source() {
        let c = ctl(VAULTS_FILE);
        handle_request(
            protect_req("/data/x"),
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        );
        match handle_request(
            Request::List,
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        ) {
            Response::Paths { paths } => {
                let vaults = paths.iter().find(|p| p.path == "/vaults").unwrap();
                assert_eq!(vaults.source, "file");
                let data = paths.iter().find(|p| p.path == "/data/x").unwrap();
                assert_eq!(data.source, "cli");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn pause_resolves_path_and_resume_clears() {
        let c = ctl(VAULTS_FILE);
        // Pause via a covered path resolves to the protected path; global scope.
        assert!(matches!(
            handle_request(
                Request::Pause {
                    path: "/vaults/sub/file".into(),
                    secs: 60
                },
                &c.state,
                &c.cache,
                &c.dyn_backend,
                &c.snoozes
            ),
            Response::Ok
        ));
        assert!(c.snoozes.active("/vaults", Some(1000)));
        match handle_request(
            Request::Verdicts,
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        ) {
            Response::Verdicts { pauses, .. } => {
                assert_eq!(pauses.len(), 1);
                assert_eq!(pauses[0].path, "/vaults");
                assert_eq!(pauses[0].uid, None);
                assert!(pauses[0].remaining_secs <= 60);
            }
            other => panic!("unexpected: {other:?}"),
        }
        // Resume by exact protected path.
        assert!(matches!(
            handle_request(
                Request::Resume {
                    path: Some("/vaults".into())
                },
                &c.state,
                &c.cache,
                &c.dyn_backend,
                &c.snoozes
            ),
            Response::Ok
        ));
        assert!(!c.snoozes.active("/vaults", Some(1000)));
        // Unknown path errors.
        assert!(matches!(
            handle_request(
                Request::Pause {
                    path: "/nope".into(),
                    secs: 60
                },
                &c.state,
                &c.cache,
                &c.dyn_backend,
                &c.snoozes
            ),
            Response::Error { .. }
        ));
    }

    #[test]
    fn verdicts_lists_temporary_and_remembered_and_forget_removes() {
        let c = ctl(VAULTS_FILE);
        c.cache
            .insert("/vaults", std::path::Path::new("/usr/bin/cat"), true);
        c.state
            .set_remembered("/vaults", PathBuf::from("/usr/bin/keepassxc"), true)
            .unwrap();
        c.state
            .set_remembered("/vaults", PathBuf::from("/tmp/stealer"), false)
            .unwrap();

        match handle_request(
            Request::Verdicts,
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        ) {
            Response::Verdicts {
                temporary,
                remembered,
                ..
            } => {
                assert_eq!(temporary.len(), 1);
                assert!(temporary[0].allow);
                assert_eq!(temporary[0].program, PathBuf::from("/usr/bin/cat"));
                assert_eq!(remembered.len(), 2);
            }
            other => panic!("unexpected: {other:?}"),
        }

        // Program-filtered forget: one remembered entry goes, temp untouched.
        match handle_request(
            Request::Forget {
                path: "/vaults".into(),
                program: Some("/tmp/stealer".into()),
            },
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        ) {
            Response::Forgotten {
                temporary,
                remembered,
            } => {
                assert_eq!(temporary, 0);
                assert_eq!(remembered, 1);
            }
            other => panic!("unexpected: {other:?}"),
        }

        // Path-wide forget: drops the temp entry + remaining remembered.
        match handle_request(
            Request::Forget {
                path: "/vaults".into(),
                program: None,
            },
            &c.state,
            &c.cache,
            &c.dyn_backend,
            &c.snoozes,
        ) {
            Response::Forgotten {
                temporary,
                remembered,
            } => {
                assert_eq!(temporary, 1);
                assert_eq!(remembered, 1);
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert!(c
            .state
            .snapshot()
            .remembered
            .get("/vaults", std::path::Path::new("/usr/bin/keepassxc"))
            .is_none());
    }

    #[test]
    fn status_reports_paths() {
        let resp = roundtrip(&test_state(), &Request::Status);
        match resp {
            Response::Status { paths, roots, .. } => {
                assert_eq!(paths, 1);
                assert_eq!(roots, vec![std::path::PathBuf::from("/vaults")]);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn check_reports_protected_and_outcome() {
        let resp = roundtrip(
            &test_state(),
            &Request::Check {
                path: "/vaults/a.kdbx".into(),
                program: Some("/tmp/x".into()),
            },
        );
        match resp {
            Response::Check {
                protected,
                path,
                outcome,
            } => {
                assert!(protected);
                assert_eq!(path.as_deref(), Some("/vaults"));
                assert_eq!(outcome.as_deref(), Some("deny"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn check_unprotected_path() {
        let resp = roundtrip(
            &test_state(),
            &Request::Check {
                path: "/etc/passwd".into(),
                program: None,
            },
        );
        match resp {
            Response::Check {
                protected,
                path,
                outcome,
            } => {
                assert!(!protected);
                assert!(path.is_none());
                assert!(outcome.is_none());
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
}
