//! Blocking reader for the daemon's read-only status socket.

use crate::model::{merge, Snapshot};
use fsnitch_core::protocol::{read_msg, write_msg, Request, Response};
use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// How many log records the log page shows.
pub const EVENT_LIMIT: usize = 200;

/// Fetch status, paths, verdicts and recent events over one connection.
/// The error is a user-facing sentence.
pub fn fetch(socket: &Path) -> Result<Snapshot, String> {
    let stream = UnixStream::connect(socket)
        .map_err(|err| format!("The fsnitch daemon is not reachable ({err})."))?;
    let timeout = Some(Duration::from_secs(5));
    let _ = stream.set_read_timeout(timeout);
    let _ = stream.set_write_timeout(timeout);
    let mut writer = stream.try_clone().map_err(|err| err.to_string())?;
    let mut reader = BufReader::new(stream);
    let mut ask = |req: Request| -> Result<Response, String> {
        write_msg(&mut writer, &req).map_err(|err| format!("talking to the daemon: {err}"))?;
        match read_msg(&mut reader) {
            Ok(Some(Response::Error { message })) => Err(message),
            Ok(Some(resp)) => Ok(resp),
            Ok(None) => Err("the daemon closed the connection".into()),
            Err(err) => Err(format!("talking to the daemon: {err}")),
        }
    };
    let unexpected = |resp: Response| format!("unexpected daemon reply: {resp:?}");

    let (version, agent_connected, degraded_roots) = match ask(Request::Status)? {
        Response::Status {
            version,
            agent_connected,
            degraded_roots,
            ..
        } => (version, agent_connected, degraded_roots),
        other => return Err(unexpected(other)),
    };
    let paths = match ask(Request::List)? {
        Response::Paths { paths } => paths,
        other => return Err(unexpected(other)),
    };
    let (pauses, temporary, remembered) = match ask(Request::Verdicts)? {
        Response::Verdicts {
            pauses,
            temporary,
            remembered,
        } => (pauses, temporary, remembered),
        other => return Err(unexpected(other)),
    };
    let events = match ask(Request::Events { limit: EVENT_LIMIT })? {
        Response::Events { events } => events,
        other => return Err(unexpected(other)),
    };
    Ok(Snapshot {
        version,
        agent_connected,
        degraded_roots,
        paths: merge(paths, pauses, temporary, remembered),
        events,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsnitch_core::protocol::PathSummary;
    use std::os::unix::net::UnixListener;

    /// A fake status socket answering each request kind with a canned reply.
    fn serve_once(listener: UnixListener) {
        let (stream, _) = listener.accept().unwrap();
        let mut writer = stream.try_clone().unwrap();
        let mut reader = BufReader::new(stream);
        while let Ok(Some(req)) = read_msg::<_, Request>(&mut reader) {
            let resp = match req {
                Request::Status => Response::Status {
                    version: "9.9.9".into(),
                    paths: 1,
                    roots: vec![],
                    log_file: "/x".into(),
                    config_dir: "/etc/fsnitch".into(),
                    degraded_roots: vec![],
                    agent_connected: true,
                },
                Request::List => Response::Paths {
                    paths: vec![PathSummary {
                        path: "/v".into(),
                        mode: "ask".into(),
                        source: "cli".into(),
                        allow: vec!["/usr/bin/ssh".into()],
                        deny: vec![],
                    }],
                },
                Request::Verdicts => Response::Verdicts {
                    pauses: vec![],
                    temporary: vec![],
                    remembered: vec![],
                },
                Request::Events { .. } => Response::Events { events: vec![] },
                _ => Response::Error {
                    message: "nope".into(),
                },
            };
            write_msg(&mut writer, &resp).unwrap();
        }
    }

    #[test]
    fn fetch_builds_a_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("status.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || serve_once(listener));
        let snap = fetch(&sock).unwrap();
        assert_eq!(snap.version, "9.9.9");
        assert!(snap.agent_connected);
        assert_eq!(snap.paths.len(), 1);
        assert_eq!(snap.paths[0].programs[0].program, "/usr/bin/ssh");
        server.join().unwrap();
    }

    #[test]
    fn fetch_reports_unreachable_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let err = fetch(&dir.path().join("missing.sock")).unwrap_err();
        assert!(err.contains("not reachable"), "{err}");
    }
}
