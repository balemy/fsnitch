//! Agent core (headless connector): connect/register/reconnect, read
//! `DaemonMsg`, forward prompts to the dialog manager, write verdicts back, and
//! surface events as notifications. Kept free of egui so it is unit-testable.

use fsnitch_core::protocol::{read_msg, write_msg, AgentMsg, DaemonMsg, PromptRequest, Verdict};
use std::io::{BufRead, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Shows FYI events to the user. Real impl uses notify-rust; tests use a fake.
pub trait Notifier: Send + Sync {
    fn notify(&self, summary: &str, body: &str);
}

/// Stable stdout/stdin token for a verdict (dialog subprocess <-> connector).
pub fn verdict_token(v: Verdict) -> String {
    match v {
        Verdict::AllowOnce => "allow_once".to_string(),
        Verdict::AllowForever => "allow_forever".to_string(),
        Verdict::DenyOnce => "deny_once".to_string(),
        Verdict::DenyForever => "deny_forever".to_string(),
        Verdict::AllowFor { secs } => format!("allow_for:{secs}"),
        Verdict::DenyFor { secs } => format!("deny_for:{secs}"),
        Verdict::Pause { secs } => format!("pause:{secs}"),
    }
}

/// Parse a verdict token printed by the dialog subprocess.
pub fn parse_verdict(s: &str) -> Option<Verdict> {
    let s = s.trim();
    if let Some(secs) = s.strip_prefix("allow_for:") {
        return secs.parse().ok().map(|secs| Verdict::AllowFor { secs });
    }
    if let Some(secs) = s.strip_prefix("deny_for:") {
        return secs.parse().ok().map(|secs| Verdict::DenyFor { secs });
    }
    if let Some(secs) = s.strip_prefix("pause:") {
        return secs.parse().ok().map(|secs| Verdict::Pause { secs });
    }
    match s {
        "allow_once" => Some(Verdict::AllowOnce),
        "allow_forever" => Some(Verdict::AllowForever),
        "deny_once" => Some(Verdict::DenyOnce),
        "deny_forever" => Some(Verdict::DenyForever),
        _ => None,
    }
}

/// Apply one daemon message: forward a prompt (stamped with its arrival time so
/// the manager can skip already-expired ones), or surface an event.
pub fn dispatch(
    msg: DaemonMsg,
    prompts: &Sender<(PromptRequest, Instant)>,
    notifier: &dyn Notifier,
) {
    match msg {
        DaemonMsg::Prompt(req) => {
            let _ = prompts.send((req, Instant::now()));
        }
        DaemonMsg::Event { kind, message } => {
            notifier.notify(&format!("fsnitch: {kind}"), &message);
        }
    }
}

pub fn send_register<W: Write>(w: &mut W) -> std::io::Result<()> {
    write_msg(w, &AgentMsg::Register)
}

pub fn send_verdict<W: Write>(w: &mut W, id: u64, verdict: Verdict) -> std::io::Result<()> {
    write_msg(w, &AgentMsg::Respond { id, verdict })
}

/// Read daemon messages until EOF/error, dispatching each.
pub fn read_loop<R: BufRead>(
    mut reader: R,
    prompts: &Sender<(PromptRequest, Instant)>,
    notifier: &dyn Notifier,
) {
    while let Ok(Some(msg)) = read_msg::<_, DaemonMsg>(&mut reader) {
        dispatch(msg, prompts, notifier);
    }
}

/// Connect, register, and pump the connection; reconnect with backoff forever.
/// A long-lived writer thread owns `verdict_rx` and writes to the current stream
/// (so it survives reconnects); while disconnected, verdicts are dropped — the
/// daemon has already timed them out.
pub fn run(
    socket_path: PathBuf,
    prompts: Sender<(PromptRequest, Instant)>,
    notifier: Arc<dyn Notifier>,
    verdict_rx: Receiver<(u64, Verdict)>,
) {
    let current: Arc<Mutex<Option<UnixStream>>> = Arc::new(Mutex::new(None));
    {
        let current = current.clone();
        std::thread::spawn(move || {
            while let Ok((id, verdict)) = verdict_rx.recv() {
                if let Some(w) = current.lock().unwrap().as_mut() {
                    if let Err(err) = send_verdict(w, id, verdict) {
                        tracing::warn!("failed to send verdict: {err}");
                    }
                }
            }
        });
    }

    let mut backoff = Duration::from_secs(1);
    loop {
        match UnixStream::connect(&socket_path) {
            Ok(stream) => {
                backoff = Duration::from_secs(1);
                match stream.try_clone() {
                    Ok(mut w) => {
                        if let Err(err) = send_register(&mut w) {
                            tracing::warn!("register failed: {err}");
                        }
                        *current.lock().unwrap() = Some(w);
                    }
                    Err(err) => tracing::warn!("stream clone failed: {err}"),
                }
                tracing::info!("connected to daemon");
                let reader = std::io::BufReader::new(stream);
                read_loop(reader, &prompts, notifier.as_ref());
                *current.lock().unwrap() = None;
                tracing::warn!("daemon connection closed");
            }
            Err(err) => {
                tracing::debug!("connect failed: {err}");
            }
        }
        std::thread::sleep(backoff);
        backoff = (backoff * 2).min(Duration::from_secs(5));
    }
}

/// Production notifier over the desktop notification service.
pub struct RealNotifier;

impl Notifier for RealNotifier {
    fn notify(&self, summary: &str, body: &str) {
        // notify-rust's `show()` makes a synchronous, per-call D-Bus connection.
        // Run it off the caller's thread (the socket read loop) so a slow or
        // absent notification service can never delay dispatch of queued prompts.
        let (summary, body) = (summary.to_string(), body.to_string());
        std::thread::spawn(move || {
            if let Err(err) = notify_rust::Notification::new()
                .summary(&summary)
                .body(&body)
                .show()
            {
                tracing::warn!("desktop notification failed: {err}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsnitch_core::protocol::{
        read_msg, write_msg, AgentMsg, DaemonMsg, PromptRequest, Verdict,
    };
    use std::io::BufReader;
    use std::sync::mpsc::channel;
    use std::sync::Mutex;

    struct FakeNotifier(Mutex<Vec<(String, String)>>);
    impl Notifier for FakeNotifier {
        fn notify(&self, summary: &str, body: &str) {
            self.0.lock().unwrap().push((summary.into(), body.into()));
        }
    }

    fn req() -> PromptRequest {
        PromptRequest {
            id: 5,
            path: "/vaults".into(),
            file: "/vaults/secret.kdbx".into(),
            program: "/usr/bin/curl".into(),
            pid: 99,
            uid: 1000,
            timeout_secs: 30,
        }
    }

    #[test]
    fn verdict_tokens_round_trip() {
        for v in [
            Verdict::AllowOnce,
            Verdict::AllowForever,
            Verdict::DenyOnce,
            Verdict::DenyForever,
            Verdict::AllowFor { secs: 900 },
            Verdict::DenyFor { secs: 900 },
            Verdict::Pause { secs: 300 },
        ] {
            assert_eq!(parse_verdict(&verdict_token(v)), Some(v));
        }
        assert_eq!(parse_verdict("garbage"), None);
        assert_eq!(parse_verdict(""), None);
        // Malformed timed tokens must not panic or misparse.
        assert_eq!(parse_verdict("pause:"), None);
        assert_eq!(parse_verdict("allow_for:x"), None);
        assert_eq!(parse_verdict("pause:-5"), None);
    }

    #[test]
    fn dispatch_prompt_forwards_to_channel() {
        let (tx, rx) = channel();
        let notifier = FakeNotifier(Mutex::new(Vec::new()));
        dispatch(DaemonMsg::Prompt(req()), &tx, &notifier);
        let (got, _at) = rx.try_recv().unwrap();
        assert_eq!(got.id, 5);
        assert!(notifier.0.lock().unwrap().is_empty());
    }

    #[test]
    fn dispatch_event_notifies() {
        let (tx, rx) = channel();
        let notifier = FakeNotifier(Mutex::new(Vec::new()));
        dispatch(
            DaemonMsg::Event {
                kind: "blocked".into(),
                message: "curl blocked".into(),
            },
            &tx,
            &notifier,
        );
        assert!(rx.try_recv().is_err());
        let n = notifier.0.lock().unwrap();
        assert_eq!(n.len(), 1);
        assert!(n[0].0.contains("blocked"));
        assert_eq!(n[0].1, "curl blocked");
    }

    #[test]
    fn send_register_writes_register() {
        let mut buf = Vec::new();
        send_register(&mut buf).unwrap();
        let got: AgentMsg = read_msg(&mut BufReader::new(buf.as_slice()))
            .unwrap()
            .unwrap();
        assert_eq!(got, AgentMsg::Register);
    }

    #[test]
    fn send_verdict_writes_respond() {
        let mut buf = Vec::new();
        send_verdict(&mut buf, 7, Verdict::AllowForever).unwrap();
        let got: AgentMsg = read_msg(&mut BufReader::new(buf.as_slice()))
            .unwrap()
            .unwrap();
        assert_eq!(
            got,
            AgentMsg::Respond {
                id: 7,
                verdict: Verdict::AllowForever
            }
        );
    }

    #[test]
    fn read_loop_dispatches_until_eof() {
        use std::os::unix::net::UnixStream;

        let (client, server) = UnixStream::pair().unwrap();
        let (tx, rx) = channel();
        let notifier = Arc::new(FakeNotifier(Mutex::new(Vec::new())));

        let handle = {
            let notifier = notifier.clone();
            std::thread::spawn(move || {
                let reader = BufReader::new(server);
                read_loop(reader, &tx, notifier.as_ref());
            })
        };

        let mut w = client.try_clone().unwrap();
        write_msg(&mut w, &DaemonMsg::Prompt(req())).unwrap();
        write_msg(
            &mut w,
            &DaemonMsg::Event {
                kind: "x".into(),
                message: "y".into(),
            },
        )
        .unwrap();
        drop(w);
        drop(client);
        handle.join().unwrap();

        let (got, _at) = rx.try_recv().unwrap();
        assert_eq!(got.id, 5);
        assert_eq!(notifier.0.lock().unwrap().len(), 1);
    }
}
