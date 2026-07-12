//! fsnitch-agent: a headless connector that talks to the daemon and shows a
//! prompt window per request by spawning a short-lived `--dialog` subprocess.
//! The connector itself has no GUI, so there is no window at idle (on any
//! platform); a window exists only while a prompt is being answered.

mod conn;
mod dialog;

use conn::{parse_verdict, verdict_token, Notifier, RealNotifier};
use fsnitch_core::protocol::{PromptRequest, Verdict};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

const DEFAULT_SOCKET: &str = "/run/fsnitch/fsnitchd.sock";

fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--dialog") {
        dialog_mode();
    } else {
        connector_mode(&args);
    }
}

/// `--dialog`: read one `PromptRequest` as JSON from stdin, show the window, and
/// print the chosen verdict token to stdout (nothing on dismiss/timeout).
fn dialog_mode() {
    let mut input = String::new();
    if let Err(err) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("fsnitch-agent --dialog: reading stdin failed: {err}");
        std::process::exit(1);
    }
    let req: PromptRequest = match serde_json::from_str(input.trim()) {
        Ok(req) => req,
        Err(err) => {
            eprintln!("fsnitch-agent --dialog: bad prompt JSON: {err}");
            std::process::exit(1);
        }
    };
    if let Some(verdict) = dialog::run_dialog(req) {
        println!("{}", verdict_token(verdict));
    }
}

/// Default mode: connect to the daemon, forward prompts to the dialog manager.
fn connector_mode(args: &[String]) {
    let socket_path = args
        .iter()
        .position(|a| a == "--socket")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET));

    let self_exe =
        std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/usr/bin/fsnitch-agent"));

    let (prompt_tx, prompt_rx) = channel::<(PromptRequest, Instant)>();
    let (verdict_tx, verdict_rx) = channel::<(u64, Verdict)>();
    let notifier: Arc<dyn Notifier> = Arc::new(RealNotifier);

    std::thread::spawn(move || dialog_manager(prompt_rx, verdict_tx, self_exe));

    // Blocks forever (reconnect loop).
    conn::run(socket_path, prompt_tx, notifier, verdict_rx);
}

/// Show prompts one window at a time; each is a `--dialog` subprocess.
fn dialog_manager(
    rx: Receiver<(PromptRequest, Instant)>,
    verdict_tx: Sender<(u64, Verdict)>,
    self_exe: PathBuf,
) {
    while let Ok((mut req, received)) = rx.recv() {
        // Skip prompts the daemon already timed out while we were busy.
        let total = Duration::from_secs(req.timeout_secs);
        let elapsed = received.elapsed();
        if elapsed >= total {
            tracing::info!(
                id = req.id,
                "prompt expired before it could be shown; skipping"
            );
            continue;
        }
        // Count down only the time that actually remains.
        req.timeout_secs = (total - elapsed).as_secs().max(1);

        let id = req.id;
        match show_dialog(&self_exe, &req) {
            Ok(Some(verdict)) => {
                let _ = verdict_tx.send((id, verdict));
            }
            Ok(None) => { /* dismissed / timed out: the daemon answers it */ }
            Err(err) => tracing::error!("dialog subprocess failed: {err}"),
        }
    }
}

/// Spawn `self_exe --dialog`, feed it the request as JSON, and read the verdict.
///
/// Bounded and always-reaping: a write failure or a wedged child (e.g. a GPU /
/// compositor init that hangs before the dialog's own self-close fires) must not
/// leak a zombie or block the single dialog_manager thread forever — that would
/// silently starve every future prompt. So we never early-return without waiting,
/// and we kill the child once its own deadline (plus a small grace) elapses.
fn show_dialog(self_exe: &Path, req: &PromptRequest) -> anyhow::Result<Option<Verdict>> {
    let json = serde_json::to_string(req)?;
    let mut child = Command::new(self_exe)
        .arg("--dialog")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    // Feed the request, then close stdin so the child's read_to_string returns.
    // Ignore write errors (a child that died early yields empty stdout -> None);
    // we must still fall through to reap it below.
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(json.as_bytes());
        let _ = stdin.write_all(b"\n");
    }
    let mut stdout = child.stdout.take();

    // The dialog self-closes at `timeout_secs`; give a couple of seconds grace,
    // then force-kill a child that hasn't exited so the pipeline never stalls.
    let deadline = Instant::now() + Duration::from_secs(req.timeout_secs) + Duration::from_secs(2);
    loop {
        match child.try_wait()? {
            Some(_status) => break,
            None if Instant::now() >= deadline => {
                tracing::warn!("dialog subprocess exceeded its deadline; killing");
                let _ = child.kill();
                let _ = child.wait();
                return Ok(None);
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    }

    // Child has exited: drain its (tiny) stdout. The four verdict tokens can't be
    // confused with eframe/wgpu diagnostics, so scanning lines is robust.
    let mut out = String::new();
    if let Some(mut so) = stdout.take() {
        let _ = so.read_to_string(&mut out);
    }
    Ok(out.lines().find_map(parse_verdict))
}
