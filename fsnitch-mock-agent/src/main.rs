//! Headless test agent: registers and replies to every prompt with a fixed verdict.

use anyhow::Context;
use fsnitch_core::protocol::{read_msg, write_msg, AgentMsg, DaemonMsg, Verdict};
use std::io::BufReader;
use std::os::unix::net::UnixStream;

const SOCKET_PATH: &str = "/run/fsnitch/fsnitchd.sock";

fn parse_verdict(s: &str) -> Option<Verdict> {
    Some(match s {
        "allow-once" => Verdict::AllowOnce,
        "allow-forever" => Verdict::AllowForever,
        "deny-once" => Verdict::DenyOnce,
        "deny-forever" => Verdict::DenyForever,
        _ => return None,
    })
}

/// (verdict word, socket path) from the CLI args (binary name already stripped).
/// `--socket PATH` may appear anywhere; any other arg is the verdict.
fn parse_args(
    mut args: impl Iterator<Item = String>,
) -> anyhow::Result<(String, std::path::PathBuf)> {
    let mut verdict = "deny-once".to_string();
    let mut socket = std::path::PathBuf::from(SOCKET_PATH);
    while let Some(arg) = args.next() {
        if arg == "--socket" {
            socket = args.next().context("--socket needs a path")?.into();
        } else {
            verdict = arg;
        }
    }
    Ok((verdict, socket))
}

fn main() -> anyhow::Result<()> {
    let (arg, socket) = parse_args(std::env::args().skip(1))?;
    let verdict = parse_verdict(&arg)
        .context("verdict must be allow-once|allow-forever|deny-once|deny-forever")?;

    let stream = UnixStream::connect(&socket)
        .with_context(|| format!("connecting to {}", socket.display()))?;
    let mut writer = stream.try_clone()?;
    write_msg(&mut writer, &AgentMsg::Register)?;
    eprintln!("mock-agent: registered, will reply {arg} to every prompt");

    let mut reader = BufReader::new(stream);
    loop {
        match read_msg::<_, DaemonMsg>(&mut reader)? {
            Some(DaemonMsg::Prompt(req)) => {
                eprintln!(
                    "mock-agent: prompt id={} program={} -> {arg}",
                    req.id,
                    req.program.display()
                );
                write_msg(
                    &mut writer,
                    &AgentMsg::Respond {
                        id: req.id,
                        verdict,
                    },
                )?;
            }
            Some(DaemonMsg::Event { kind, message }) => {
                eprintln!("mock-agent: event {kind}: {message}");
            }
            None => break, // daemon closed
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn parse(args: &[&str]) -> anyhow::Result<(String, PathBuf)> {
        parse_args(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn defaults_to_deny_once_on_the_default_socket() {
        let (verdict, socket) = parse(&[]).unwrap();
        assert_eq!(verdict, "deny-once");
        assert_eq!(socket, PathBuf::from(SOCKET_PATH));
    }

    #[test]
    fn socket_flag_overrides_the_path() {
        let (verdict, socket) = parse(&["allow-forever", "--socket", "/tmp/t.sock"]).unwrap();
        assert_eq!(verdict, "allow-forever");
        assert_eq!(socket, PathBuf::from("/tmp/t.sock"));
    }

    #[test]
    fn socket_flag_may_precede_the_verdict() {
        let (verdict, socket) = parse(&["--socket", "/tmp/t.sock", "allow-once"]).unwrap();
        assert_eq!(verdict, "allow-once");
        assert_eq!(socket, PathBuf::from("/tmp/t.sock"));
    }

    #[test]
    fn socket_flag_without_a_path_is_an_error() {
        assert!(parse(&["--socket"]).is_err());
    }
}
