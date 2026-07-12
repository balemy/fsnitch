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

fn main() -> anyhow::Result<()> {
    let arg = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "deny-once".into());
    let verdict = parse_verdict(&arg)
        .context("verdict must be allow-once|allow-forever|deny-once|deny-forever")?;

    let stream =
        UnixStream::connect(SOCKET_PATH).with_context(|| format!("connecting to {SOCKET_PATH}"))?;
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
