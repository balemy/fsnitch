//! Running policy changes through `pkexec fsnitch …` off the GTK main thread.

use std::process::Command;

/// What became of one privileged command, as shown in a toast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Done,
    /// The user dismissed the password prompt.
    Cancelled,
    Failed(String),
}

/// pkexec: 126 = the user dismissed the dialog / not authorized,
/// 127 = authentication failed or no polkit agent could be reached.
pub fn classify(code: Option<i32>, stderr: &str) -> Outcome {
    let first_line = || {
        stderr
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("")
            .to_string()
    };
    match code {
        Some(0) => Outcome::Done,
        Some(126) => Outcome::Cancelled,
        Some(127) if stderr.contains("authentication agent") || stderr.is_empty() => {
            Outcome::Failed(
                "Authorization failed — is a polkit authentication agent running?".into(),
            )
        }
        _ => {
            let line = first_line();
            Outcome::Failed(if line.is_empty() {
                "The command failed.".into()
            } else {
                // `fail()` prints "error: …", anyhow from main "Error: …".
                line.trim_start_matches("error: ")
                    .trim_start_matches("Error: ")
                    .to_string()
            })
        }
    }
}

/// Run `argv` (blocking — call it via `gio::spawn_blocking`).
pub fn run(argv: &[String]) -> Outcome {
    let Some((program, args)) = argv.split_first() else {
        return Outcome::Failed("empty command".into());
    };
    match Command::new(program).args(args).output() {
        Ok(out) => classify(out.status.code(), &String::from_utf8_lossy(&out.stderr)),
        Err(err) => Outcome::Failed(format!("could not run {program}: {err}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_classified() {
        assert_eq!(classify(Some(0), ""), Outcome::Done);
        assert_eq!(classify(Some(126), "Not authorized"), Outcome::Cancelled);
        assert!(matches!(
            classify(Some(127), "Error executing command as another user: No authentication agent found."),
            Outcome::Failed(m) if m.contains("polkit")
        ));
        assert_eq!(
            classify(Some(1), "\nerror: no protected path matches /x\nmore\n"),
            Outcome::Failed("no protected path matches /x".into())
        );
        assert_eq!(
            classify(None, ""),
            Outcome::Failed("The command failed.".into())
        );
    }

    #[test]
    fn run_reports_missing_binary() {
        assert!(matches!(
            run(&["/nonexistent/fsnitch-test-binary".to_string()]),
            Outcome::Failed(m) if m.contains("could not run")
        ));
    }
}
