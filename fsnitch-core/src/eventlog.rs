//! Append-only JSON-lines event log.

use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRecord {
    /// RFC 3339 UTC timestamp.
    pub ts: String,
    /// The protected path whose policy produced the decision.
    pub path: String,
    /// The specific file the program tried to open (a placeholder like
    /// `<prompt>`/`<unresolved>` when no single file applies).
    pub file: PathBuf,
    /// The program attempting the access.
    pub program: Option<PathBuf>,
    pub pid: i32,
    pub uid: u32,
    /// "allow" | "deny"
    pub decision: String,
    /// "policy" | "watch" | "remembered" | "cache" | "prompt" | "no_agent" |
    /// "paused" | "timeout" | "overload" | "unresolved_path" — what produced
    /// the decision.
    pub source: String,
}

impl EventRecord {
    pub fn now_ts() -> String {
        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }
}

pub struct EventLog {
    file: File,
}

impl EventLog {
    pub fn open(path: &Path) -> std::io::Result<EventLog> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(EventLog { file })
    }

    pub fn append(&mut self, record: &EventRecord) -> std::io::Result<()> {
        serde_json::to_writer(&mut self.file, record)?;
        self.file.write_all(b"\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> EventRecord {
        EventRecord {
            ts: "2026-07-10T12:00:00Z".into(),
            path: "/home/luke/vaults".into(),
            file: "/home/luke/vaults/secret.kdbx".into(),
            program: Some("/tmp/stealer".into()),
            pid: 4242,
            uid: 1000,
            decision: "deny".into(),
            source: "rule".into(),
        }
    }

    #[test]
    fn appends_json_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let mut log = EventLog::open(&path).unwrap();
        log.append(&record()).unwrap();
        log.append(&record()).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let parsed: EventRecord = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed.path, "/home/luke/vaults");
        assert_eq!(parsed.decision, "deny");
    }

    #[test]
    fn creates_parent_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/dir/events.jsonl");
        let mut log = EventLog::open(&path).unwrap();
        log.append(&record()).unwrap();
        assert!(path.exists());
    }
}
