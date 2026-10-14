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

/// How far back from the end `read_tail` scans at most, so a frequent poller
/// (the GUI) never makes the daemon read a huge log in full.
pub const TAIL_SCAN_BYTES: u64 = 4 * 1024 * 1024;
const TAIL_CHUNK: u64 = 64 * 1024;

/// The last `limit` parseable records (oldest first), optionally only `uid`'s,
/// from at most the last `TAIL_SCAN_BYTES` of the log. A missing log is
/// empty; unparseable lines are skipped.
pub fn read_tail(path: &Path, limit: usize, uid: Option<u32>) -> std::io::Result<Vec<EventRecord>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    let len = file.metadata()?.len();
    let floor = len.saturating_sub(TAIL_SCAN_BYTES);
    let mut out = Vec::new();
    // Bytes of a line that started before the chunk read so far.
    let mut carry: Vec<u8> = Vec::new();
    let mut pos = len;
    while pos > floor && out.len() < limit {
        let start = pos.saturating_sub(TAIL_CHUNK).max(floor);
        let mut chunk = vec![0; (pos - start) as usize];
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(&mut chunk)?;
        chunk.extend_from_slice(&carry);
        pos = start;
        // The first piece may be the tail of an earlier line: keep it for the
        // next round, unless we're at the start of the file.
        let mut lines: Vec<&[u8]> = chunk.split(|b| *b == b'\n').collect();
        let head = if pos > 0 {
            lines.remove(0).to_vec()
        } else {
            Vec::new()
        };
        for line in lines.into_iter().rev() {
            let Ok(record) = serde_json::from_slice::<EventRecord>(line) else {
                continue;
            };
            if uid.is_none_or(|uid| record.uid == uid) {
                out.push(record);
                if out.len() == limit {
                    break;
                }
            }
        }
        carry = head;
    }
    out.reverse();
    Ok(out)
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
    fn read_tail_returns_last_n_filtered_by_uid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let mut log = EventLog::open(&path).unwrap();
        for (i, uid) in [1000, 0, 1000, 1001, 1000].iter().enumerate() {
            let mut r = record();
            r.pid = i as i32;
            r.uid = *uid;
            log.append(&r).unwrap();
        }
        let all = read_tail(&path, 3, None).unwrap();
        assert_eq!(all.iter().map(|r| r.pid).collect::<Vec<_>>(), vec![2, 3, 4]);
        let mine = read_tail(&path, 2, Some(1000)).unwrap();
        assert_eq!(mine.iter().map(|r| r.pid).collect::<Vec<_>>(), vec![2, 4]);
    }

    #[test]
    fn read_tail_reads_backwards_across_chunks_and_stops_at_the_scan_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let mut log = EventLog::open(&path).unwrap();
        // One old record of uid 7, then far more than the scan cap of others.
        let mut old = record();
        old.uid = 7;
        log.append(&old).unwrap();
        let line_len = serde_json::to_string(&record()).unwrap().len() as u64 + 1;
        let n = (TAIL_SCAN_BYTES / line_len) as i32 + 100;
        for i in 0..n {
            let mut r = record();
            r.pid = i;
            log.append(&r).unwrap();
        }
        // The newest records come back intact and in order across chunk edges.
        let last = read_tail(&path, 3, None).unwrap();
        assert_eq!(
            last.iter().map(|r| r.pid).collect::<Vec<_>>(),
            vec![n - 3, n - 2, n - 1]
        );
        let many = read_tail(&path, 2000, Some(1000)).unwrap();
        assert_eq!(many.len(), 2000);
        assert!(many.windows(2).all(|w| w[0].pid + 1 == w[1].pid));
        // uid 7's record lies beyond the scan cap: not found (bounded work).
        assert!(read_tail(&path, 10, Some(7)).unwrap().is_empty());
    }

    #[test]
    fn read_tail_skips_garbage_and_missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        assert!(read_tail(&path, 10, None).unwrap().is_empty());
        std::fs::write(&path, "not json\n").unwrap();
        assert!(read_tail(&path, 10, None).unwrap().is_empty());
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
