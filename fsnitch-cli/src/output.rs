//! Pure renderers for the sectioned `status`/`show` output. No printing —
//! callers get a String, which keeps this unit-testable. Under `cargo test`
//! stdout is not a TTY, so `style` yields plain (uncolored) text.

use fsnitch_core::protocol::{PathSummary, PauseInfo, RememberedInfo, TemporaryInfo};

use super::{fmt_secs, style};

use std::fmt::Write as _;

fn pause_scope(uid: Option<u32>) -> String {
    match uid {
        None => "everyone".to_string(),
        Some(uid) => format!("uid {uid}"),
    }
}

fn allow_badge() -> String {
    style::green("allow")
}
/// Padded to the same width as "allow" so the program column lines up.
fn deny_badge() -> String {
    style::red("deny ")
}

/// Filter the three verdict lists down to one path, in the same order the
/// renderer takes them: (remembered, temporary, pauses).
pub(super) fn verdicts_for<'a>(
    path: &str,
    remembered: &'a [RememberedInfo],
    temporary: &'a [TemporaryInfo],
    pauses: &'a [PauseInfo],
) -> (
    Vec<&'a RememberedInfo>,
    Vec<&'a TemporaryInfo>,
    Vec<&'a PauseInfo>,
) {
    (
        remembered.iter().filter(|r| r.path == path).collect(),
        temporary.iter().filter(|t| t.path == path).collect(),
        pauses.iter().filter(|s| s.path == path).collect(),
    )
}

/// One path's section: header (path · mode · source), then its fixed entries,
/// remembered and temporary verdicts, and pause state — in that order. The
/// program column is padded to the widest program in this section. A section
/// with nothing in it gets a dim "(no rules)" line.
pub(super) fn render_path_section(
    p: &PathSummary,
    remembered: &[&RememberedInfo],
    temporary: &[&TemporaryInfo],
    pauses: &[&PauseInfo],
) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{}  {} {}",
        style::bold(&p.path),
        style::mode(&p.mode),
        style::source(&format!("· {}", p.source)),
    );

    // (badge, program, annotation) rows share one aligned program column.
    let mut rows: Vec<(String, String, String)> = Vec::new();
    for entry in &p.allow {
        rows.push((allow_badge(), entry.clone(), style::dim("fixed")));
    }
    for entry in &p.deny {
        rows.push((deny_badge(), entry.clone(), style::dim("fixed")));
    }
    for r in remembered {
        let badge = if r.allow { allow_badge() } else { deny_badge() };
        rows.push((
            badge,
            r.program.display().to_string(),
            style::dim("remembered (always)"),
        ));
    }
    for t in temporary {
        let badge = if t.allow { allow_badge() } else { deny_badge() };
        rows.push((
            badge,
            t.program.display().to_string(),
            style::dim(&format!("temporary · {} left", fmt_secs(t.remaining_secs))),
        ));
    }

    let width = rows
        .iter()
        .map(|(_, prog, _)| prog.len())
        .max()
        .unwrap_or(0);
    for (badge, prog, note) in &rows {
        let _ = writeln!(out, "  {badge}  {prog:<width$}  {note}");
    }
    for s in pauses {
        let _ = writeln!(
            out,
            "  {}  {}",
            style::yellow("⏸ paused"),
            style::dim(&format!(
                "for {} · {} left",
                pause_scope(s.uid),
                fmt_secs(s.remaining_secs)
            )),
        );
    }
    if rows.is_empty() && pauses.is_empty() {
        let _ = writeln!(out, "  {}", style::dim("(no rules)"));
    }
    out
}

/// The live banner shown atop `status`: wordmark + daemon version, an active
/// indicator with the guarded-path count and config dir, and a one-line tip.
/// The glyph/color/bold/dim styling goes through `style`, which is a no-op
/// (plain text) off a TTY — the literal spacing between segments is fixed so
/// the plain-text form has stable, fixed spacing.
pub(super) fn render_banner_live(version: &str, paths: usize, config: &std::path::Path) -> String {
    let noun = if paths == 1 { "path" } else { "paths" };
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{}  {}          {}",
        style::bold("▉ fsnitch"),
        style::dim("· file access guard"),
        style::bold(&format!("fsnitchd {version}")),
    );
    let _ = writeln!(
        out,
        "{} active · {paths} {noun} guarded · config {}",
        style::green("●"),
        config.display(),
    );
    let _ = writeln!(
        out,
        "  {}",
        style::dim("tip: `fsnitch help` for commands · `fsnitch` alone = this view"),
    );
    out
}

/// The "Quick actions" block shown at the bottom of `status`.
pub(super) fn render_quick_actions() -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{}", style::bold("Quick actions"));
    let _ = writeln!(
        out,
        "  fsnitch protect <path>               guard a new file or directory"
    );
    let _ = writeln!(
        out,
        "  fsnitch protect <path> --program P   guard it and allow one program"
    );
    let _ = writeln!(
        out,
        "  fsnitch preset apply <pack>          guard a curated set (see `preset list`)"
    );
    let _ = writeln!(
        out,
        "  fsnitch log --follow                 watch access events live"
    );
    out
}

/// Verdicts whose path is not in `known` (no longer protected). Should not
/// happen thanks to unprotect/forget cleanup, but must never be silently
/// dropped. Returns None when every verdict belongs to a known path.
pub(super) fn render_orphan_verdicts(
    known: &[&str],
    remembered: &[RememberedInfo],
    temporary: &[TemporaryInfo],
    pauses: &[PauseInfo],
) -> Option<String> {
    let is_orphan = |path: &str| !known.contains(&path);
    let mut out = String::new();
    for r in remembered.iter().filter(|r| is_orphan(&r.path)) {
        let badge = if r.allow { allow_badge() } else { deny_badge() };
        let _ = writeln!(
            out,
            "  {}  {}  {}",
            badge,
            r.program.display(),
            style::dim(&format!("on {} · remembered (always)", r.path)),
        );
    }
    for t in temporary.iter().filter(|t| is_orphan(&t.path)) {
        let badge = if t.allow { allow_badge() } else { deny_badge() };
        let _ = writeln!(
            out,
            "  {}  {}  {}",
            badge,
            t.program.display(),
            style::dim(&format!(
                "on {} · temporary · {} left",
                t.path,
                fmt_secs(t.remaining_secs)
            )),
        );
    }
    for s in pauses.iter().filter(|s| is_orphan(&s.path)) {
        let _ = writeln!(
            out,
            "  {}  {}  {}",
            style::yellow("⏸"),
            s.path,
            style::dim(&format!(
                "paused for {} · {} left",
                pause_scope(s.uid),
                fmt_secs(s.remaining_secs)
            )),
        );
    }
    if out.is_empty() {
        None
    } else {
        Some(format!(
            "{}\n{out}",
            style::dim("verdicts on unprotected paths")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn summary() -> PathSummary {
        PathSummary {
            path: "/home/luke/vaults".into(),
            mode: "ask".into(),
            source: "cli".into(),
            allow: vec!["/usr/bin/keepassxc".into()],
            deny: vec!["/usr/bin/curl".into()],
        }
    }

    #[test]
    fn section_orders_and_aligns_entries() {
        let remembered = RememberedInfo {
            path: "/home/luke/vaults".into(),
            program: PathBuf::from("/usr/bin/borg"),
            allow: true,
        };
        let temporary = TemporaryInfo {
            path: "/home/luke/vaults".into(),
            program: PathBuf::from("/usr/bin/cat"),
            allow: false,
            remaining_secs: 723,
        };
        let pause = PauseInfo {
            path: "/home/luke/vaults".into(),
            uid: Some(1000),
            remaining_secs: 41,
        };
        let s = render_path_section(&summary(), &[&remembered], &[&temporary], &[&pause]);
        let lines: Vec<&str> = s.lines().collect();
        // Order: header, fixed allow, fixed deny, remembered, temporary, pause.
        // Program column padded to the widest program (18 = len of keepassxc path).
        assert_eq!(lines[0], "/home/luke/vaults  ask · cli");
        assert_eq!(lines[1], "  allow  /usr/bin/keepassxc  fixed");
        assert_eq!(lines[2], "  deny   /usr/bin/curl       fixed");
        assert_eq!(lines[3], "  allow  /usr/bin/borg       remembered (always)");
        assert_eq!(
            lines[4],
            "  deny   /usr/bin/cat        temporary · 12m 3s left"
        );
        assert_eq!(lines[5], "  ⏸ paused  for uid 1000 · 41s left");
        assert_eq!(lines.len(), 6);
    }

    #[test]
    fn empty_section_prints_no_rules() {
        let p = PathSummary {
            path: "/home/luke/.mozilla".into(),
            mode: "watch".into(),
            source: "file".into(),
            allow: vec![],
            deny: vec![],
        };
        let s = render_path_section(&p, &[], &[], &[]);
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines[0], "/home/luke/.mozilla  watch · file");
        assert_eq!(lines[1], "  (no rules)");
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn global_pause_scope_is_everyone() {
        let pause = PauseInfo {
            path: "/home/luke/vaults".into(),
            uid: None,
            remaining_secs: 300,
        };
        let s = render_path_section(&summary(), &[], &[], &[&pause]);
        assert!(s.contains("⏸ paused  for everyone · 5m 0s left"));
    }

    #[test]
    fn verdicts_for_filters_by_path() {
        let remembered = vec![
            RememberedInfo {
                path: "/a".into(),
                program: PathBuf::from("/p"),
                allow: true,
            },
            RememberedInfo {
                path: "/b".into(),
                program: PathBuf::from("/p"),
                allow: true,
            },
        ];
        let temporary: Vec<TemporaryInfo> = vec![];
        let pauses = vec![PauseInfo {
            path: "/b".into(),
            uid: None,
            remaining_secs: 1,
        }];
        let (rem, tmp, pse) = verdicts_for("/b", &remembered, &temporary, &pauses);
        assert_eq!(rem.len(), 1);
        assert!(tmp.is_empty());
        assert_eq!(pse.len(), 1);
    }

    #[test]
    fn orphan_verdicts_render_only_unknown_paths() {
        let remembered = vec![RememberedInfo {
            path: "/gone".into(),
            program: PathBuf::from("/usr/bin/x"),
            allow: false,
        }];
        let temporary = vec![TemporaryInfo {
            path: "/home/luke/vaults".into(), // known -> not an orphan
            program: PathBuf::from("/usr/bin/cat"),
            allow: true,
            remaining_secs: 5,
        }];
        let pauses: Vec<PauseInfo> = vec![];
        let known = ["/home/luke/vaults"];
        let block = render_orphan_verdicts(&known, &remembered, &temporary, &pauses).unwrap();
        assert!(block.starts_with("verdicts on unprotected paths"));
        assert!(block.contains("/usr/bin/x"));
        assert!(block.contains("on /gone · remembered (always)"));
        assert!(!block.contains("/usr/bin/cat"));
    }

    #[test]
    fn no_orphans_yields_none() {
        let known = ["/a"];
        let remembered = vec![RememberedInfo {
            path: "/a".into(),
            program: PathBuf::from("/p"),
            allow: true,
        }];
        assert!(render_orphan_verdicts(&known, &remembered, &[], &[]).is_none());
    }

    #[test]
    fn banner_live_contains_expected_fields() {
        let cfg = PathBuf::from("/etc/fsnitch");
        let s = render_banner_live("0.1.0", 3, &cfg);
        assert!(s.contains("fsnitchd 0.1.0"), "missing version: {s}");
        assert!(s.contains("active"), "missing active: {s}");
        assert!(s.contains("3 paths"), "missing path count: {s}");
        assert!(s.contains("/etc/fsnitch"), "missing config dir: {s}");
        assert!(s.contains("fsnitch help"), "missing help tip: {s}");
    }

    #[test]
    fn banner_live_pluralizes_path_count() {
        let cfg = PathBuf::from("/etc/fsnitch");
        let one = render_banner_live("0.1.0", 1, &cfg);
        assert!(one.contains("1 path "), "should say '1 path', got: {one}");
        assert!(!one.contains("1 paths"), "should not pluralize: {one}");

        let three = render_banner_live("0.1.0", 3, &cfg);
        assert!(three.contains("3 paths"), "should pluralize: {three}");
    }

    #[test]
    fn quick_actions_lists_examples() {
        let s = render_quick_actions();
        assert!(s.contains("fsnitch protect <path>"), "got: {s}");
        assert!(s.contains("fsnitch log --follow"), "got: {s}");
    }
}
