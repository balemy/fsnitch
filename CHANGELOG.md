# Changelog

## 0.6.0 — Unreleased

- Added: `fsnitch-gui`, a tray icon that shows at a glance whether protection
  is fully active (green: daemon + your prompt agent; yellow: no agent, a
  paused path or degraded move protection; red: daemon unreachable), plus a
  libadwaita management window: protect/unprotect paths, change the mode,
  pause/resume, allow or deny programs (optionally pinned or timed), forget
  remembered answers, and browse your recent events. Changes run through
  `pkexec fsnitch …`. Ships a systemd user unit, a desktop file and icons.
- Added: a read-only status socket `/run/fsnitch/status.sock` for
  unprivileged readers (`status`, `list`, `verdicts`, `events`); per-user data
  is filtered to the caller's uid and every mutating request is refused.
- Added: `Status` reports `agent_connected`; `fsnitch status` warns when no
  prompt agent is connected.
- Added: `fsnitch protect <path> --deny <program>` adds a fixed deny entry.
- Added: same-filesystem move protection. The daemon indexes the `(dev, ino)`
  of every regular file under a protected root, so a secret renamed out of its
  root and read elsewhere on the same filesystem is still gated (previously a
  `mv` out of the root bypassed the policy). Hardlinks are covered too. The
  index is scanned at load/reload and kept fresh by an inotify watcher, so
  files created under a root after startup are tracked as well.
- Added: `general.max_tracked_inodes` (default 1000000) caps the inode index.
  A root that exceeds it keeps path protection but loses move protection, logs
  a warning, and is listed by `fsnitch status`.
- Fixed: stale inode-index entries no longer misattribute unrelated files to a
  protected root (seen as bogus prompts naming e.g. a browser's own cache
  files). Three leaks let entries of deleted files survive, so their recycled
  inode numbers later matched new files: a directory renamed within a root
  double-counted the links of every file inside (blocking their eviction
  forever), a file indexed by both the seed scan and a racing create event was
  double-counted the same way, and an inotify queue overflow silently dropped
  delete events (the watcher now rescans its roots instead). As a backstop, the
  index also records each file's birth time and the inode-identity fallback
  only matches when the accessed file's birth time agrees — a recycled inode
  number can no longer match at all on filesystems that report btime.
- Fixed: with `session-hardening`, the prompt agent can now run as a systemd
  user service. The active-graphical-session check binds to the user's logind
  seat (via `sd_uid_get_display`) instead of the agent process's own session,
  which a user-manager service is never part of.
- Fixed: a second `fsnitchd` no longer silently unlinks the control socket of
  a running daemon. Startup now probes the socket path first and refuses to
  start while another daemon still answers on it; only a stale socket file
  left by a dead daemon is removed and rebound. (Previously a transient second
  instance — e.g. an e2e test — left the running daemon serving an orphaned
  socket inode, and every new CLI connection got "connection refused".)
- Fixed: the e2e test scripts start their daemon on a private socket inside
  the test work dir instead of `/run/fsnitch/fsnitchd.sock`, so running them
  with sudo no longer disturbs an installed daemon. `fsnitch-mock-agent`
  gained a `--socket` flag for this.
- Enh: `tools/install-local.sh` also restarts a running `fsnitch-agent` user
  service after upgrading, so the agent reconnects to the new daemon
  immediately instead of erroring until manually restarted.

## 0.5.0 — 2026-07-12

First release.

- Root daemon gating file `open()` via fanotify permission events, with
  per-path policies: `block` (deny silently), `ask` (prompt), and `watch`
  (allow but log). Nested paths resolve to the most specific match.
- Program allowlists with optional `sha256` pinning; a pinned program that
  changes after load fails safe until reload.
- Graphical prompt agent: a full-screen `wlr-layer-shell` overlay on wlroots
  (Sway/Hyprland/KWin), windowed fallback elsewhere. Once / timed / remembered
  verdicts, plus desktop notifications.
- `fsnitch` CLI: `protect` / `unprotect`, `status` / `show`, `pause` /
  `resume` / `forget`, curated `preset` packs, `log`, and `reload`.
- Root-only control plane (`SO_PEERCRED`). The prompt agent is pinned via
  `SO_PEERPIDFD` and verified against the configured binary; an optional
  active-graphical-session check is available behind the `session-hardening`
  build feature.
