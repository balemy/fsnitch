# Changelog

## 0.6.0 — Unreleased

- Added: same-filesystem move protection. The daemon indexes the `(dev, ino)`
  of every regular file under a protected root, so a secret renamed out of its
  root and read elsewhere on the same filesystem is still gated (previously a
  `mv` out of the root bypassed the policy). Hardlinks are covered too.
- Added: `general.max_tracked_inodes` (default 1000000) caps the inode index.
  A root that exceeds it keeps path protection but loses move protection, logs
  a warning, and is listed by `fsnitch status`.
- Fixed: with `session-hardening`, the prompt agent can now run as a systemd
  user service. The active-graphical-session check binds to the user's logind
  seat (via `sd_uid_get_display`) instead of the agent process's own session,
  which a user-manager service is never part of.

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
