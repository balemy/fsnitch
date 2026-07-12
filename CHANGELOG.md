# Changelog

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
