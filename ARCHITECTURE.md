# Architecture

## The core idea

fsnitch uses **fanotify permission events** (`FAN_OPEN_PERM`). It's the one
Linux mechanism where the kernel *pauses* a file open while userspace decides
whether to allow it — which is exactly what an interactive prompt needs. A BPF
LSM hook can't sleep waiting for a human, so it's only interesting later as a
fail-closed, non-interactive backend behind the same abstraction.

The daemon marks the filesystems that hold protected paths and receives an
event for every open on them. The overwhelming majority of opens are on
unprotected paths and are allowed with a cheap prefix check; only opens under a
protected path go through the policy engine.

## Components

| Crate | Runs as | Purpose |
|---|---|---|
| `fsnitch-core` | library | config model, policy matching, IPC protocol, verdict stores — pure, no I/O, fully unit-tested |
| `fsnitchd` | root (systemd system service) | fanotify backend, policy engine, event log, control socket |
| `fsnitch` (`fsnitch-cli`) | user / root CLI | protect/unprotect, status, presets, log, reload |
| `fsnitch-agent` | user (systemd user service) | the graphical prompt + desktop notifications |
| `fsnitch-gui` | user (systemd user service) | tray icon showing whether daemon + agent are up, and a management window |
| `fsnitch-mock-agent` | test only | headless agent that scripts verdicts for the e2e tests |

The enforcement mechanism sits behind an `EnforcementBackend` trait in the
daemon (today: `FanotifyBackend`), which keeps the policy engine independent of
the kernel mechanism.

## How a decision is made

1. A process calls `open()` on a marked filesystem; the kernel pauses the call
   and hands the daemon a permission event (target fd + subject pid/uid).
2. The daemon resolves the real target path via `/proc/self/fd/<fd>` and does a
   longest-prefix match against the protected paths. No match → allow
   immediately (the hot path). It also always allows its own pid, so reload-time
   work can't deadlock against its own policy.
3. On a match, the most specific path's policy decides. A program in the path's
   `deny` list is refused; one in `allow` passes; otherwise the `mode`
   (`block` / `ask` / `watch`) applies. Every decision can be logged as a JSON
   line.

Subject identity is the symlink-resolved `/proc/<pid>/exe`, optionally pinned to
a `sha256`. Pins are computed when the config loads; at event time only a
`stat` freshness check runs (no file read on the blocking hot path), so a binary
that changes after load fails its pin — fail-safe — until the next reload.

## The prompt flow (`ask` mode)

When an `ask`-mode open can't be decided outright, the daemon **parks** the
blocked event and sends a prompt to the registered agent for that uid. The
agent replies with a verdict and a duration:

- *once* answers are cached briefly (in memory);
- *timed* answers (15 min / 1 hour) live in the daemon's memory;
- *always* answers are written to `<config-dir>/remembered.toml`.

If no agent is registered, or nobody answers within `timeout`, the daemon
applies `on_no_agent` / `on_no_answer` (default deny). A background reaper
answers prompts that time out so a blocked open never hangs forever.

## The control socket and agent trust

There's one Unix socket, `/run/fsnitch/fsnitchd.sock`, world-connectable
(mode 0666), speaking JSON lines. The daemon reads the kernel-supplied peer
credentials (`SO_PEERCRED`) to assign a role: **uid 0** gets the control plane
(policy management, status, reload, log); **any other uid** may only register as
*that user's* prompt agent.

The registering agent is pinned via `SO_PEERPIDFD` (falling back to the
`SO_PEERCRED` pid on kernels < 6.5) so a reused pid can't be swapped in, and the
daemon verifies the peer is running the configured `agent` binary. With
`--features session-hardening` it additionally requires the agent's uid to have
an active graphical logind session. See [SECURITY.md](SECURITY.md) for what these
checks do and don't prove.

Next to it, `/run/fsnitch/status.sock` (also 0666) is a **read-only** socket for
unprivileged readers such as the tray. It answers `status` (including whether
the *caller's* agent is connected), `list`, `verdicts` and `events` (the tail of
the event log, filtered to the caller's uid unless the caller is root) and
refuses everything else.

## The GUI

`fsnitch-gui` polls `status.sock` every few seconds. A StatusNotifierItem tray
icon (waybar, KDE, GNOME with the AppIndicator extension) shows green when the
daemon is reachable and the user's agent is connected, yellow when protection is
limited (no agent, a paused path, a root over the inode cap), and red when the
daemon is unreachable. Clicking it opens a libadwaita window listing every
protected path with its mode, pause state and one merged program list (fixed
entries, remembered and temporary verdicts), plus the user's recent events.
The GUI never talks to the control plane directly: every change runs the CLI as
`pkexec fsnitch …`, so it is authenticated by polkit and goes through the same
code path as a manual `sudo fsnitch`.

## The agent

`fsnitch-agent` connects to the socket and registers. It stays idle until a
prompt arrives, then renders it. On wlroots compositors (Sway, Hyprland, KWin)
the prompt is a full-screen `wlr-layer-shell` overlay (GTK4) — dimmed backdrop,
centered card, always on top; every output is dimmed on multi-monitor setups.
Where layer-shell isn't available (e.g. GNOME) it falls back to a normal
centered window. Daemon "FYI" events show up as desktop notifications.
