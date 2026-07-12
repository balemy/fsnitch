# fsnitch

Interactive file access guard for the Linux desktop — the OpenSnitch idea,
applied to files. A root daemon gates `open()` on paths you declare sensitive
(password vaults, browser profiles, wallets, SSH keys). Allowlisted programs
pass; everything else is denied or triggers an interactive prompt. A protected
**path** covers itself and everything beneath it, and when paths nest the most
specific (longest) one wins.

**Status: prototype, approaching a 1.0 release.** The enforcing daemon, the
interactive prompt agent (`fsnitch-agent`), `sha256` hash pinning, the
`ufw`-style rule CLI, verdict visibility + snooze, and the path-centric model
all work end to end. See `SECURITY.md` for the threat model and its honest
limitations: no protection against root malware, confused-deputy, or code
injection into allowlisted programs — this stops the common infostealer
pattern, it is not a sandbox.

The model in one paragraph: a protected **path** carries a **policy** — a
**mode** (`block` denies silently, `ask` prompts, `watch` allows but logs) plus
a fixed list of **programs** to always `allow`/`deny`. On top of that sit
dynamic verdicts: **remembered** "always" answers, **temporary** timed answers,
and a **paused** path where everything passes for a while. Dynamic state attaches
to the *specific* path that governs an access, so when paths nest, pausing (or
remembering a verdict on) `/a` does not affect a separately-protected `/a/sub` —
each protected path is independent.

What the daemon does today (features land per milestone; all now use the
path-centric model):

- **`mode = "ask"` works** with a registered agent: the daemon asks the agent
  for a verdict; `allow/deny once` is cached (60 s), `allow/deny forever` is
  stored in `<config-dir>/remembered.toml`. With no agent or no answer within
  `timeout` seconds, it falls back to `on_no_agent` / `on_no_answer`
  (default deny). The graphical agent `fsnitch-agent` shows the dialog and
  desktop notifications; `fsnitch-mock-agent` remains for headless tests.
- **`sha256` hash pinning works**: pin an allow/deny entry to a program's
  hash (`{ program = "/usr/bin/borg", sha256 = "…" }`). The pin is verified
  against the program's content hashed at config load; at event time only a
  `stat` freshness check runs (no file read on the hot path — that would
  deadlock), so a pinned program that changes after load fails its pin
  (fail-safe) until you reload. The daemon auto-allows its own pid so
  reload-time hashing can't self-deadlock.
- **Paths from the CLI work**: `sudo fsnitch protect <path>` creates a
  CLI-managed path (default mode `ask`; `--mode block|ask|watch`) and is
  **additive** — protecting an already-managed path merges into it instead of
  failing. Repeatable `--program <program>` (with optional `--pin
  <sha256|auto>` for hash pinning) allows a program, whether on the initial
  `protect` or added later by re-`protect`-ing the same path; `--mode` on a
  re-protect only changes the mode when explicitly given. It takes effect
  immediately — the daemon marks new filesystems at runtime. `sudo fsnitch
  status` shows all protected paths (`cli` vs `file` source);
  `sudo fsnitch unprotect <path>` removes a whole CLI-managed path
  (hand-written policies are never touched), and
  `sudo fsnitch unprotect <path> --program <program>` removes just that one
  fixed allow entry instead (the inverse of `protect --program` — no need to
  unprotect and rebuild). There is no CLI `deny` — hand-write a `deny` entry in
  a drop-in file if you need one. Managed paths live in
  `<config-dir>/paths.d/managed.toml`. No tray icon / prompt history — later.
- **Verdicts are visible and manageable**: plain `fsnitch` = `status`,
  which prints one section per protected path — the path with its mode/source,
  then its fixed allow/deny entries and any live verdicts (remembered "always"
  answers, temporary timed answers with remaining time, and pause state)
  beneath it; `fsnitch show <path>` prints that same section for a single path.
  `fsnitch pause <path> [15m]` pauses a path for a while (every program passes;
  memory-only, gone on restart), `fsnitch resume [<path>]` re-arms, and
  `fsnitch forget <path> [--program <program>]` drops temporary and remembered
  verdicts. `fsnitch protect <path> --program <program> --for 15m` grants a
  *temporary* timed allow from the CLI (an in-memory verdict that shows in
  `status` and expires on its own) instead of a permanent entry; it applies to
  `ask`-mode access only and errors over a deny/block path (`--for` and
  `--pin` are mutually exclusive). The prompt dialog carries the same durations: a `Just now / 15 min
  / 1 hour / Always` selector drives Deny/Allow, plus a "pause the whole path"
  row (suspends the path for your user). CLI output is TTY-aware (color +
  aligned columns when interactive, plain when piped).
- **No watchdog** (`Restart=always` covers crashes, not hangs) — M3.

The control socket is world-connectable (mode 0666); `SO_PEERCRED` assigns
roles — uid 0 gets the control plane (status, policy management, reload, log),
any other uid may only register as that user's prompt agent.

**Agent trust.** The peer that registers as the prompt agent is pinned via
`SO_PEERPIDFD` (falling back to the `SO_PEERCRED` pid on kernels older than
6.5, with a warning) so the pid can't be reused out from under the check
between verification and use. Every build also verifies the peer is running the
configured `agent` binary.

For stricter hardening, the daemon can enforce that the agent runs *inside the
same uid's active graphical logind session* (Wayland/X11/Mir; a `tty` or
background session doesn't count). This requires building with `--features
session-hardening` (which links libsystemd). The default lightweight build
(no libsystemd) skips the session check — set `require_agent_session = false`
for headless/dev/CI setups (see `tools/dev-run.sh` and `tests/e2e-prompt.sh`).
On a default build, `require_agent_session = true` is logged as a warning at
startup and has no effect; rebuild with `--features session-hardening` to
enforce it. The Arch/AUR package (see Install below) builds with this feature
enabled.

Honest limit: a human still answers the dialog either way — session-binding
narrows *who may register* as the agent to the live graphical seat, it does
not prove the agent process itself isn't malware.

## Install

To actually run fsnitch day-to-day, see **[docs/INSTALL.md](docs/INSTALL.md)**:
Arch/AUR (`fsnitch` release or `fsnitch-git` HEAD), a manual build for the
full hardened desktop experience on other distros, or a manual lightweight
build for headless boxes with no GTK/agent. All three end up with the same
`/etc/fsnitch/config.toml` and CLI shown throughout this README.

The rest of this section — "Try it" and "Development" below — is the
build-from-source path for hacking on fsnitch itself, not the recommended way
to install it.

## Try it (build from source)

Build the daemon and CLI first; the binaries land in `./target/debug/`.

```sh
cargo build --workspace
sudo mkdir -p /etc/fsnitch/paths.d
sudo tee /etc/fsnitch/paths.d/10-vaults.toml <<'EOF'
[[path]]
path  = "/home/YOU/vaults"
mode  = "block"
allow = [{ program = "/usr/bin/keepassxc" }]
EOF
sudo ./target/debug/fsnitchd            # terminal 1
sudo ./target/debug/fsnitch status      # terminal 2
sudo ./target/debug/fsnitch log --follow
```

Companion hardening: set `kernel.yama.ptrace_scope = 1`.

Symlinks: protected paths are canonicalized at load, so a path written through
a symlinked directory (e.g. `/home/YOU/...` when `/home` is a symlink) resolves
to and matches its real location automatically — you do not have to hand-resolve
symlinks in your config.

Reload caveat: `fsnitch reload` re-reads policies but does not re-mark
filesystems, so adding a path on a filesystem that had no protected paths
before requires a daemon restart (the `protect` CLI marks new filesystems at
runtime, so it is not subject to this caveat).

### Preset packs

Instead of hand-protecting each well-known location, apply a curated pack:

    fsnitch preset list                       # see the packs and what they cover
    sudo fsnitch preset apply browsers        # protect existing browser profiles
    sudo fsnitch preset apply ssh --dry-run   # preview, change nothing

`apply` protects every path in the pack that exists on your machine (skipping
the rest) in `ask` mode, so the first legitimate access prompts and you build
the allowlist by answering "always allow". Packs expand `~` against the `sudo`
user's home (override with `--user`); `--mode` overrides the default. `list`
and `apply --dry-run` need neither root nor a running daemon. Available packs:
`browsers`, `ssh`, `gnupg`, `password-managers`, `crypto-wallets`,
`dev-credentials`.

## The prompt agent

`fsnitch-agent` is the graphical agent: when an `ask`-mode path can't decide an
access, a dialog pops up (process, file, path, countdown). You pick **how long**
the decision lasts — `Just now` · `15 min` · `1 hour` · `Always` — then hit the
big **Deny** or **Allow**; a separate row can **pause the whole path** (every
program) for a while. "Always" verdicts are remembered in `remembered.toml`,
timed ones live in the daemon's memory. It also shows the daemon's FYI events as
desktop notifications.

On wlroots compositors (Sway, Hyprland, KWin) the prompt is a **full-screen
`wlr-layer-shell` overlay** (GTK4): dimmed backdrop, centered card, guaranteed on
top, with keyboard shortcuts — `Esc`/`d` deny and `a` allow (at the selected
duration), `D`/`A` always deny/allow. With multiple monitors **every output is
dimmed**; the interactive card appears on the largest one. Where layer-shell is
unavailable
(e.g. GNOME) it falls back to a normal centered window. Needs the system `gtk4`
and `gtk4-layer-shell` libraries. Build it, install it where the
daemon's `agent` expects (default `/usr/bin/fsnitch-agent`), and run it in
your graphical session:

```sh
cargo build --release -p fsnitch-agent
sudo install -Dm755 target/release/fsnitch-agent /usr/bin/fsnitch-agent
install -Dm644 packaging/fsnitch-agent.service ~/.config/systemd/user/fsnitch-agent.service
systemctl --user enable --now fsnitch-agent
```

For a quick manual test without installing, point the daemon's `agent` at the
built binary and run the agent against the running daemon in your session — or
just use the dev-run below.

## Development — run it locally

For a throwaway local run without installing anything:

```sh
./tools/dev-run.sh
```

It builds the workspace, generates a config under `./dev/` (gitignored), starts
the daemon (via `sudo`, for fanotify) and the agent (as you, in your graphical
session), and streams their logs. In another terminal, trigger a prompt:

```sh
cat ./dev/protected/secret.txt
```

The dialog pops up; choose Allow/Deny (once/always). `Ctrl-C` in the dev-run
terminal stops both. Reset remembered "always" verdicts with
`rm ./dev/etc/remembered.toml`, or wipe everything with `rm -rf ./dev`.

## Tests

- `cargo test --workspace` — unit tests, no root needed.
- `sudo tests/e2e.sh` — end-to-end enforcement check (root).
- `sudo tests/e2e-prompt.sh` — end-to-end interactive-prompt check with the
  headless mock agent (root; run via `sudo` from a normal user).
- `sudo tests/e2e-hash.sh` — end-to-end sha256 pin check: correct pin allows,
  wrong pin (after reload) denies (root).
- `sudo tests/e2e-cli.sh` — end-to-end `protect`/`show`/`unprotect` check,
  including most-specific-path precedence, additive re-protect (merge, not
  fail), and that a path takes effect without a daemon restart (root).
