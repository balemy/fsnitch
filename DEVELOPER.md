# Developing fsnitch

For the design and how the pieces fit together, see
[ARCHITECTURE.md](ARCHITECTURE.md). This is the practical build/test guide.

## Prerequisites

- A recent Rust toolchain (edition 2021).
- For the hardened build only: `libsystemd`, `gtk4`, `gtk4-layer-shell`,
  `libadwaita` (the GUI).
  On Arch: `sudo pacman -S --needed rust systemd gtk4 gtk4-layer-shell libadwaita`.

## Build

```sh
cargo build --workspace            # everything, debug
cargo build --release -p fsnitchd  # just the daemon, release
```

The daemon has one feature flag, `session-hardening` (off by default), which
links `libsystemd` and enforces the active-graphical-session check for agents:

```sh
cargo build -p fsnitchd --features session-hardening
```

The default (lightweight) build has no `libsystemd` dependency at all, which
keeps it broadly buildable on headless boxes.

## Run it locally without installing

```sh
./tools/dev-run.sh
```

Builds the workspace, generates a throwaway config under `./dev/` (gitignored),
starts the daemon (via `sudo`, for fanotify) and the agent (as you), and streams
their logs. Trigger a prompt from another terminal with
`cat ./dev/protected/secret.txt`; `Ctrl-C` tears both down. Wipe state with
`rm -rf ./dev`.

To install onto the local system instead, use `./tools/install-local.sh` (see
[INSTALLATION.md](INSTALLATION.md)).

## Tests

```sh
cargo test --workspace        # unit tests, no root needed
cargo clippy --workspace --all-targets
cargo fmt --all -- --check
```

The end-to-end scripts drive a real daemon and **must run as root**:

```sh
sudo tests/e2e.sh         # enforcement: unlisted denied, allowlisted allowed
sudo tests/e2e-prompt.sh  # interactive prompt via the headless mock agent
sudo tests/e2e-hash.sh    # sha256 pin: correct pin allows, wrong pin denies
sudo tests/e2e-cli.sh     # protect/show/unprotect, precedence, live marking
sudo tests/e2e-status.sh  # read-only status socket: readable, uid-filtered, refuses changes
```

Run them via `sudo` from your normal user — `e2e-prompt.sh` uses `$SUDO_UID`
and `setpriv` to run the agent and subject as a non-root uid, matching the real
case. The graphical overlay itself can't be checked headlessly; run
`./tools/dev-run.sh` in a graphical session to exercise it.

### Checking the GUI by hand

`fsnitch-gui`'s logic (health, merging, command lines) is unit-tested in
`fsnitch-gui/src/model.rs`; the widgets are checked by hand. With
`./tools/dev-run.sh` running, start the GUI as printed there and walk through:

- tray icon green; stop the agent → yellow with *Start agent*; stop the
  daemon → red and the window greys out
- protect a folder (mode Ask) → it appears in the sidebar
- add a program (allow, pinned) → row shows *sha256* · *fixed*; add one for
  15 min → *N min left*; deny one → *Denied*
- trigger a prompt and answer *Always* → row shows *remembered*; trash it →
  it prompts again
- pause 15 min → sidebar badge + yellow tray; *Resume* clears it
- cancel the pkexec dialog → toast *Cancelled*, the view snaps back
- a path from `paths.d` is read-only; *Log* lists your recent accesses

## Layout

```
fsnitch-core/   # config, policy matching, protocol, verdict stores (pure)
fsnitchd/       # root daemon: fanotify, engine, control socket, event log
fsnitch-cli/    # the `fsnitch` command
fsnitch-agent/  # graphical prompt agent
fsnitch-gui/    # tray icon + management window (libadwaita)
fsnitch-mock-agent/  # scripted agent for tests
packaging/      # systemd units, desktop file, icons, default config, AUR PKGBUILDs
tools/          # dev-run.sh, install-local.sh
tests/          # root e2e scripts
```

## Contributing

Keep changes focused and match the surrounding style. Before sending a change,
make sure `cargo test --workspace`, `cargo clippy --workspace --all-targets`,
and `cargo fmt --all -- --check` are clean, and run the relevant e2e script if
you touched enforcement, the CLI, or the protocol. Security-sensitive reports:
see [SECURITY.md](SECURITY.md).
