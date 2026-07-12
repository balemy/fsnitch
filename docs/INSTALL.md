# Installing fsnitch

Three ways to get fsnitch running, in order of preference: Arch/AUR, a manual
build with the full hardened desktop experience, and a manual lightweight
build for headless/server boxes. All three end with the same on-disk config
(`/etc/fsnitch/config.toml`) and CLI (`fsnitch protect`, `fsnitch status`, …)
described in the [README](../README.md).

## Arch (AUR)

Two packages, built from `packaging/aur/`:

- **`fsnitch`** — release build, pinned to the `v1.0.0` git tag.
  **Not usable yet** — the tag doesn't exist until 1.0 ships. Until then, use
  `fsnitch-git` below.
- **`fsnitch-git`** — builds from the repo's HEAD. This is the one to use
  pre-1.0.

Both build `fsnitchd` with `--features session-hardening` (so the daemon
links `libsystemd` and enforces the active-graphical-session check) and
install all three binaries, both systemd units, the default config, the
LICENSE, and the README.

With an AUR helper:

```sh
paru -S fsnitch-git   # or: yay -S fsnitch-git
```

Or manually:

```sh
cd packaging/aur/fsnitch-git
makepkg -si
```

Then enable the daemon and, in your graphical session, the prompt agent:

```sh
sudo systemctl enable --now fsnitchd
systemctl --user enable --now fsnitch-agent
```

Protect some paths:

```sh
sudo fsnitch protect /home/YOU/vaults --program /usr/bin/keepassxc
sudo fsnitch preset apply browsers      # or: fsnitch preset list
```

Recommended companion hardening:

```sh
sudo sysctl kernel.yama.ptrace_scope=1
```

## Manual, hardened desktop (other distros)

Same feature set as the AUR package — full session-hardening, graphical
prompt agent — for distros without an fsnitch package. Needs `libsystemd`,
`gtk4`, and `gtk4-layer-shell` installed.

Build:

```sh
cargo build --release -p fsnitchd --features session-hardening
cargo build --release -p fsnitch-cli -p fsnitch-agent
```

Install the three binaries:

```sh
sudo install -Dm755 target/release/fsnitchd      /usr/bin/fsnitchd
sudo install -Dm755 target/release/fsnitch       /usr/bin/fsnitch
sudo install -Dm755 target/release/fsnitch-agent /usr/bin/fsnitch-agent
```

Install the units and the default config:

```sh
sudo install -Dm644 packaging/fsnitchd.service      /usr/lib/systemd/system/fsnitchd.service
sudo install -Dm644 packaging/fsnitch-agent.service /usr/lib/systemd/user/fsnitch-agent.service
sudo install -Dm644 packaging/config.toml           /etc/fsnitch/config.toml
```

Enable and protect paths as above:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now fsnitchd
systemctl --user daemon-reload
systemctl --user enable --now fsnitch-agent
sudo fsnitch protect /home/YOU/vaults --program /usr/bin/keepassxc
```

## Manual, lightweight / headless

For servers, CI, or anywhere without a graphical session — no `libsystemd`,
no GTK, and **no prompt agent**. Only the daemon and CLI are built:

```sh
cargo build --release -p fsnitchd -p fsnitch-cli
```

**Deliberately not built here:** `session-hardening` is off (no libsystemd
link, no active-session check) and `fsnitch-agent` is not built at all, so
there is nothing to answer interactive prompts. Use `block` or `watch` mode
for protected paths instead of `ask`, or run `ask` mode with
`on_no_agent = "deny"` (the default) knowing it will always deny rather than
show a dialog. Set `require_agent_session = false` in the config — with no
`session-hardening` feature the check is a no-op anyway, and the daemon logs a
startup warning if you leave it `true` on this kind of build.

Install just the two binaries:

```sh
sudo install -Dm755 target/release/fsnitchd /usr/bin/fsnitchd
sudo install -Dm755 target/release/fsnitch  /usr/bin/fsnitch
```

From here, install the unit and config, and protect paths, the same way as
the hardened-desktop path above (skip the agent binary and its unit) —
just remember `mode = "ask"` won't have anyone to prompt.
