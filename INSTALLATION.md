# Installing fsnitch

Two supported ways to install: build from this checkout (recommended for now),
or grab a prebuilt **binary package** from the GitHub Releases page. There's no
AUR package published yet.

Whichever you pick, you end up with the same binaries, systemd units, and
`/etc/fsnitch/config.toml`. See [USAGE.md](USAGE.md) for what to do next and
[CONFIGURATION.md](CONFIGURATION.md) for the config reference.

## Quick local install (from source)

On your own machine, one script builds and installs everything — the hardened
desktop build (session check + graphical agent):

```sh
./tools/install-local.sh                # hardened desktop (default)
./tools/install-local.sh --lightweight  # daemon + CLI only, no GTK/agent
```

It builds release binaries, installs them to `/usr/bin`, drops the systemd
units and a default `/etc/fsnitch/config.toml` (an existing one is left
untouched), and enables the daemon. It uses `sudo` for the root-owned parts and
prints the remaining steps (enable the user agent, protect a path).

Prerequisites for the hardened build: a Rust toolchain plus the system
libraries `libsystemd`, `gtk4`, and `gtk4-layer-shell`. On Arch:

```sh
sudo pacman -S --needed rust systemd gtk4 gtk4-layer-shell
```

## Manual build

If you'd rather run the steps yourself.

**Hardened desktop:**

```sh
cargo build --release -p fsnitchd --features session-hardening
cargo build --release -p fsnitch-cli -p fsnitch-agent

sudo install -Dm755 target/release/fsnitchd       /usr/bin/fsnitchd
sudo install -Dm755 target/release/fsnitch        /usr/bin/fsnitch
sudo install -Dm755 target/release/fsnitch-agent  /usr/bin/fsnitch-agent
sudo install -Dm644 packaging/fsnitchd.service      /usr/lib/systemd/system/fsnitchd.service
sudo install -Dm644 packaging/fsnitch-agent.service /usr/lib/systemd/user/fsnitch-agent.service
sudo install -Dm644 packaging/config.toml           /etc/fsnitch/config.toml
```

**Lightweight / headless** (servers, CI — no `libsystemd`, no GTK, no prompt
agent):

```sh
cargo build --release -p fsnitchd -p fsnitch-cli
sudo install -Dm755 target/release/fsnitchd /usr/bin/fsnitchd
sudo install -Dm755 target/release/fsnitch  /usr/bin/fsnitch
sudo install -Dm644 packaging/fsnitchd.service /usr/lib/systemd/system/fsnitchd.service
sudo install -Dm644 packaging/config.toml      /etc/fsnitch/config.toml
```

With no agent, `mode = "ask"` has nobody to prompt and falls back to
`on_no_agent` (default `deny`). Use `block` or `watch` instead, and keep
`require_agent_session = false` (the session check is a no-op without the
feature; leaving it `true` just logs a startup warning).

## Binary package

Prebuilt binaries are attached to each [GitHub
Release](https://github.com/balemy/fsnitch/releases) once 1.0 ships. Download
the archive, unpack it, and run the bundled installer:

```sh
tar xf fsnitch-1.0.0-x86_64-linux.tar.zst
cd fsnitch-1.0.0-x86_64-linux
sudo ./install.sh
```

It installs the binaries, units, and default config, then enables the daemon
(the same end state as the manual build).

## Enable and protect paths

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now fsnitchd

# graphical session, no sudo:
systemctl --user enable --now fsnitch-agent

sudo fsnitch protect /home/YOU/vaults --program /usr/bin/keepassxc
sudo fsnitch preset apply browsers        # curated packs; `fsnitch preset list`
sudo sysctl kernel.yama.ptrace_scope=1    # recommended companion hardening
```

## AUR (later)

PKGBUILDs live under `packaging/aur/` but are **not published** to the AUR yet.
To build a local Arch package from them: `cd packaging/aur/fsnitch-git &&
makepkg -si`. This may be published later.
