#!/usr/bin/env bash
# Build fsnitch from this checkout and install it on the local machine.
#
# Default: hardened desktop build (session-hardening + graphical agent).
# --lightweight: daemon + CLI only, no libsystemd, no GTK, no agent.
#
# Uses sudo for the root-owned bits (binaries, system unit, /etc/fsnitch).
# The existing /etc/fsnitch/config.toml is never overwritten.
set -euo pipefail

LIGHTWEIGHT=0
[[ "${1:-}" == "--lightweight" ]] && LIGHTWEIGHT=1

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
export PATH="$HOME/.cargo/bin:$PATH"

echo "==> building release binaries"
if [[ "$LIGHTWEIGHT" == 1 ]]; then
    cargo build --release -p fsnitchd -p fsnitch-cli
else
    cargo build --release -p fsnitchd --features session-hardening
    cargo build --release -p fsnitch-cli -p fsnitch-agent
fi

echo "==> installing binaries to /usr/bin (sudo)"
sudo install -Dm755 target/release/fsnitchd /usr/bin/fsnitchd
sudo install -Dm755 target/release/fsnitch  /usr/bin/fsnitch
[[ "$LIGHTWEIGHT" == 0 ]] && sudo install -Dm755 target/release/fsnitch-agent /usr/bin/fsnitch-agent

echo "==> installing systemd units + default config (sudo)"
sudo install -Dm644 packaging/fsnitchd.service /usr/lib/systemd/system/fsnitchd.service
[[ "$LIGHTWEIGHT" == 0 ]] && sudo install -Dm644 packaging/fsnitch-agent.service /usr/lib/systemd/user/fsnitch-agent.service
if [[ ! -e /etc/fsnitch/config.toml ]]; then
    sudo install -Dm644 packaging/config.toml /etc/fsnitch/config.toml
else
    echo "    /etc/fsnitch/config.toml exists — left untouched"
fi

echo "==> enabling the daemon (sudo)"
sudo systemctl daemon-reload
sudo systemctl enable --now fsnitchd

cat <<EOF

fsnitch installed.

EOF
if [[ "$LIGHTWEIGHT" == 0 ]]; then
cat <<EOF
Start the prompt agent in your graphical session (no sudo):
    systemctl --user daemon-reload
    systemctl --user enable --now fsnitch-agent
EOF
else
cat <<EOF
Lightweight build: no prompt agent. Use mode = "block" or "watch" (ask mode
will always fall back to on_no_agent = "deny").
EOF
fi
cat <<EOF

Protect a path and check status:
    sudo fsnitch protect /home/$USER/vaults --program /usr/bin/keepassxc
    sudo fsnitch status

Recommended companion hardening:
    sudo sysctl kernel.yama.ptrace_scope=1
EOF
