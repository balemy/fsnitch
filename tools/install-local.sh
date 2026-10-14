#!/usr/bin/env bash
# Build fsnitch from this checkout and install it on the local machine.
#
# Default: hardened desktop build (session-hardening + graphical agent + tray).
# --lightweight: daemon + CLI only, no libsystemd, no GTK, no agent, no tray.
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
    cargo build --release -p fsnitch-cli -p fsnitch-agent -p fsnitch-gui
fi

echo "==> installing binaries to /usr/bin (sudo)"
sudo install -Dm755 target/release/fsnitchd /usr/bin/fsnitchd
sudo install -Dm755 target/release/fsnitch  /usr/bin/fsnitch
[[ "$LIGHTWEIGHT" == 0 ]] && sudo install -Dm755 target/release/fsnitch-agent /usr/bin/fsnitch-agent
[[ "$LIGHTWEIGHT" == 0 ]] && sudo install -Dm755 target/release/fsnitch-gui /usr/bin/fsnitch-gui

echo "==> installing systemd units + default config (sudo)"
sudo install -Dm644 packaging/fsnitchd.service /usr/lib/systemd/system/fsnitchd.service
if [[ "$LIGHTWEIGHT" == 0 ]]; then
    sudo install -Dm644 packaging/fsnitch-agent.service /usr/lib/systemd/user/fsnitch-agent.service
    sudo install -Dm644 packaging/fsnitch-gui.service /usr/lib/systemd/user/fsnitch-gui.service
    sudo install -Dm644 packaging/fsnitch-gui.desktop /usr/share/applications/fsnitch-gui.desktop
    sudo install -Dm644 packaging/icons/fsnitch.svg /usr/share/icons/hicolor/scalable/apps/fsnitch.svg
    for icon in packaging/icons/fsnitch-*.svg; do
        sudo install -Dm644 "$icon" "/usr/share/icons/hicolor/scalable/status/${icon##*/}"
    done
    sudo gtk-update-icon-cache -q /usr/share/icons/hicolor 2>/dev/null || true
fi
if [[ ! -e /etc/fsnitch/config.toml ]]; then
    sudo install -Dm644 packaging/config.toml /etc/fsnitch/config.toml
else
    echo "    /etc/fsnitch/config.toml exists — left untouched"
fi

echo "==> enabling and (re)starting the daemon (sudo)"
sudo systemctl daemon-reload
sudo systemctl enable fsnitchd
sudo systemctl restart fsnitchd   # picks up the new binary on re-install too

# A running prompt agent lost its daemon connection on the restart above and
# may be an older binary — restart it too (user service, no sudo). First-time
# installs get the enable hint below instead.
if [[ "$LIGHTWEIGHT" == 0 ]] && systemctl --user is-active --quiet fsnitch-agent 2>/dev/null; then
    echo "==> restarting the user prompt agent"
    systemctl --user daemon-reload
    systemctl --user restart fsnitch-agent
fi
# Same for a running tray, so a re-install picks up the new binary.
if [[ "$LIGHTWEIGHT" == 0 ]] && systemctl --user is-active --quiet fsnitch-gui 2>/dev/null; then
    echo "==> restarting the tray"
    systemctl --user daemon-reload
    systemctl --user restart fsnitch-gui
fi

cat <<EOF

fsnitch installed.

EOF
if [[ "$LIGHTWEIGHT" == 0 ]]; then
cat <<EOF
Start the prompt agent and the tray in your graphical session (no sudo):
    systemctl --user daemon-reload
    systemctl --user enable --now fsnitch-agent fsnitch-gui
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
