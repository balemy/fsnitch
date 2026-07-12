#!/usr/bin/env bash
# Install fsnitch from an unpacked binary release. Run from the unpacked
# directory as root: `sudo ./install.sh`.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo ./install.sh"; exit 1; }
cd "$(dirname "$0")"

install -Dm755 fsnitchd /usr/bin/fsnitchd
install -Dm755 fsnitch  /usr/bin/fsnitch
[ -f fsnitch-agent ] && install -Dm755 fsnitch-agent /usr/bin/fsnitch-agent

install -Dm644 fsnitchd.service /usr/lib/systemd/system/fsnitchd.service
[ -f fsnitch-agent.service ] && install -Dm644 fsnitch-agent.service /usr/lib/systemd/user/fsnitch-agent.service

if [ ! -e /etc/fsnitch/config.toml ]; then
    install -Dm644 config.toml /etc/fsnitch/config.toml
else
    echo "/etc/fsnitch/config.toml exists — left untouched"
fi

systemctl daemon-reload
systemctl enable --now fsnitchd

echo
echo "fsnitch installed. Start the prompt agent in your graphical session:"
echo "    systemctl --user enable --now fsnitch-agent"
echo "Then protect a path, e.g.:"
echo "    sudo fsnitch protect /home/\$USER/vaults --program /usr/bin/keepassxc"
