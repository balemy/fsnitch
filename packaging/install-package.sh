#!/usr/bin/env bash
# Install fsnitch from an unpacked binary release. Run from the unpacked
# directory as root: `sudo ./install.sh`.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo ./install.sh"; exit 1; }
cd "$(dirname "$0")"

install -Dm755 fsnitchd /usr/bin/fsnitchd
install -Dm755 fsnitch  /usr/bin/fsnitch
[ -f fsnitch-agent ] && install -Dm755 fsnitch-agent /usr/bin/fsnitch-agent
[ -f fsnitch-gui ] && install -Dm755 fsnitch-gui /usr/bin/fsnitch-gui

install -Dm644 fsnitchd.service /usr/lib/systemd/system/fsnitchd.service
[ -f fsnitch-agent.service ] && install -Dm644 fsnitch-agent.service /usr/lib/systemd/user/fsnitch-agent.service
if [ -f fsnitch-gui ]; then
    install -Dm644 fsnitch-gui.service /usr/lib/systemd/user/fsnitch-gui.service
    install -Dm644 fsnitch-gui.desktop /usr/share/applications/fsnitch-gui.desktop
    install -Dm644 icons/fsnitch.svg /usr/share/icons/hicolor/scalable/apps/fsnitch.svg
    for icon in icons/fsnitch-*.svg; do
        install -Dm644 "$icon" "/usr/share/icons/hicolor/scalable/status/${icon##*/}"
    done
    gtk-update-icon-cache -q /usr/share/icons/hicolor 2>/dev/null || true
fi

if [ ! -e /etc/fsnitch/config.toml ]; then
    install -Dm644 config.toml /etc/fsnitch/config.toml
else
    echo "/etc/fsnitch/config.toml exists — left untouched"
fi

systemctl daemon-reload
systemctl enable --now fsnitchd

echo
echo "fsnitch installed. Start the prompt agent and the tray in your graphical session:"
echo "    systemctl --user enable --now fsnitch-agent fsnitch-gui"
echo "Then protect a path, e.g.:"
echo "    sudo fsnitch protect /home/\$USER/vaults --program /usr/bin/keepassxc"
