#!/usr/bin/env bash
# One-command local dev run of fsnitch: builds, sets up a throwaway repo-local
# environment under ./dev/, starts the daemon (via sudo) and the agent (as you),
# and streams their logs. Ctrl-C tears both down. No /etc, no systemd, no install.
#
# Trigger a prompt from another terminal:  cat ./dev/protected/secret.txt
# Reset remembered "always" verdicts:      rm ./dev/etc/remembered.toml   (or: rm -rf ./dev)
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
export PATH="$HOME/.cargo/bin:$PATH"

echo "==> building"
cargo build --workspace

DEV="$REPO/dev"
SOCK="$DEV/fsnitchd.sock"
AGENT_BIN="$REPO/target/debug/fsnitch-agent"
DAEMON_BIN="$REPO/target/debug/fsnitchd"

mkdir -p "$DEV/etc" "$DEV/protected"
[ -f "$DEV/protected/secret.txt" ] || echo "top secret" > "$DEV/protected/secret.txt"

# Regenerate the config each run; keep ./dev/etc/remembered.toml so "always"
# verdicts persist across runs (delete it to reset).
cat > "$DEV/etc/config.toml" <<EOF
[general]
log_file = "$DEV/events.jsonl"
agent    = "$(readlink -f "$AGENT_BIN")"
timeout  = 30
on_no_agent = "deny"
# dev build is lightweight (session-hardening off), so session binding is moot
require_agent_session = false

[[path]]
path = "$DEV/protected"
mode = "ask"
EOF

DAEMON_STARTED=0
AGENT_PID=""
cleanup() {
    echo
    echo "==> stopping"
    [ -n "$AGENT_PID" ] && kill "$AGENT_PID" 2>/dev/null || true
    if [ "$DAEMON_STARTED" = 1 ]; then
        sudo pkill -f "$DAEMON_BIN --config $DEV/etc" 2>/dev/null || true
    fi
}
trap cleanup INT TERM EXIT

echo "==> starting daemon (needs sudo for fanotify)"
sudo "$DAEMON_BIN" --config "$DEV/etc" --socket "$SOCK" &
DAEMON_STARTED=1

# Wait for the socket to appear (daemon came up).
for _ in $(seq 1 50); do
    [ -S "$SOCK" ] && break
    sleep 0.1
done
if [ ! -S "$SOCK" ]; then
    echo "FAIL: daemon did not create $SOCK — see its output above" >&2
    exit 1
fi

echo "==> starting agent (as $USER, in your graphical session)"
"$AGENT_BIN" --socket "$SOCK" &
AGENT_PID=$!

cat <<EOF

fsnitch dev environment is up.
  Protected dir : $DEV/protected
  Trigger a prompt (another terminal):  cat $DEV/protected/secret.txt
  Reset remembered verdicts:            rm $DEV/etc/remembered.toml
  Manage (root):                        sudo ./target/debug/fsnitch --socket $SOCK protect <path> | show <path> | pause <path> 15m | resume | forget <path> | unprotect <path>
  Tray + manager window:                FSNITCH_GUI_ICON_DIR=$REPO/packaging/icons ./target/debug/fsnitch-gui --socket $SOCK --cli $REPO/target/debug/fsnitch
  Stop everything:                      Ctrl-C here

Daemon + agent logs follow:
EOF

# Block until Ctrl-C; the daemon/agent log to this terminal's stderr.
wait
