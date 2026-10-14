#!/usr/bin/env bash
# End-to-end check for the read-only status socket. MUST run as root via sudo
# (the unprivileged half runs as $SUDO_USER).
# An unprivileged user must be able to read status/list/events from
# status.sock, must only see their own events, and every mutating request on
# it must be refused — the policy stays unchanged.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run as root (sudo)"; exit 1; }
USER_NAME="${SUDO_USER:?run via sudo so there is an unprivileged user to test as}"

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

if command -v cargo >/dev/null 2>&1; then
    cargo build --workspace
elif [[ -x ./target/debug/fsnitchd ]]; then
    echo "note: cargo not found on PATH under sudo; using existing ./target/debug build"
else
    echo "FAIL: cargo not found and no existing build at ./target/debug."
    echo "Run 'cargo build --workspace' as your normal user first, then re-run with sudo."
    exit 1
fi

WORK=$(mktemp -d)
chmod 755 "$WORK"
SOCK="$WORK/fsnitchd.sock"
STATUS="$WORK/status.sock"
CLI=(./target/debug/fsnitch --socket "$SOCK")
DAEMON_PID=""
trap 'kill "$DAEMON_PID" 2>/dev/null || true; rm -rf "$WORK"' EXIT

mkdir -p "$WORK/etc" "$WORK/protected"
echo "top secret" > "$WORK/protected/secret.txt"
cat > "$WORK/etc/config.toml" <<EOF
[general]
log_file = "$WORK/events.jsonl"
EOF

./target/debug/fsnitchd --config "$WORK/etc" --socket "$SOCK" &
DAEMON_PID=$!
for _ in $(seq 1 50); do [ -S "$STATUS" ] && break; sleep 0.1; done
[ -S "$STATUS" ] || { echo "FAIL: daemon did not create $STATUS"; exit 1; }

"${CLI[@]}" protect "$WORK/protected" --mode block >/dev/null
# One denied access by root (uid 0) and one by the user.
cat "$WORK/protected/secret.txt" 2>/dev/null || true
sudo -u "$USER_NAME" cat "$WORK/protected/secret.txt" 2>/dev/null || true

# Send one JSON request to status.sock as the unprivileged user; print the reply.
ask() {
    sudo -u "$USER_NAME" python3 -I -c '
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
s.sendall(sys.argv[2].encode() + b"\n")
print(s.makefile().readline().strip())
' "$STATUS" "$1"
}

echo "--- status is readable as $USER_NAME"
ask '{"type":"status"}' | grep -q '"type":"status"' || { echo "FAIL: status not readable"; exit 1; }
ask '{"type":"status"}' | grep -q '"agent_connected":false' \
    || { echo "FAIL: agent_connected should be false without an agent"; exit 1; }
echo "OK: status"

echo "--- list shows the protected path"
ask '{"type":"list"}' | grep -q "$WORK/protected" || { echo "FAIL: list misses the path"; exit 1; }
echo "OK: list"

echo "--- events are filtered to the user's own uid"
USER_UID=$(id -u "$USER_NAME")
EVENTS=$(ask '{"type":"events","limit":100}')
echo "$EVENTS" | grep -q "\"uid\":$USER_UID" || { echo "FAIL: user's own event missing: $EVENTS"; exit 1; }
if echo "$EVENTS" | grep -q '"uid":0'; then
    echo "FAIL: root's event leaked to $USER_NAME: $EVENTS"; exit 1
fi
echo "OK: events filtered"

echo "--- mutating requests are refused"
for req in \
    "{\"type\":\"unprotect\",\"path\":\"$WORK/protected\"}" \
    "{\"type\":\"pause\",\"path\":\"$WORK/protected\",\"secs\":600}" \
    "{\"type\":\"protect\",\"path\":\"$WORK\",\"mode\":\"watch\",\"allow\":[]}" \
    '{"type":"reload"}'; do
    ask "$req" | grep -q 'read-only' || { echo "FAIL: not refused: $req"; exit 1; }
done
"${CLI[@]}" show "$WORK/protected" | grep -q "block" || { echo "FAIL: policy changed"; exit 1; }
if "${CLI[@]}" status | grep -q "paused"; then
    echo "FAIL: a pause got through the status socket"; exit 1
fi
echo "OK: read-only"

echo "PASS"
