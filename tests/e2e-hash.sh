#!/usr/bin/env bash
# End-to-end check for sha256 hash pinning. MUST run as root.
# Verifies: a pinned allow entry with the CORRECT hash allows the binary; after
# the pin is changed to a wrong value (and reload), the same binary is denied
# (the pin no longer verifies, so it is no longer allowlisted).
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
if command -v cargo >/dev/null 2>&1; then cargo build --workspace
elif [[ -x ./target/debug/fsnitchd ]]; then echo "note: cargo not found under sudo; using existing build"
else echo "FAIL: build the workspace first (cargo build --workspace)"; exit 1; fi

WORK=$(mktemp -d)
# Own socket path — never touch /run/fsnitch of an installed daemon.
SOCK="$WORK/fsnitchd.sock"
DAEMON_PID=""
trap 'kill "$DAEMON_PID" 2>/dev/null || true; rm -rf "$WORK"' EXIT

mkdir -p "$WORK/protected" "$WORK/etc"
echo secret > "$WORK/protected/secret.txt"

# Allowlist `head`, pinned to its real hash; `cat` is not listed.
HEAD="$(readlink -f "$(command -v head)")"
GOOD="$(sha256sum "$HEAD" | cut -d' ' -f1)"
WRONG="0000000000000000000000000000000000000000000000000000000000000000"

write_config() { # $1 = pin
cat > "$WORK/etc/config.toml" <<EOF
[general]
log_file = "$WORK/events.jsonl"

[[path]]
path = "$WORK/protected"
mode = "block"
allow = [{ program = "$HEAD", sha256 = "$1" }]
EOF
}

write_config "$GOOD"
./target/debug/fsnitchd --config "$WORK/etc" --socket "$SOCK" & DAEMON_PID=$!
sleep 1
kill -0 "$DAEMON_PID" || { echo "FAIL: daemon died on startup"; exit 1; }

echo "--- correct pin: allowlisted binary is allowed"
head -n1 "$WORK/protected/secret.txt" >/dev/null || { echo "FAIL: correctly-pinned head was denied"; exit 1; }
echo "OK: head allowed with correct pin"

echo "--- unlisted binary still denied"
if cat "$WORK/protected/secret.txt" 2>/dev/null; then echo "FAIL: cat could read the protected file"; exit 1; fi
echo "OK: cat denied"

echo "--- wrong pin (after reload): same binary is denied"
write_config "$WRONG"
./target/debug/fsnitch --socket "$SOCK" reload
sleep 1
if head -n1 "$WORK/protected/secret.txt" 2>/dev/null; then echo "FAIL: head allowed despite wrong pin"; exit 1; fi
echo "OK: head denied with wrong pin"

grep -q '"decision":"allow"' "$WORK/events.jsonl" || { echo "FAIL: no allow event logged"; exit 1; }
grep -q '"decision":"deny"' "$WORK/events.jsonl" || { echo "FAIL: no deny event logged"; exit 1; }

echo "ALL HASH-PIN E2E CHECKS PASSED"
