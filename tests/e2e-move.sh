#!/usr/bin/env bash
# End-to-end check for same-filesystem move protection (inode identity).
# MUST run as root.
# Verifies:
#   1. A file present at startup, moved OUT of its protected root, is still
#      denied to an unlisted binary (inode identity; Phase 1 scan).
#   2. A file CREATED under the root after startup, then moved out, is also
#      denied (inotify freshness; Phase 2).
#   3. A genuinely unrelated file on the same filesystem stays readable.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }

cd "$(dirname "$0")/.."

# sudo resets PATH; pick up the invoking user's cargo, else use an existing build.
export PATH="$HOME/.cargo/bin:$PATH"
if command -v cargo >/dev/null 2>&1; then
    cargo build --workspace
elif [[ -x ./target/debug/fsnitchd ]]; then
    echo "note: cargo not found on PATH under sudo; using existing ./target/debug/fsnitchd build"
else
    echo "FAIL: cargo not found and no existing build at ./target/debug/fsnitchd."
    echo "Run 'cargo build --workspace' as your normal user first, then re-run this script with sudo."
    exit 1
fi

WORK=$(mktemp -d)
# Own socket path — never touch /run/fsnitch of an installed daemon.
SOCK="$WORK/fsnitchd.sock"
trap 'kill "$DAEMON_PID" 2>/dev/null || true; rm -rf "$WORK"' EXIT

mkdir -p "$WORK/protected" "$WORK/etc"
echo "top secret" > "$WORK/protected/secret.txt"
echo "public"     > "$WORK/unrelated.txt"

# Allowlist the shell so it may *create* files inside the block-mode vault
# (fsnitch gates create/write opens too — an unlisted program cannot even make
# a file here). This stands in for a legitimate writer like keepassxc; the
# unlisted reader (`cat`) below is still denied.
BASH_BIN=$(readlink -f "$(command -v bash)")

cat > "$WORK/etc/config.toml" <<EOF
[general]
log_file = "$WORK/events.jsonl"

[[path]]
path = "$WORK/protected"
mode = "block"
allow = [{ program = "$BASH_BIN" }]
EOF

./target/debug/fsnitchd --config "$WORK/etc" --socket "$SOCK" &
DAEMON_PID=$!
sleep 1
kill -0 "$DAEMON_PID" || { echo "FAIL: daemon died on startup"; exit 1; }

echo "--- (1) file present at startup, moved out of the root, stays denied"
# Same-filesystem rename (both under $WORK) -> inode preserved.
mv "$WORK/protected/secret.txt" "$WORK/leaked.txt"
if cat "$WORK/leaked.txt" 2>/dev/null; then
    echo "FAIL: moved-out secret was readable (inode identity not enforced)"; exit 1
fi
echo "OK: moved-out secret denied"

echo "--- (2) file created after startup, moved out, stays denied"
# Created in-place by the allowlisted shell -> the inotify watcher indexes it.
echo "new secret" > "$WORK/protected/new.txt"
sleep 0.5   # let the inotify watcher index the newly created file
mv "$WORK/protected/new.txt" "$WORK/new-leaked.txt"
if cat "$WORK/new-leaked.txt" 2>/dev/null; then
    echo "FAIL: moved-out freshly-created secret was readable (inotify freshness failed)"; exit 1
fi
echo "OK: moved-out freshly-created secret denied"

echo "--- (3) an unrelated same-fs file is readable"
cat "$WORK/unrelated.txt" >/dev/null || { echo "FAIL: unrelated file blocked"; exit 1; }
echo "OK: unrelated file untouched"

echo "--- deny events were logged"
grep -q '"decision":"deny"' "$WORK/events.jsonl" || { echo "FAIL: no deny event logged"; exit 1; }
echo "OK: deny events logged"

echo "ALL MOVE-PROTECTION E2E CHECKS PASSED"
