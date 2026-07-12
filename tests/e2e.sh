#!/usr/bin/env bash
# End-to-end check for the enforcing daemon. MUST run as root.
# Verifies: unlisted binary gets EPERM on a protected file; allowlisted binary succeeds;
# unprotected files are untouched; events are logged.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }

cd "$(dirname "$0")/.."

# sudo resets PATH, so the invoking user's ~/.cargo/bin (where cargo lives)
# may be missing even though it's on their normal PATH. Try to pick it up;
# if cargo is still not found, fall back to a binary that's already built.
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
trap 'kill "$DAEMON_PID" 2>/dev/null || true; rm -rf "$WORK"' EXIT

mkdir -p "$WORK/protected" "$WORK/etc"
echo "top secret" > "$WORK/protected/secret.txt"
echo "public"     > "$WORK/public.txt"

CAT_ALLOWED=$(command -v head)   # head is allowlisted, cat is not
cat > "$WORK/etc/config.toml" <<EOF
[general]
log_file = "$WORK/events.jsonl"

[[path]]
path = "$WORK/protected"
mode = "block"
allow = [{ program = "$(readlink -f "$CAT_ALLOWED")" }]
EOF

./target/debug/fsnitchd --config "$WORK/etc" &
DAEMON_PID=$!
sleep 1
kill -0 "$DAEMON_PID" || { echo "FAIL: daemon died on startup"; exit 1; }

echo "--- unlisted binary must be denied"
if cat "$WORK/protected/secret.txt" 2>/dev/null; then
    echo "FAIL: cat could read the protected file"; exit 1
fi
echo "OK: cat denied"

echo "--- allowlisted binary must succeed"
head -n1 "$WORK/protected/secret.txt" >/dev/null || { echo "FAIL: head was denied"; exit 1; }
echo "OK: head allowed"

echo "--- unprotected file unaffected"
cat "$WORK/public.txt" >/dev/null || { echo "FAIL: unprotected file blocked"; exit 1; }
echo "OK: unprotected untouched"

echo "--- events were logged"
grep -q '"decision":"deny"' "$WORK/events.jsonl" || { echo "FAIL: no deny event logged"; exit 1; }
grep -q '"decision":"allow"' "$WORK/events.jsonl" || { echo "FAIL: no allow event logged"; exit 1; }
echo "OK: events logged"

echo "ALL E2E CHECKS PASSED"
