#!/usr/bin/env bash
# End-to-end check for the path CLI. MUST run as root.
# The daemon starts with ZERO protected paths; `fsnitch protect` must take
# effect immediately (dynamic fanotify mark, no restart), `fsnitch show` must
# report the path as cli-managed, the most-specific path must win when paths
# nest, `protect` is additive (re-protecting merges instead of failing), and
# `unprotect` must lift enforcement (whole path, or just one `--program`).
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }

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
SOCK="$WORK/fsnitchd.sock"
CLI=(./target/debug/fsnitch --socket "$SOCK")
DAEMON_PID=""
trap 'kill "$DAEMON_PID" 2>/dev/null || true; rm -rf "$WORK"' EXIT

mkdir -p "$WORK/etc" "$WORK/protected" "$WORK/protected/sub"
echo "top secret" > "$WORK/protected/secret.txt"
# The nested-path fixture is created here, before any policy is applied — once
# /protected is block-protected, an unlisted program (the shell) cannot create
# files under it, so the fixture must pre-exist.
echo "inner" > "$WORK/protected/sub/inner.txt"
cat > "$WORK/etc/config.toml" <<EOF
[general]
log_file = "$WORK/events.jsonl"
EOF

./target/debug/fsnitchd --config "$WORK/etc" --socket "$SOCK" &
DAEMON_PID=$!
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "FAIL: daemon did not come up"; exit 1; }

HEAD_BIN=$(readlink -f "$(command -v head)")
CAT_BIN=$(readlink -f "$(command -v cat)")

echo "--- protect (block, program head) — daemon had no paths at startup"
"${CLI[@]}" protect "$WORK/protected" --mode block --program "$HEAD_BIN"

echo "--- unlisted binary must be denied, without a daemon restart"
if cat "$WORK/protected/secret.txt" 2>/dev/null; then
    echo "FAIL: cat could read the protected file"; exit 1
fi
echo "OK: cat denied"

echo "--- allowlisted binary must succeed"
head -n1 "$WORK/protected/secret.txt" >/dev/null || { echo "FAIL: head denied"; exit 1; }
echo "OK: head allowed"

echo "--- show reports the path as cli-managed"
# Match the SOURCE column (" cli"), not the whole line (the tmpdir path could
# contain "cli"); the path is at the start of the line, the source at the end.
"${CLI[@]}" show "$WORK/protected" | grep -q " cli" \
    || { echo "FAIL: path not shown as cli-managed"; exit 1; }
echo "OK: cli-managed"

echo "--- most-specific path wins: a watch path nested under a block path"
"${CLI[@]}" protect "$WORK/protected/sub" --mode watch
# A read directly under the block path is still denied (cat is not allowlisted).
if cat "$WORK/protected/secret.txt" 2>/dev/null; then
    echo "FAIL: read directly under the block path was allowed"; exit 1
fi
# A read under the more-specific watch path is allowed (watch logs but permits).
cat "$WORK/protected/sub/inner.txt" >/dev/null \
    || { echo "FAIL: read under the watch path was denied"; exit 1; }
echo "OK: most-specific path wins"

echo "--- protect is additive: re-protecting merges instead of failing"
if "${CLI[@]}" protect "$WORK/protected" --program "$CAT_BIN" >/dev/null; then
    echo "OK: additive re-protect succeeded"
else
    echo "FAIL: additive re-protect was rejected"; exit 1
fi
"${CLI[@]}" show "$WORK/protected" | grep -qE "allow .*$(basename "$HEAD_BIN")" \
    || { echo "FAIL: head no longer listed after the additive protect"; exit 1; }
"${CLI[@]}" show "$WORK/protected" | grep -qE "allow .*$(basename "$CAT_BIN")" \
    || { echo "FAIL: cat not listed after the additive protect"; exit 1; }
echo "OK: show lists both allowed programs"
# Revert to the pre-merge allowlist so the pause/resume denial check below
# (cat must stay denied) is unaffected by this test.
"${CLI[@]}" unprotect "$WORK/protected" --program "$CAT_BIN" >/dev/null

echo "--- pause allows everything, resume re-arms"
"${CLI[@]}" pause "$WORK/protected" 1m
cat "$WORK/protected/secret.txt" >/dev/null || { echo "FAIL: pause did not allow cat"; exit 1; }
"${CLI[@]}" status | grep -q "paused" || { echo "FAIL: pause not shown in status"; exit 1; }
"${CLI[@]}" resume "$WORK/protected"
if cat "$WORK/protected/secret.txt" 2>/dev/null; then
    echo "FAIL: cat allowed after resume"; exit 1
fi
echo "OK: pause + resume"

echo "--- unprotect lifts enforcement"
"${CLI[@]}" unprotect "$WORK/protected"
cat "$WORK/protected/secret.txt" >/dev/null || { echo "FAIL: still denied after unprotect"; exit 1; }
echo "OK: unprotect works"

echo "--- unprotect --program removes a fixed allow entry"
"${CLI[@]}" protect "$WORK/protected" --mode ask --program "$HEAD_BIN" >/dev/null
"${CLI[@]}" show "$WORK/protected" | grep -q "$(basename "$HEAD_BIN")" \
    || { echo "FAIL: allow entry not shown before unprotect --program"; exit 1; }
"${CLI[@]}" unprotect "$WORK/protected" --program "$HEAD_BIN"
if "${CLI[@]}" show "$WORK/protected" | grep -qE "allow .*$(basename "$HEAD_BIN")"; then
    echo "FAIL: allow entry still present after unprotect --program"; exit 1
fi
echo "OK: unprotect --program works"

echo "--- protect --program --for injects a temporary verdict on an ask-mode path"
"${CLI[@]}" protect "$WORK/protected" --program "$HEAD_BIN" --for 2m
"${CLI[@]}" status | grep -qiE "temporary|[12]m" \
    || { echo "FAIL: timed allow not shown in status"; exit 1; }
"${CLI[@]}" unprotect "$WORK/protected" >/dev/null
echo "OK: timed allow works"

echo "--- preset list and dry-run are socket-free and safe"
"${CLI[@]}" preset list | grep -q "browsers" || { echo "FAIL: preset list missing browsers"; exit 1; }
"${CLI[@]}" preset apply ssh --user "${SUDO_USER:-$USER}" --dry-run | grep -qiE "would protect|skip" \
    || { echo "FAIL: preset dry-run produced no plan"; exit 1; }
echo "OK: preset list/dry-run"

echo "PASS"
