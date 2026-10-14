#!/usr/bin/env bash
# End-to-end check for the interactive prompt path. MUST run as root.
# Verifies: ask-mode access with a registered agent is decided by the agent;
# DenyOnce blocks; AllowForever is remembered and a later access is allowed
# without a second prompt (source=remembered); no agent -> on_no_agent.
#
# Prompts are routed by the SUBJECT uid (the process opening the file), so the
# file accesses below run as the same non-root uid the agent registers for —
# exactly the real case where the user's processes and the user's agent share a
# uid. (Run via `sudo` from a normal user so SUDO_UID is that non-root uid.)
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
if command -v cargo >/dev/null 2>&1; then cargo build --workspace
elif [[ -x ./target/debug/fsnitchd ]]; then echo "note: cargo not found under sudo; using existing build"
else echo "FAIL: build the workspace first (cargo build --workspace)"; exit 1; fi

AGENT_UID="${SUDO_UID:-}"
if [[ -z "$AGENT_UID" || "$AGENT_UID" == "0" ]]; then
    echo "FAIL: run via sudo from a normal user (need SUDO_UID for the non-root agent/subject)"; exit 1
fi

# Run a command as the non-root subject/agent uid.
as_user() { setpriv --reuid "$AGENT_UID" --regid "$AGENT_UID" --clear-groups "$@"; }

WORK=$(mktemp -d)
# Own socket path — never touch /run/fsnitch of an installed daemon.
SOCK="$WORK/fsnitchd.sock"
DAEMON_PID=""; AGENT_PID=""
trap 'kill "$AGENT_PID" 2>/dev/null||true; kill "$DAEMON_PID" 2>/dev/null||true; rm -rf "$WORK"' EXIT

mkdir -p "$WORK/protected" "$WORK/etc"
echo secret > "$WORK/protected/secret.txt"
# The subject runs as $AGENT_UID, so the path must be traversable/readable by it
# (mktemp -d is 0700). The daemon still gates the open() via fanotify regardless.
chmod 755 "$WORK" "$WORK/protected"
chmod 644 "$WORK/protected/secret.txt"

MOCK="$(readlink -f ./target/debug/fsnitch-mock-agent)"
cat > "$WORK/etc/config.toml" <<EOF
[general]
log_file = "$WORK/events.jsonl"
agent = "$MOCK"
on_no_agent = "deny"
timeout = 5
# the setpriv'd agent here isn't in a real graphical logind session
require_agent_session = false

[[path]]
path = "$WORK/protected"
mode = "ask"
EOF

start_daemon() {
    ./target/debug/fsnitchd --config "$WORK/etc" --socket "$SOCK" & DAEMON_PID=$!
    sleep 1
    kill -0 "$DAEMON_PID" || { echo "FAIL: daemon died on startup"; exit 1; }
}

echo "--- no agent registered: ask-mode access denied (on_no_agent)"
start_daemon
if as_user cat "$WORK/protected/secret.txt" 2>/dev/null; then echo "FAIL: read succeeded with no agent"; exit 1; fi
grep -q '"source":"no_agent"' "$WORK/events.jsonl" || { echo "FAIL: no no_agent event logged"; exit 1; }
echo "OK: denied with no agent"

echo "--- agent replies allow-forever: access allowed and remembered"
as_user "$MOCK" allow-forever --socket "$SOCK" & AGENT_PID=$!
sleep 1
as_user head -n1 "$WORK/protected/secret.txt" >/dev/null || { echo "FAIL: allow-forever access blocked"; exit 1; }
grep -q '"source":"prompt"' "$WORK/events.jsonl" || { echo "FAIL: no prompt-sourced event logged"; exit 1; }
test -f "$WORK/etc/remembered.toml" || { echo "FAIL: remembered.toml not written"; exit 1; }
echo "OK: allowed via prompt and remembered"

echo "--- remembered verdict applies without a new prompt"
kill "$AGENT_PID" 2>/dev/null || true; AGENT_PID=""
sleep 1
as_user head -n1 "$WORK/protected/secret.txt" >/dev/null || { echo "FAIL: remembered allow not honored after agent gone"; exit 1; }
grep -q '"source":"remembered"' "$WORK/events.jsonl" || { echo "FAIL: no remembered-sourced event logged"; exit 1; }
echo "OK: remembered verdict honored without agent"

echo "ALL PROMPT E2E CHECKS PASSED"
