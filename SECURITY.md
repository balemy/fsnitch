# Security policy

## What fsnitch is

fsnitch gates `open()` on paths you declare sensitive. A root daemon
(`fsnitchd`) uses fanotify permission events to pause a file open while it
decides: allowlisted programs pass, and everything else is denied silently
(`block`), prompts you (`ask`), or is allowed-but-logged (`watch`).

The honest one-line pitch: **fsnitch stops the common infostealer pattern — an
unprivileged program reading your vaults, cookies, wallets, or keys and
exfiltrating them. It is policy enforcement, not a sandbox, and not malware
detection.** Read the threat model below before you rely on it.

## Threat model

### In scope

- **Unprivileged processes directly opening protected files.** The standard
  infostealer flow (read a secret, send it somewhere) and direct tampering
  (writing/overwriting a protected file). The daemon gates the `open()` on the
  kernel-canonical target path, so it applies no matter what path — including a
  symlinked one — the program used to reach the file.
- **Programs you did not allowlist.** Only the exact programs you list (by
  absolute, symlink-resolved executable path, optionally pinned to a `sha256`)
  are allowed; anything else hits your chosen `mode`.

### Fail-safe posture

- Defaults deny: with no agent (`on_no_agent`) or no answer within `timeout`
  (`on_no_answer`), the default action is **deny**.
- A `sha256`-pinned program whose file changes after the daemon loaded its hash
  fails the pin (and is therefore no longer allowlisted) until you reload —
  it fails safe rather than trusting a changed binary.
- If an unpinned `allow` and a `deny` name the same program, the config is
  rejected at load: an unverifiable allow must not silently win over a deny.

### Out of scope (non-goals)

These are deliberate limitations, not bugs. fsnitch does **not** protect
against:

- **Root-level malware.** Root can stop the daemon, edit the config, read raw
  disk, or load a kernel module. A root attacker is game over; fsnitch defends
  the unprivileged boundary only.
- **Confused-deputy abuse.** An allowlisted program that can be driven to read
  arbitrary files on an attacker's behalf (for example a browser started with a
  remote-debugging port, or any allowlisted interpreter or shell) defeats the
  allowlist, because the *program* is what fsnitch trusts. Allowlist narrow,
  purpose-built binaries — not `python`, `bash`, `node`, or a browser — and
  prefer `sha256` pins. Heuristics for this class are on the roadmap.
- **Code injection into an allowlisted program.** `LD_PRELOAD`, `ptrace`, or
  `gdb` against a process running an allowlisted binary lets an attacker read
  the file through a trusted identity. Set `kernel.yama.ptrace_scope = 1` to
  raise the bar.
- **Delete and cross-filesystem move.** fanotify cannot block these as
  permission events, so fsnitch gates opens (read/write), not unlink/rename.
  A *same-filesystem* rename out of a protected path **is** covered: the open
  verdict falls back to the file's inode identity `(dev, ino)`, so moving a
  secret elsewhere on the same filesystem and reading it there is still gated
  (hardlinks likewise). The inode set is built by scanning each root at
  load/reload and kept fresh by an inotify watcher, so files *created* under a
  root after startup are tracked too. Still out of scope: delete;
  cross-filesystem move (a copy whose source read is already gated, landing on
  a new inode); the narrow race between a file being created-and-moved and the
  watcher indexing it (fanotify has no `CREATE_PERM`); the brief window after a
  reload or `protect` before the watcher re-seeds the new roots; and any root
  that exceeded `max_tracked_inodes` (it falls back to path-only — see
  `fsnitch status`).
- **Multi-user / multi-seat desktops.** The design assumes a single interactive
  user; prompts route to the one registered agent per uid.
- **Signature or behavioural malware scanning.** fsnitch is policy, not
  detection — it never inspects file *contents* or program *behaviour*.

## Control plane and agent trust

The control socket (`/run/fsnitch/fsnitchd.sock`) is world-connectable
(mode 0666). Roles are assigned from the kernel-supplied peer credentials
(`SO_PEERCRED`), which cannot be forged by the connecting process:

- **uid 0** gets the control plane: status, policy management, reload, log.
- **any other uid** may only register as *that user's* prompt agent.

The peer that registers as the prompt agent is pinned via `SO_PEERPIDFD` (on
kernels older than 6.5 this falls back to the `SO_PEERCRED` pid, logged as a
warning) so a reused pid cannot be substituted between the check and its use.
Every build also verifies the peer is running the configured `agent` binary.

**Optional session hardening.** Built with `--features session-hardening` (which
links libsystemd), the daemon additionally requires the agent's uid to have an
*active graphical* logind session — a `tty` or headless login does not qualify
(so the agent may run as a systemd user service). The default lightweight build omits this (and libsystemd); on
it, `require_agent_session = true` is logged as an ineffective warning at
startup. Honest limit: a human still answers the dialog either way — session
binding narrows *who may register* as the agent to the live graphical seat, it
does not prove the agent process itself is not malicious.

**Read-only status socket.** A second socket, `/run/fsnitch/status.sock`
(also 0666), serves the tray/GUI as a normal user. It answers only `status`,
`list`, `verdicts` and `events`; every other request is refused, so it cannot
change policy. Per-user data is filtered by peer uid: a non-root peer sees only
its own event-log records and pauses. Honest limit: the list of protected
paths, their allow/deny programs and the remembered verdicts are visible to any
local user — fsnitch treats *which* paths are guarded as non-secret. Changes
from the GUI go through `pkexec fsnitch …`, i.e. through polkit
authentication and the root control plane.

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue.

- Email **lucas@humhub.com** with a description, affected version/commit, and
  reproduction steps.
- Once the project is hosted publicly, GitHub **private security advisories**
  are also welcome.

Because fsnitch runs a root daemon that gates file access, take particular care
with any report that could let an unprivileged process bypass enforcement,
escalate through the control socket, or crash/hang the daemon (which fails
open for events already in flight). Expect an acknowledgement and a discussion
of scope; given the stated non-goals, please confirm a finding is *in scope*
before treating it as a vulnerability.
