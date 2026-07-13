# Configuration reference

fsnitch reads its configuration from a directory, `/etc/fsnitch` by default
(override with `fsnitchd --config <dir>`). Everything is TOML.

## Directory layout

| File | Written by | Purpose |
|---|---|---|
| `config.toml` | you | `[general]` settings and hand-written `[[path]]` policies |
| `paths.d/*.toml` | you | drop-in `[[path]]` policies, loaded in lexicographic filename order |
| `paths.d/managed.toml` | the daemon | paths created via `fsnitch protect` |
| `remembered.toml` | the daemon | "always" verdicts from prompts |

`config.toml` and `paths.d/` are both optional; an empty directory is a valid
(do-nothing) configuration. Do not hand-edit the daemon-written files —
`managed.toml` is owned by the `protect`/`unprotect` CLI and `remembered.toml`
by the prompt flow; use the CLI (`fsnitch protect`, `fsnitch forget`, …) to
change them.

All `[[path]]` blocks from every file are merged into one policy set. A given
path may be protected **once** across all files — a duplicate is a load error.

## `[general]`

All keys are optional; defaults shown.

```toml
[general]
timeout               = 30                              # seconds to wait for an agent answer
on_no_answer          = "deny"                          # deny | allow — prompt shown, nobody answered in time
on_no_agent           = "deny"                          # deny | allow — no agent registered for the uid
log_file              = "/var/log/fsnitch/events.jsonl" # JSON-lines event log
agent                 = "/usr/bin/fsnitch-agent"        # binary a peer must run to register as the prompt agent
max_pending           = 128                             # cap on concurrently parked prompts
require_agent_session = true                            # require the agent in the uid's active graphical session
max_tracked_inodes    = 1000000                         # cap on the inode index used for move protection
```

- **`timeout`** — how long an `ask`-mode open is held waiting for the agent
  before `on_no_answer` applies.
- **`on_no_answer`** / **`on_no_agent`** — the fail-safe actions. Both default
  to `deny`. Set to `allow` only where availability matters more than
  protection.
- **`log_file`** — appended as JSON lines; each record carries the path,
  target file, program, pid, uid, decision, and source. Its directory must be
  writable by the daemon (root).
- **`agent`** — the absolute path of the agent binary. A peer registering as
  the prompt agent must be running exactly this binary (verified against its
  `/proc/<pid>/exe`).
- **`max_pending`** — when this many prompts are already parked, further
  `ask`-mode opens take `on_no_answer` immediately instead of queueing
  unbounded.
- **`require_agent_session`** — when `true`, the agent's uid must have an
  *active graphical* logind session. This is enforced **only** in a build
  with `--features session-hardening`; on the default lightweight build it is
  logged as an ineffective warning at startup. Set it to `false` for headless,
  CI, or dev setups. See [SECURITY.md](SECURITY.md#control-plane-and-agent-trust).
- **`max_tracked_inodes`** — bounds the inode index that backs same-filesystem
  move protection (the daemon records the `(dev, ino)` of every regular file
  under each protected root so a file renamed out of its root is still gated).
  A root whose file count would exceed this cap keeps its **path** protection
  but loses **move** protection; the daemon logs a warning at load/reload and
  `fsnitch status` lists the degraded roots. Raise it to re-cover a large root
  (roughly 24 bytes of memory per tracked inode).

## `[[path]]` — a protected path and its policy

```toml
[[path]]
path  = "/home/you/vaults"        # absolute, normalized; required
mode  = "ask"                     # block | ask | watch; required
allow = [                         # programs always allowed (optional)
    { program = "/usr/bin/keepassxc" },
    { program = "/usr/bin/borg", sha256 = "ab12…64hex…" },
]
deny  = [                         # programs always denied (optional)
    { program = "/usr/bin/curl" },
]
```

A protected path covers **itself and everything beneath it**. When paths nest,
the **most specific (longest) matching path wins**, and its policy is applied
independently — protecting or pausing `/a` does not affect a separately
protected `/a/sub`.

### `mode`

| Mode | A program that is neither allowed nor denied… |
|---|---|
| `block` | is denied silently (logged) |
| `ask` | triggers an interactive prompt to the agent |
| `watch` | is allowed, but logged (learning / audit mode) |

In every mode an entry in `deny` is refused and an entry in `allow` passes;
`mode` only decides the *default* for unlisted programs. A `deny` entry always
wins over an `allow` for the same program (and see the pin rule below).

### `allow` / `deny` entries

Each entry names one program:

- **`program`** — an **absolute, normalized** path to the executable, matched
  against the subject's symlink-resolved `/proc/<pid>/exe`. No glob characters
  (`* ? [ ] { }`) — it is a literal path, not a pattern. Allowlist narrow,
  purpose-built binaries; listing an interpreter or shell (`python`, `bash`,
  `node`) or a browser effectively allows anything it can be told to read (see
  the confused-deputy note in [SECURITY.md](SECURITY.md#out-of-scope-non-goals)).
- **`sha256`** *(optional)* — a 64-hex-character content hash pinning the
  program. The hash is computed when the daemon loads the config; at event time
  only a `stat` freshness check runs (no read on the hot path). If the file
  changes after load, the pin no longer verifies and the entry stops allowing
  the program until you `reload` — it fails safe. Case-insensitive; stored
  lowercased.

## Validation

The daemon refuses to load (or, for CLI changes, to apply) a configuration that
violates any of:

- a `path` that is not absolute, or not normalized (no `//`, `/./`, `..`, or a
  trailing slash; a bare `/` is allowed);
- the same `path` protected more than once;
- a `program` that is not absolute, contains glob characters, or is not
  normalized;
- a `sha256` that is not exactly 64 hexadecimal characters;
- the same program appearing in an **unpinned** `allow` and in `deny` on one
  path — add a `sha256` to the allow so the intent is verifiable, or drop one
  of the two.

A rejected configuration leaves the previously loaded policy in place; fix the
error and `reload`.

## Applying changes

- Editing files then `sudo fsnitch reload` re-reads all policies. Reload does
  **not** re-mark filesystems, so protecting a path on a filesystem that had no
  protected paths before needs a daemon **restart**.
- `sudo fsnitch protect <path> …` writes to `paths.d/managed.toml` and takes
  effect immediately, including marking a new filesystem at runtime — so the
  restart caveat above does not apply to the `protect` CLI.

See the README for the full `protect` / `unprotect` / `status` / `pause` /
`forget` / `preset` command surface.
