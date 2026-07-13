# Inode-identity move protection — design

Date: 2026-07-13
Status: approved (brainstorm), pending implementation

## Problem

fsnitch identifies a protected file by its **path**. The whole-filesystem
fanotify mark (`FAN_MARK_FILESYSTEM`, `FAN_OPEN_PERM`) delivers an
`open()` permission event for every open on the filesystem, but the verdict is
taken in `CompiledPaths::policy_for()` by longest-prefix **path** match against
the configured roots.

Consequence — a policy bypass:

1. `mv ~/vaults/secret.kdbx /tmp/` is a `rename(2)`. It needs write permission on
   the *directories* only (not the file), triggers no `open()`, and fanotify has
   no `MOVE_PERM`, so it is not intercepted.
2. `cat /tmp/secret.kdbx` still fires an open event (the whole-fs mark covers
   `/tmp` too), but the resolved path `/tmp/secret.kdbx` matches no root →
   `policy_for` returns `None` → **allowed, unlogged**.

Within the same filesystem, `rename` preserves the **inode**. The event already
reaches us; we simply fail to *recognize* the file. That is the gap this design
closes.

Cross-filesystem `mv` is `copy + unlink`: the copy reads (opens) the source at
its protected path → already gated today; the destination is a genuinely new
inode. So cross-fs move stays out of scope by construction.

## Goal

A file that is a descendant of a protected root at scan time (or created under
it later) stays protected after a same-filesystem `rename` out of the root,
because the verdict keys on `(st_dev, st_ino)` identity, not only on the current
path. Hardlinks fall out for free (same inode).

Non-goals (unchanged, documented in SECURITY.md): delete, cross-filesystem move,
and the inherent create→move race window (fanotify has no `CREATE_PERM`/
`MOVE_PERM`).

## Approach (decided)

Approach 1 — a userspace **inode index** built by a proactive scan and kept
fresh live. No per-inode fanotify marks; no lazy learning. Freshness via
**inotify** (nix 0.30.1 exposes a safe `inotify` wrapper; it does **not** expose
`FAN_REPORT_FID`, so the fanotify-FID variant is off the table — it would require
raw-libc info-record parsing, inconsistent with this codebase).

Enforcement stays entirely on the existing whole-fs fanotify mark. inotify is
used *only* to keep the index fresh.

## Components

### 1. Config: `max_tracked_inodes`

`fsnitch_core::config::General` gains:

```rust
#[serde(default = "default_max_tracked_inodes")]
pub max_tracked_inodes: usize,   // default: 1_000_000  (~24 MB at ~24 B/entry)
```

A single global cap. Its purpose is a safety net against a pathologically large
root, not routine tuning.

### 2. `InodeIndex` (fsnitch-core, new module `inode_index.rs`)

A compact, immutable-after-build lookup rebuilt on every snapshot:

- Storage: sorted `Vec<(dev: u64, ino: u64, root_idx: u32)>`, binary-searched by
  `(dev, ino)`. `root_idx` indexes into `CompiledPaths`' roots/policies so the
  matched policy is recoverable. Lower per-entry overhead than a `HashMap`; the
  lookup runs on the open hot path (fallback only), `O(log n)` is fine.
- Only **regular files** are indexed (directories, symlinks, sockets, fifos,
  devices skipped). A moved directory keeps its descendants' inodes, which we
  hold individually; a symlink open resolves to the target inode, held
  separately.
- Per-root degradation flag: if indexing a root would exceed
  `max_tracked_inodes`, that root is marked **degraded** — its inodes are dropped
  from the index (move protection off, path protection unchanged) and a loud
  `WARN` is logged. The set of degraded roots is queryable for status.

API sketch:

```rust
pub struct InodeIndex { /* sorted entries + degraded-root set + cap */ }
impl InodeIndex {
    pub fn policy_idx_for(&self, dev: u64, ino: u64) -> Option<usize>;
    pub fn degraded_roots(&self) -> &[String];
    pub fn len(&self) -> usize;
}
```

### 3. Scan (build)

At snapshot build (`state.rs::build_snapshot`, load + every reload), walk each
root recursively over **all descendants**, collect `(dev, ino)` of regular
files, tagged with the owning root. Nested roots: assign the most-specific root
(same tie-break as `policy_for`). Runs during the (already off-hot-path) reload;
initial startup scan happens before enforcement goes live, so there is no gating
of the scan's own reads.

### 4. Enforcement wiring

- `backend.rs`: `AccessEvent` gains `dev: u64, ino: u64`.
- `fanotify.rs::next_events`: `fstat` the event fd (already owned) to fill
  `dev`/`ino`. One extra `fstat` per open — negligible next to the existing
  `/proc/self/fd` readlink.
- `rules.rs`: `CompiledPaths::policy_for_inode(&index, dev, ino) -> Option<&PathPolicy>`.
- `engine.rs::decide_event`: after the existing `policy_for(path)` returns
  `None`, fall back to `policy_for_inode`. Everything downstream (modes, pins,
  overlay, snooze, prompt) is unchanged. Log record: `path` = policy root,
  `file` = current path (e.g. `/tmp/secret.kdbx`), matching `make_record`.
- `main.rs`: pass `event.dev`/`event.ino` into `decide_event`; the index lives on
  the snapshot.

The daemon's own-pid auto-allow and unresolved-path fail-open branches are
untouched and still take precedence.

### 5. inotify freshness watcher

A dedicated thread owns an `Inotify` instance:

- On (re)build, add a directory watch (`IN_CREATE | IN_MOVED_TO | IN_MOVED_FROM |
  IN_DELETE`, with `IN_ONLYDIR` so the watch target must be a directory) on each
  directory under each non-degraded root, recursively. Files need no watch of
  their own — their create/move/delete are reported by the parent directory's
  watch.
- `IN_CREATE` / `IN_MOVED_TO` for a regular file → `stat` it, insert
  `(dev, ino)` into the live index; track `name → (dev, ino)` in that dir's
  bookkeeping. If the name displaced a previous inode no longer referenced by any
  tracked name, evict it.
- `IN_CREATE | IN_ISDIR` / `IN_MOVED_TO | IN_ISDIR` → add a watch for the new
  subdirectory (recursion), then scan its existing contents.
- `IN_MOVED_FROM` → drop the `name` reference but **keep** the inode in the index
  (this is exactly the protection travelling with the file).
- `IN_DELETE` → drop the `name` reference and evict the inode if no tracked name
  still references it.
- Watch-count is bounded by the same `max_tracked_inodes` budget; exceeding it
  degrades the affected root exactly like the scan path (path protection stays,
  loud WARN).

Reload rebuilds the watch set and index from scratch, which also clears any
residual stale entries.

### 5a. Architecture: one live index, outside the snapshot

The inode index is **not** part of `Snapshot` (snapshots are immutable, swapped
`Arc`s — they cannot be mutated live). Instead there is one `LiveInodeIndex`,
an `Arc` with interior mutability (`RwLock` over the sorted entries + degraded
set + a small `roots: Vec<Arc<str>>` table), shared between:

- the enforcement loop (reader, open hot path), and
- the inotify watcher thread (writer).

Index entries store `root_idx: u32` into the index's own `roots` table (kept
compact). At decision time `decide_event` takes the matched **root path string**
and resolves its policy against the *current* snapshot's `CompiledPaths` (exact
root lookup). This decouples the long-lived index from snapshot swaps: if a
reload removed that root, the lookup yields `None` → allow (correct — the path is
unprotected and the root is gone).

Reload sequence: `build_snapshot` swaps the snapshot as today, then signals the
watcher to re-seed — rescan the new roots and reset watches — producing a fresh
`LiveInodeIndex` state that is swapped in atomically. Enforcement always reads a
consistent index.

### 6. Eviction / inode reuse

Stale entries (an inode moved out of all watched dirs and later deleted where we
do not watch) only cause **over-blocking** — fail-safe, never a hole — and are
cleared on the next reload's full rebuild. In-tree churn (editor atomic-saves,
temp files) is evicted live via the `name → inode` bookkeeping above, so normal
churn does not creep toward the cap. No file-handle / `open_by_handle_at`
tracking (that route needs libc and was rejected with the fanotify-FID variant).

### 7. Status surfacing

The set of degraded roots (cap exceeded → move protection off) is exposed via the
control plane so `fsnitch status` can show it. A silent degradation is not
acceptable; it appears both as a startup/reload `WARN` and in status.

## Config surface

One new `[general]` key: `max_tracked_inodes` (default 1_000_000). No per-path
options. Inode-identity protection is on for every root by default; a root only
loses it by exceeding the cap (loudly).

## SECURITY.md changes

Refine the "Delete and rename" non-goal: same-filesystem `rename` is now covered
by inode-identity. Still out of scope, in the document's existing honest tone:
*delete*, *cross-filesystem move*, the create→move race window, and any root that
exceeded `max_tracked_inodes` (degraded to path-only, surfaced in status).

## Testing

Unit / integration tests that need **no root** (tempdirs):

- `InodeIndex`: build, sorted lookup, most-specific-root tie-break, cap →
  degradation (root dropped, flag set), regular-files-only filter.
- Scan over a tempdir tree, including nested roots and non-regular entries.
- `policy_for_inode` and the `decide_event` inode fallback (mirrors the existing
  `decide_event` test suite).
- inotify watcher: create / move-in / move-out / delete / new-subdir under a
  tempdir root drive the expected index mutations. inotify needs no privilege.

Root-only e2e (documented, run by the user with sudo): the full fanotify path
with the added `fstat`, and the end-to-end move-then-open scenario.

## Residual limits (by design, documented)

- create→move→open race before the inotify event is drained (inherent; no
  `CREATE_PERM`).
- cross-filesystem move (new inode; source read already gated).
- a root over `max_tracked_inodes` → path-only, surfaced in status.
- a moved-out-then-deleted-elsewhere inode stays indexed until the next reload
  (fail-safe over-block only).

## Touched files

- `fsnitch-core/src/config.rs` — `max_tracked_inodes`.
- `fsnitch-core/src/inode_index.rs` — new.
- `fsnitch-core/src/rules.rs` — `policy_for_inode`.
- `fsnitch-core/src/lib.rs` — module export.
- `fsnitchd/src/backend.rs` — `AccessEvent { dev, ino }`.
- `fsnitchd/src/fanotify.rs` — `fstat` in `next_events`.
- `fsnitchd/src/inode_watch.rs` — new (inotify thread).
- `fsnitchd/src/state.rs` — build/expose index in `Snapshot`; live index handle.
- `fsnitchd/src/engine.rs` — inode fallback in `decide_event`.
- `fsnitchd/src/main.rs` — pass `dev`/`ino`; spawn watcher.
- `fsnitchd/src/control.rs` — degraded-roots in status.
- `SECURITY.md`, `CONFIGURATION.md`, `CHANGELOG.md` (this repo keeps its
  changelog at the repo root — it is not a HumHub module).
