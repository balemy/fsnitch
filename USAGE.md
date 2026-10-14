# Using fsnitch

The control plane is root-only, so the managing commands need `sudo`. The
prompt agent runs as you, in your graphical session. (`fsnitch preset list` and
`preset apply --dry-run` are the only commands that work unprivileged.)

## The basic workflow

1. Protect a path in `ask` mode:

   ```sh
   sudo fsnitch protect /home/you/vaults
   ```

2. The next time any program opens something under it, a prompt pops up
   (process, file, path, countdown). Pick a duration — **Just now · 15 min ·
   1 hour · Always** — then **Allow** or **Deny**. Keyboard: `a` allow, `Esc`/`d`
   deny, `A`/`D` for the "always" versions.

3. Answering **Allow → Always** records the program permanently, so it never
   prompts again. Over time you build up the allowlist by just answering.

You can also allow a program up front instead of waiting for the prompt:

```sh
sudo fsnitch protect /home/you/vaults --program /usr/bin/keepassxc
```

## The tray and manager window

`fsnitch-gui` puts a shield in your tray (waybar's `tray` module, KDE, or GNOME
with the AppIndicator extension):

- **green** — the daemon is running and your prompt agent is connected
- **yellow** — protection is limited: no agent (prompts are decided without
  asking), a path is paused, or move protection is off for a huge root
- **red** — the daemon is not reachable

Click it (or start **fsnitch** from your app launcher) to open the manager. The
sidebar lists your protected paths; each path's page shows its mode, lets you
pause it, and lists every program with its access (allowed / denied) and where
that comes from — a fixed rule, a remembered answer, or a timed one with its
time left. The trash button removes a rule or forgets an answer. The **Log**
page shows your own recent accesses.

Viewing needs no privileges. Every change asks for your password (polkit /
`pkexec`), so a polkit authentication agent must be running in your session —
GNOME and KDE ship one; on Sway start one such as `polkit-gnome` or
`lxqt-policykit`. Paths defined in drop-in files under `paths.d` are shown
read-only.

## Modes

Every protected path has a `mode` deciding what happens to a program that is
neither allowed nor denied:

- **`block`** — denied silently (still logged)
- **`ask`** — prompts you (needs the agent)
- **`watch`** — allowed but logged (good for learning what touches a path)

Set it with `--mode` on `protect` (default `ask`).

## Commands

```sh
sudo fsnitch protect <path> [--mode block|ask|watch] [--program P [--pin sha256|auto]]
sudo fsnitch protect <path> --program P --for 15m   # temporary timed allow (ask paths)
sudo fsnitch protect <path> --deny P                # deny one program (repeatable)
sudo fsnitch unprotect <path>                       # remove the whole path
sudo fsnitch unprotect <path> --program P           # remove just one program's allow/deny entry

fsnitch                 # = status: one section per protected path
fsnitch status
fsnitch show <path>     # status for a single path
fsnitch pause <path> [15m]   # everything passes for a while (memory-only)
fsnitch resume [<path>]
fsnitch forget <path> [--program P]   # drop remembered / temporary verdicts

fsnitch preset list                      # curated packs of well-known locations
sudo fsnitch preset apply browsers       # protect the ones that exist, in ask mode
sudo fsnitch preset apply ssh --dry-run  # preview, change nothing

fsnitch log [--follow]  # the event log
sudo fsnitch reload     # re-read config files after editing them
```

`protect` is additive: re-running it on the same path merges in the new
program(s) or mode instead of failing. `--deny` adds a fixed deny entry; a
denied program is refused even on a `watch` path or when it is also allowed.

Preset packs: `browsers`, `ssh`, `gnupg`, `password-managers`,
`crypto-wallets`, `dev-credentials`. `apply` protects every path in the pack
that exists on your machine and skips the rest.

## Pinning a program

Pin an allowed program to its content hash, so a swapped binary stops being
trusted until you reload:

```sh
sudo fsnitch protect /home/you/vaults --program /usr/bin/borg --pin auto
```

`--pin auto` hashes the binary now; pass a literal `sha256` to set it
explicitly.

## Config files

Most of the time the CLI is enough. To edit by hand, the config lives in
`/etc/fsnitch/` — a `config.toml` for `[general]` settings and `[[path]]`
blocks, plus drop-ins under `paths.d/*.toml`. Run `sudo fsnitch reload` after
editing. The full reference is in [CONFIGURATION.md](CONFIGURATION.md).

Reload caveat: `reload` re-reads policies but does not re-scan filesystems, so
protecting a path on a filesystem that had none before needs a daemon restart.
The `protect` CLI marks new filesystems at runtime and is not affected.

## Memory shown by systemd

After a reboot, `systemctl status fsnitchd` can report hundreds of MB of
memory. That number is the cgroup total, which includes kernel caches: the
daemon scans every file under your protected paths at startup (for move
protection), and on a cold boot it is the first process to touch them, so the
kernel's dentry/inode caches for all those files land on its account. This
cache is reclaimable — the kernel frees it automatically under memory
pressure. The daemon's own footprint is what `VmRSS` reports (roughly
300 bytes per tracked file):

```sh
grep VmRSS /proc/$(pidof fsnitchd)/status
```

Restarts later in the day show a small number for the same reason in reverse:
the caches are already warm and charged to whoever touched them first.
