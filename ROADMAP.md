# fsnitch Roadmap

High-level direction. See `CONFIGURATION.md` and `SECURITY.md` for how the
current features work and what they do (and don't) protect against.

## Guiding principle: lightweight by default, hardening is opt-in

The lightweight configuration works as broadly as possible — including on
systems without a graphical session, without systemd, headless, and in CI. All
hardening features are **optional**: each is a build feature and/or a config
toggle with a default chosen so the base build "just runs". Turning hardening on
is never required to get useful protection; it raises assurance for those who
want it.

Concretely: no *mandatory* runtime dependency on libsystemd, a graphical
session, or a specific desktop; every hardening gate degrades gracefully or is
compiled out when its prerequisite is absent.

## Where things stand

The core is in place: the enforcing fanotify daemon, the interactive GTK prompt
agent, `sha256` hash pinning, the `protect`/`unprotect --program` CLI, verdict
visibility and snooze, the path-centric policy model, preset packs, load-time
path canonicalization, and the opt-in agent session binding. Arch packaging
(AUR) and install docs exist.

## Toward 1.0

- **User & security docs** — a configuration reference and a consolidated
  security model with its honest limits.
- **Release hygiene** — a CHANGELOG, CI (build, test, clippy, fmt across both
  the base and hardened builds), and a tagged 1.0 release.

## Later

- **BPF-LSM enforcement backend** — fail-closed, kernel-side, surviving daemon
  death and covering more entry points (exec/mmap). Complements fanotify (which
  stays for interactive prompts) behind the existing backend abstraction.
- **Confused-deputy heuristics** — e.g. refuse a browser launched with
  `--remote-debugging-port`; detect an allowlisted program driven as a proxy.
- **systemd watchdog** — `sd_notify` + `WatchdogSec` so hangs (not just crashes)
  are recovered.
- Delete/rename gating (needs the LSM backend — fanotify permission events can't
  block unlink/rename), preset expansion, multi-user/multi-seat prompt routing,
  and further desktop integration.

All future hardening remains subject to the guiding principle: optional,
gracefully degrading, never required for the lightweight base to work.
