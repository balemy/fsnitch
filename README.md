# fsnitch

Interactive file-access guard for the Linux desktop.

## What it does

fsnitch watches the files you care about most and lets only the programs you
trust open them:

- **You choose what to protect** — password vaults, browser profiles, crypto
  wallets, SSH keys, or any file or folder you name.
- **You decide who gets in** — when a program you haven't approved tries to open
  a protected file, you get a simple **allow / deny** prompt.
- **It remembers your choices** — trusted programs keep working without asking
  again; everything else is kept out.
- **You see that it's working** — a shield in your tray turns green when
  everything is running, and a settings window lets you manage it all without
  the command line.
- **It stops silent data theft** — the common trick where a program quietly
  reads your secrets and ships them off is blocked before it happens.

## What it is not

fsnitch is policy enforcement, **not a sandbox and not a malware scanner**. It
does not defend against root-level malware, an allowlisted program being abused
as a proxy (a browser, an interpreter, a shell), or code injected into a trusted
process. See [SECURITY.md](SECURITY.md) for the full threat model and its honest
limits — read it before you rely on fsnitch.

## Status

Approaching a 1.0 release. The enforcing daemon, the graphical prompt agent,
`sha256` program pinning, the rule CLI, and preset packs all work end to end.

The first version was developed and tested primarily on **Arch Linux** with
**Sway / wlroots** (the full-screen prompt overlay is a `wlr-layer-shell`
surface, with a plain-window fallback elsewhere). It should work on other
distros and compositors, but that's where it's proven.

On Sway, start the prompt agent and the tray from your Sway config
(`exec systemctl --user start fsnitch-agent fsnitch-gui`), since Sway doesn't activate
`graphical-session.target` on its own. Without a running agent, accesses that
should prompt are blocked silently. See [INSTALLATION.md](INSTALLATION.md).

## Docs

- **[INSTALLATION.md](INSTALLATION.md)** — install it (manual build or binary package)
- **[USAGE.md](USAGE.md)** — day-to-day use: protect paths, answer prompts, presets
- **[CONFIGURATION.md](CONFIGURATION.md)** — full config reference
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — how it works (daemon, agent, fanotify)
- **[DEVELOPER.md](DEVELOPER.md)** — build from source, tests, contributing
- **[SECURITY.md](SECURITY.md)** — threat model and vulnerability reporting

## License

MIT. See [LICENSE](LICENSE).
