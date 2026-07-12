# fsnitch

Interactive file-access guard for the Linux desktop — the OpenSnitch idea,
applied to files.

A small root daemon watches the paths you declare sensitive — password vaults,
browser profiles, crypto wallets, SSH keys — and gates every `open()` on them.
Programs you've allowlisted pass; anything else is denied silently, allowed but
logged, or pops an interactive **allow / deny** prompt. It's built to stop the
common infostealer pattern: some unprivileged program quietly reading your
secrets and shipping them off.

A protected **path** covers itself and everything beneath it; when paths nest,
the most specific one wins.

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

## Docs

- **[INSTALLATION.md](INSTALLATION.md)** — install it (manual build or binary package)
- **[USAGE.md](USAGE.md)** — day-to-day use: protect paths, answer prompts, presets
- **[CONFIGURATION.md](CONFIGURATION.md)** — full config reference
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — how it works (daemon, agent, fanotify)
- **[DEVELOPER.md](DEVELOPER.md)** — build from source, tests, contributing
- **[SECURITY.md](SECURITY.md)** — threat model and vulnerability reporting

## License

MIT. See [LICENSE](LICENSE).
