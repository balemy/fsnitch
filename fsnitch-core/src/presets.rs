//! Curated preset packs: named bundles of well-known sensitive paths a user
//! can protect in one command. Pure data + helpers; the CLI drives application.

use crate::config::Mode;
use std::path::{Path, PathBuf};

pub struct Preset {
    pub name: &'static str,
    pub description: &'static str,
    /// Default mode; the CLI's --mode overrides.
    pub mode: Mode,
    /// Each entry is absolute or starts with `~`/`~/` (expanded per user).
    pub paths: &'static [&'static str],
}

pub const PRESETS: &[Preset] = &[
    Preset {
        name: "browsers",
        description: "Browser profiles and cookie stores",
        mode: Mode::Ask,
        paths: &[
            "~/.mozilla",
            "~/.config/google-chrome",
            "~/.config/chromium",
            "~/.config/BraveSoftware",
            "~/.config/microsoft-edge",
        ],
    },
    Preset {
        name: "ssh",
        description: "SSH keys and known hosts",
        mode: Mode::Ask,
        paths: &["~/.ssh"],
    },
    Preset {
        name: "gnupg",
        description: "GnuPG keyring and trust database",
        mode: Mode::Ask,
        paths: &["~/.gnupg"],
    },
    Preset {
        name: "password-managers",
        description: "Password stores and keyrings",
        mode: Mode::Ask,
        paths: &[
            "~/.password-store",
            "~/.local/share/keyrings",
            "~/.config/keepassxc",
        ],
    },
    Preset {
        name: "crypto-wallets",
        description: "Cryptocurrency wallet data",
        mode: Mode::Ask,
        paths: &[
            "~/.electrum",
            "~/.bitcoin",
            "~/.ethereum",
            "~/.bitmonero",
            "~/Monero/wallets",
            "~/.config/Exodus",
            "~/.config/Ledger Live",
        ],
    },
    Preset {
        name: "dev-credentials",
        description: "Cloud and developer credential files",
        mode: Mode::Ask,
        paths: &[
            "~/.aws",
            "~/.config/gh",
            "~/.docker/config.json",
            "~/.kube",
            "~/.netrc",
        ],
    },
];

pub fn find(name: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|p| p.name == name)
}

/// Substitute a leading `~` / `~/` with `home`. Absolute paths and paths
/// without a leading `~` are returned joined/verbatim as appropriate.
pub fn expand_home(path: &str, home: &Path) -> PathBuf {
    if path == "~" {
        return home.to_path_buf();
    }
    if let Some(rest) = path.strip_prefix("~/") {
        return home.join(rest);
    }
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_tilde_slash() {
        assert_eq!(
            expand_home("~/.ssh", Path::new("/home/luke")),
            PathBuf::from("/home/luke/.ssh")
        );
    }

    #[test]
    fn expand_bare_tilde() {
        assert_eq!(
            expand_home("~", Path::new("/home/luke")),
            PathBuf::from("/home/luke")
        );
    }

    #[test]
    fn absolute_path_unchanged() {
        assert_eq!(
            expand_home("/etc/thing", Path::new("/home/luke")),
            PathBuf::from("/etc/thing")
        );
    }

    #[test]
    fn find_hit_and_miss() {
        assert!(find("ssh").is_some());
        assert_eq!(find("ssh").unwrap().paths, &["~/.ssh"]);
        assert!(find("nope").is_none());
    }

    #[test]
    fn preset_invariants() {
        let mut seen = std::collections::HashSet::new();
        for p in PRESETS {
            assert!(!p.name.is_empty(), "empty preset name");
            assert!(seen.insert(p.name), "duplicate preset name: {}", p.name);
            assert!(!p.description.is_empty(), "empty description: {}", p.name);
            assert!(!p.paths.is_empty(), "preset {} has no paths", p.name);
            for path in p.paths {
                assert!(
                    path.starts_with('/') || path.starts_with('~'),
                    "preset {} path {path:?} is neither absolute nor ~-relative",
                    p.name
                );
            }
        }
    }
}
