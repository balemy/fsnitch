//! Configuration model: /etc/fsnitch/config.toml + paths.d/*.toml drop-ins.
//! A protected `path` carries its whole policy: a `mode`, and fixed allow/deny
//! entries naming programs. Path is the identity — no names, no globs.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// How a path treats a program that is neither allowed nor denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Silently refuse (was "enforce").
    Block,
    /// Pop the prompt (was "prompt").
    Ask,
    /// Allow but log/notify (was "notify").
    Watch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailAction {
    Deny,
    Allow,
}

/// One fixed allow/deny entry: a program, optionally pinned to a sha256.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowEntry {
    pub program: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// A protected path and its policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathPolicy {
    pub path: String,
    pub mode: Mode,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<AllowEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<AllowEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct General {
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    #[serde(default = "default_fail")]
    pub on_no_answer: FailAction,
    #[serde(default = "default_fail")]
    pub on_no_agent: FailAction,
    #[serde(default = "default_log_file")]
    pub log_file: PathBuf,
    #[serde(default = "default_agent")]
    pub agent: PathBuf,
    #[serde(default = "default_max_pending")]
    pub max_pending: usize,
    #[serde(default = "default_require_agent_session")]
    pub require_agent_session: bool,
    #[serde(default = "default_max_tracked_inodes")]
    pub max_tracked_inodes: usize,
}

fn default_timeout() -> u64 {
    30
}
fn default_fail() -> FailAction {
    FailAction::Deny
}
fn default_log_file() -> PathBuf {
    PathBuf::from("/var/log/fsnitch/events.jsonl")
}
fn default_agent() -> PathBuf {
    PathBuf::from("/usr/bin/fsnitch-agent")
}
fn default_max_pending() -> usize {
    128
}
fn default_require_agent_session() -> bool {
    true
}
fn default_max_tracked_inodes() -> usize {
    1_000_000
}

impl Default for General {
    fn default() -> Self {
        General {
            timeout: default_timeout(),
            on_no_answer: default_fail(),
            on_no_agent: default_fail(),
            log_file: default_log_file(),
            agent: default_agent(),
            max_pending: default_max_pending(),
            require_agent_session: default_require_agent_session(),
            max_tracked_inodes: default_max_tracked_inodes(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub general: General,
    #[serde(default, rename = "path")]
    pub paths: Vec<PathPolicy>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse {path:?}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("path {path:?} must be absolute")]
    RelativePath { path: String },
    #[error("path {path:?} must be normalized (no '//', '/./', '..' or trailing slash)")]
    UnnormalizedPath { path: String },
    #[error("path {path:?}: program {program:?} {reason}")]
    InvalidProgram {
        path: String,
        program: String,
        reason: &'static str,
    },
    #[error("path {path:?}: program {program:?}: sha256 {pin:?} must be 64 hex chars")]
    InvalidSha256 {
        path: String,
        program: String,
        pin: String,
    },
    #[error(
        "path {path:?}: program {program:?} is in an unpinned allow and a deny; \
         add a sha256 pin to the allow (an unverifiable pin must fail safe)"
    )]
    ConflictingEntries { path: String, program: String },
    #[error("path {path:?} is protected more than once (a path has one policy)")]
    DuplicatePath { path: String },
}

impl Config {
    /// Parse a single TOML document (tests; `load` for the real dir layout).
    pub fn parse_str(s: &str) -> Result<Config, ConfigError> {
        let mut cfg: Config = toml::from_str(s).map_err(|source| ConfigError::Parse {
            path: PathBuf::from("<inline>"),
            source,
        })?;
        cfg.normalize();
        cfg.validate()?;
        Ok(cfg)
    }

    /// Load `<dir>/config.toml` plus `<dir>/paths.d/*.toml` drop-ins in
    /// lexicographic filename order. Both are optional.
    pub fn load(dir: &Path) -> Result<Config, ConfigError> {
        let main = dir.join("config.toml");
        let mut cfg: Config = if main.exists() {
            let text = std::fs::read_to_string(&main).map_err(|source| ConfigError::Io {
                path: main.clone(),
                source,
            })?;
            toml::from_str(&text).map_err(|source| ConfigError::Parse {
                path: main.clone(),
                source,
            })?
        } else {
            Config::default()
        };

        let paths_d = dir.join("paths.d");
        if paths_d.is_dir() {
            let mut entries: Vec<PathBuf> = Vec::new();
            for entry in std::fs::read_dir(&paths_d).map_err(|source| ConfigError::Io {
                path: paths_d.clone(),
                source,
            })? {
                let entry = entry.map_err(|source| ConfigError::Io {
                    path: paths_d.clone(),
                    source,
                })?;
                let p = entry.path();
                if p.extension().is_some_and(|e| e == "toml") {
                    entries.push(p);
                }
            }
            entries.sort();
            for p in entries {
                let text = std::fs::read_to_string(&p).map_err(|source| ConfigError::Io {
                    path: p.clone(),
                    source,
                })?;
                let drop_in: Config =
                    toml::from_str(&text).map_err(|source| ConfigError::Parse {
                        path: p.clone(),
                        source,
                    })?;
                cfg.paths.extend(drop_in.paths);
            }
        }

        cfg.normalize();
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        Self::validate_policies(&self.paths)
    }

    /// Validate a set of path policies (absolute normalized paths & programs,
    /// pin format, conflicting entries, duplicate paths). Public so the daemon
    /// can validate a candidate policy before persisting it.
    pub fn validate_policies(policies: &[PathPolicy]) -> Result<(), ConfigError> {
        let mut seen: Vec<&str> = Vec::new();
        for p in policies {
            if !p.path.starts_with('/') {
                return Err(ConfigError::RelativePath {
                    path: p.path.clone(),
                });
            }
            if !segments_normalized(&p.path) {
                return Err(ConfigError::UnnormalizedPath {
                    path: p.path.clone(),
                });
            }
            if seen.contains(&p.path.as_str()) {
                return Err(ConfigError::DuplicatePath {
                    path: p.path.clone(),
                });
            }
            seen.push(&p.path);

            for entry in p.allow.iter().chain(p.deny.iter()) {
                let program = entry.program.to_string_lossy();
                if !program.starts_with('/') {
                    return Err(ConfigError::InvalidProgram {
                        path: p.path.clone(),
                        program: program.into_owned(),
                        reason: "must be absolute",
                    });
                }
                if program.contains(['*', '?', '[', ']', '{', '}']) {
                    return Err(ConfigError::InvalidProgram {
                        path: p.path.clone(),
                        program: program.into_owned(),
                        reason: "must be a literal path without glob characters",
                    });
                }
                if !segments_normalized(&program) {
                    return Err(ConfigError::InvalidProgram {
                        path: p.path.clone(),
                        program: program.into_owned(),
                        reason: "must be normalized (no '//', '/./', '..' or trailing slash)",
                    });
                }
                if let Some(pin) = &entry.sha256 {
                    if pin.len() != 64 || !pin.chars().all(|c| c.is_ascii_hexdigit()) {
                        return Err(ConfigError::InvalidSha256 {
                            path: p.path.clone(),
                            program: program.into_owned(),
                            pin: pin.clone(),
                        });
                    }
                }
            }
            for allow in &p.allow {
                if allow.sha256.is_none() && p.deny.iter().any(|d| d.program == allow.program) {
                    return Err(ConfigError::ConflictingEntries {
                        path: p.path.clone(),
                        program: allow.program.to_string_lossy().into_owned(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Lowercase all sha256 pins to compare equal to computed digests.
    fn normalize(&mut self) {
        for p in &mut self.paths {
            for entry in p.allow.iter_mut().chain(p.deny.iter_mut()) {
                if let Some(pin) = &mut entry.sha256 {
                    pin.make_ascii_lowercase();
                }
            }
        }
    }
}

/// Whether every path segment is non-empty and neither `.` nor `..`
/// (no `//`, `/./`, `..`, or trailing slash; a bare "/" is allowed).
fn segments_normalized(path: &str) -> bool {
    if path == "/" {
        return true;
    }
    let segments: Vec<&str> = path.split('/').collect();
    for (i, seg) in segments.iter().enumerate() {
        if i == 0 {
            continue; // leading root slash → empty first segment
        }
        if seg.is_empty() || *seg == "." || *seg == ".." {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const PIN: &str = "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12";

    const SAMPLE: &str = r#"
        [general]
        timeout = 10
        on_no_agent = "allow"

        [[path]]
        path = "/home/luke/vaults"
        mode = "ask"
        allow = [
            { program = "/usr/bin/keepassxc" },
            { program = "/usr/bin/borg", sha256 = "AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12" },
        ]
    "#;

    #[test]
    fn parses_full_config() {
        let cfg = Config::parse_str(SAMPLE).unwrap();
        assert_eq!(cfg.general.timeout, 10);
        assert_eq!(cfg.general.on_no_agent, FailAction::Allow);
        assert_eq!(cfg.paths.len(), 1);
        let p = &cfg.paths[0];
        assert_eq!(p.path, "/home/luke/vaults");
        assert_eq!(p.mode, Mode::Ask);
        assert_eq!(p.allow[0].sha256, None);
        assert_eq!(p.allow[1].sha256.as_deref(), Some(PIN)); // lowercased
    }

    #[test]
    fn general_defaults_apply() {
        let cfg = Config::parse_str("").unwrap();
        assert_eq!(cfg.general.timeout, 30);
        assert_eq!(cfg.general.on_no_answer, FailAction::Deny);
        assert!(cfg.paths.is_empty());
    }

    #[test]
    fn rejects_relative_path() {
        let err = Config::parse_str("[[path]]\npath = \"rel\"\nmode = \"block\"\n");
        assert!(matches!(err, Err(ConfigError::RelativePath { .. })));
    }

    #[test]
    fn rejects_duplicate_path() {
        let toml =
            "[[path]]\npath = \"/a\"\nmode = \"block\"\n[[path]]\npath = \"/a\"\nmode = \"ask\"\n";
        assert!(matches!(
            Config::parse_str(toml),
            Err(ConfigError::DuplicatePath { .. })
        ));
    }

    #[test]
    fn policy_serializes_to_loadable_toml() {
        let policy = PathPolicy {
            path: "/home/u/vaults".into(),
            mode: Mode::Ask,
            allow: vec![AllowEntry {
                program: "/usr/bin/keepassxc".into(),
                sha256: None,
            }],
            deny: vec![],
        };
        #[derive(serde::Serialize)]
        struct Doc {
            #[serde(rename = "path")]
            paths: Vec<PathPolicy>,
        }
        let text = toml::to_string_pretty(&Doc {
            paths: vec![policy.clone()],
        })
        .unwrap();
        let cfg = Config::parse_str(&text).unwrap();
        assert_eq!(cfg.paths, vec![policy]);
    }

    #[test]
    fn max_tracked_inodes_default_and_parse() {
        assert_eq!(
            Config::parse_str("").unwrap().general.max_tracked_inodes,
            1_000_000
        );
        let cfg = Config::parse_str("[general]\nmax_tracked_inodes = 42\n").unwrap();
        assert_eq!(cfg.general.max_tracked_inodes, 42);
    }

    #[test]
    fn require_agent_session_defaults_true_and_parses() {
        assert!(Config::parse_str("").unwrap().general.require_agent_session);
        let cfg = Config::parse_str("[general]\nrequire_agent_session = false\n").unwrap();
        assert!(!cfg.general.require_agent_session);
    }
}
