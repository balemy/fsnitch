//! Compiled path set: longest-prefix matching. A protected path covers itself
//! and everything beneath it; the most-specific (longest) match wins.

use crate::config::{Config, PathPolicy};
use std::path::{Path, PathBuf};

pub struct CompiledPaths {
    policies: Vec<PathPolicy>,
    roots: Vec<PathBuf>,
}

impl CompiledPaths {
    /// Build from config. Paths are already validated (absolute, normalized,
    /// unique) by `Config`.
    pub fn compile(cfg: &Config) -> CompiledPaths {
        let policies = cfg.paths.clone();
        let mut roots: Vec<PathBuf> = policies.iter().map(|p| PathBuf::from(&p.path)).collect();
        roots.sort();
        roots.dedup();
        CompiledPaths { policies, roots }
    }

    /// The protected paths themselves (for fanotify filesystem marking).
    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// The policy governing `path`: the longest protected path that is a
    /// component-wise prefix of (or equal to) `path`. `None` = not protected.
    pub fn policy_for(&self, path: &Path) -> Option<&PathPolicy> {
        self.policies
            .iter()
            .filter(|p| path.starts_with(&p.path))
            .max_by_key(|p| Path::new(&p.path).components().count())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::path::Path;

    fn compile(toml: &str) -> CompiledPaths {
        CompiledPaths::compile(&Config::parse_str(toml).unwrap())
    }

    const CFG: &str = r#"
        [[path]]
        path = "/home/luke/vaults"
        mode = "block"

        [[path]]
        path = "/home/luke/.config/chromium"
        mode = "ask"
    "#;

    #[test]
    fn covers_path_and_descendants() {
        let paths = compile(CFG);
        assert_eq!(
            paths
                .policy_for(Path::new("/home/luke/vaults"))
                .unwrap()
                .path,
            "/home/luke/vaults"
        );
        assert_eq!(
            paths
                .policy_for(Path::new("/home/luke/vaults/x/y/b.kdbx"))
                .unwrap()
                .path,
            "/home/luke/vaults"
        );
        assert!(paths.policy_for(Path::new("/home/luke/other")).is_none());
    }

    #[test]
    fn most_specific_path_wins() {
        let paths = compile(
            r#"
            [[path]]
            path = "/data"
            mode = "block"

            [[path]]
            path = "/data/secret"
            mode = "ask"
        "#,
        );
        assert_eq!(
            paths.policy_for(Path::new("/data/x")).unwrap().path,
            "/data"
        );
        assert_eq!(
            paths.policy_for(Path::new("/data/secret/x")).unwrap().path,
            "/data/secret"
        );
    }

    #[test]
    fn prefix_is_component_wise() {
        let paths = compile("[[path]]\npath = \"/home/luke/vaults\"\nmode = \"block\"\n");
        // "/home/luke/vaultsfake" must NOT match "/home/luke/vaults".
        assert!(paths
            .policy_for(Path::new("/home/luke/vaultsfake/x"))
            .is_none());
    }

    #[test]
    fn roots_are_the_paths() {
        let paths = compile(CFG);
        assert!(paths.roots().contains(&PathBuf::from("/home/luke/vaults")));
    }
}
