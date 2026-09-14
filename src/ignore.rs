use ignore::overrides::{Override, OverrideBuilder};
use std::path::Path;

/// Directories that LeakGuard skips by default regardless of configuration.
pub const DEFAULT_SKIPPED_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
];

/// Encapsulates ignore logic, combining default directory skips, .gitignore rules,
/// and custom patterns from .leakguard.toml and CLI arguments.
#[derive(Debug, Clone)]
pub struct IgnoreEngine {
    custom_patterns: Vec<String>,
}

impl IgnoreEngine {
    pub fn new(custom_patterns: Vec<String>) -> Self {
        Self { custom_patterns }
    }

    /// Check if a path component matches any default ignored directory name.
    pub fn is_default_ignored_dir(path: &Path) -> bool {
        for component in path.components() {
            if let std::path::Component::Normal(os_str) = component {
                if let Some(s) = os_str.to_str() {
                    if DEFAULT_SKIPPED_DIRS.contains(&s) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Build an `ignore::overrides::Override` matcher for directory walk filtering.
    pub fn build_overrides(&self, root_path: &Path) -> Result<Override, String> {
        let mut builder = OverrideBuilder::new(root_path);

        // Add default ignored directories as exclusions
        for dir in DEFAULT_SKIPPED_DIRS {
            let pattern = format!("!**/{}/**", dir);
            builder.add(&pattern).map_err(|e| {
                format!("Failed to add default ignore pattern '{}': {}", pattern, e)
            })?;
            let root_pattern = format!("!{}/**", dir);
            let _ = builder.add(&root_pattern);
        }

        // Add custom patterns (inverted if not already starting with '!')
        for pattern in &self.custom_patterns {
            let pat = if pattern.starts_with('!') {
                pattern.clone()
            } else {
                format!("!{}", pattern)
            };
            builder
                .add(&pat)
                .map_err(|e| format!("Invalid ignore pattern '{}': {}", pattern, e))?;
        }

        builder
            .build()
            .map_err(|e| format!("Failed to build ignore overrides: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_default_ignored_dir() {
        assert!(IgnoreEngine::is_default_ignored_dir(&PathBuf::from(
            "src/node_modules/package.json"
        )));
        assert!(IgnoreEngine::is_default_ignored_dir(&PathBuf::from(
            "target/debug/leakguard"
        )));
        assert!(IgnoreEngine::is_default_ignored_dir(&PathBuf::from(
            ".git/HEAD"
        )));
        assert!(!IgnoreEngine::is_default_ignored_dir(&PathBuf::from(
            "src/models.rs"
        )));
    }

    #[test]
    fn test_build_overrides() {
        let engine = IgnoreEngine::new(vec!["*.log".to_string(), "docs/**".to_string()]);
        let overrides = engine.build_overrides(Path::new(".")).unwrap();
        assert!(overrides.matched(Path::new("test.log"), false).is_ignore());
    }
}
