use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub const DEFAULT_MAX_FILE_SIZE: u64 = 5 * 1024 * 1024; // 5 MB
pub const DEFAULT_MIN_ENTROPY: f64 = 4.0;
pub const CONFIG_FILE_NAME: &str = ".leakguard.toml";
pub const LEGACY_CONFIG_FILE_NAME: &str = ".sentinel.toml";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    pub ignore: IgnoreConfig,
    #[serde(default)]
    pub allowlist: AllowlistConfig,
    #[serde(default)]
    pub entropy: EntropyConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    #[serde(default = "default_max_file_size")]
    pub max_file_size: u64,
    #[serde(default)]
    pub follow_symlinks: bool,
    #[serde(default)]
    pub workers: usize,
}

fn default_max_file_size() -> u64 {
    DEFAULT_MAX_FILE_SIZE
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            follow_symlinks: false,
            workers: 0,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IgnoreConfig {
    #[serde(default)]
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AllowlistConfig {
    #[serde(default)]
    pub fingerprints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyConfig {
    #[serde(default = "default_minimum_entropy")]
    pub minimum: f64,
}

fn default_minimum_entropy() -> f64 {
    DEFAULT_MIN_ENTROPY
}

impl Default for EntropyConfig {
    fn default() -> Self {
        Self {
            minimum: DEFAULT_MIN_ENTROPY,
        }
    }
}

impl Config {
    /// Attempt to load configuration from a given file path.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file '{}': {}", path.display(), e))?;
        let mut config: Config = toml::from_str(&content)
            .map_err(|e| format!("Invalid TOML syntax in '{}': {}", path.display(), e))?;
        config.normalize();
        Ok(config)
    }

    /// Normalize and deduplicate configuration values.
    pub fn normalize(&mut self) {
        // Deduplicate allowlisted fingerprints
        self.allowlist.fingerprints.sort();
        self.allowlist.fingerprints.dedup();

        // Enforce valid entropy minimum
        if self.entropy.minimum.is_nan() || self.entropy.minimum < 0.0 {
            self.entropy.minimum = DEFAULT_MIN_ENTROPY;
        }
    }

    /// Automatically find and load `.leakguard.toml` (or legacy `.sentinel.toml`) in `dir` or default if not found.
    ///
    /// Returns an error if the configuration file exists but contains invalid TOML syntax.
    pub fn find_or_default(target_path: &Path) -> Result<(Self, Option<PathBuf>), String> {
        let (candidate, legacy_candidate) = if target_path.is_dir() {
            (
                target_path.join(CONFIG_FILE_NAME),
                target_path.join(LEGACY_CONFIG_FILE_NAME),
            )
        } else if let Some(parent) = target_path.parent() {
            (
                parent.join(CONFIG_FILE_NAME),
                parent.join(LEGACY_CONFIG_FILE_NAME),
            )
        } else {
            (
                PathBuf::from(CONFIG_FILE_NAME),
                PathBuf::from(LEGACY_CONFIG_FILE_NAME),
            )
        };

        if candidate.exists() && candidate.is_file() {
            let cfg = Self::from_file(&candidate)?;
            Ok((cfg, Some(candidate)))
        } else if legacy_candidate.exists() && legacy_candidate.is_file() {
            let cfg = Self::from_file(&legacy_candidate)?;
            Ok((cfg, Some(legacy_candidate)))
        } else {
            Ok((Self::default(), None))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.scan.max_file_size, DEFAULT_MAX_FILE_SIZE);
        assert!(!config.scan.follow_symlinks);
        assert_eq!(config.entropy.minimum, DEFAULT_MIN_ENTROPY);
        assert!(config.ignore.patterns.is_empty());
        assert!(config.allowlist.fingerprints.is_empty());
    }

    #[test]
    fn test_parse_toml() {
        let toml_str = r#"
        [scan]
        max_file_size = 1048576
        follow_symlinks = true
        workers = 4

        [ignore]
        patterns = ["fixtures/**", "*.lock"]

        [allowlist]
        fingerprints = ["abc123"]

        [entropy]
        minimum = 4.2
        "#;

        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.scan.max_file_size, 1048576);
        assert!(config.scan.follow_symlinks);
        assert_eq!(config.scan.workers, 4);
        assert_eq!(config.ignore.patterns.len(), 2);
        assert_eq!(config.allowlist.fingerprints, vec!["abc123"]);
        assert_eq!(config.entropy.minimum, 4.2);
    }
}
