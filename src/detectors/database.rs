use crate::config::Config;
use crate::detector::Detector;
use crate::entropy::is_likely_false_positive;
use crate::fingerprint::compute_fingerprint;
use crate::models::{Finding, Severity};
use regex::Regex;
use std::path::Path;

pub struct DatabaseUriDetector {
    uri_regex: Regex,
}

impl Default for DatabaseUriDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DatabaseUriDetector {
    pub fn new() -> Self {
        Self {
            uri_regex: Regex::new(
                r#"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://(?:[a-zA-Z0-9_\-\.]*):([^@\s/]+)@[\w\.\-]+(?::\d+)?(?:/[^\s"';]*)?"#,
            )
            .unwrap(),
        }
    }
}

impl Detector for DatabaseUriDetector {
    fn id(&self) -> &'static str {
        "database_connection_string"
    }

    fn name(&self) -> &'static str {
        "Database Connection String"
    }

    fn category(&self) -> &'static str {
        "Database Credentials"
    }

    fn description(&self) -> &'static str {
        "Detects database URIs with embedded authentication credentials"
    }

    fn default_severity(&self) -> Severity {
        Severity::High
    }

    fn scan_line(
        &self,
        line: &str,
        line_num: usize,
        file_path: &Path,
        _config: &Config,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for cap in self.uri_regex.captures_iter(line) {
            if let Some(pwd_match) = cap.get(1) {
                let password = pwd_match.as_str();

                // Suppress documentation examples and placeholders
                if is_likely_false_positive(password) {
                    continue;
                }

                let full_match = cap.get(0).unwrap();
                let fp = compute_fingerprint(full_match.as_str());

                findings.push(Finding {
                    detector: self.id().to_string(),
                    category: self.category().to_string(),
                    severity: self.default_severity(),
                    file: file_path.to_string_lossy().to_string(),
                    line: line_num,
                    column: full_match.start() + 1,
                    fingerprint: fp,
                    confidence: 0.95,
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_uri_detection() {
        let detector = DatabaseUriDetector::new();
        let line = "DATABASE_URL=postgres://admin:SuperSecretPass123!@db.internal:5432/production";
        let findings = detector.scan_line(line, 5, Path::new(".env"), &Config::default());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_database_uri_redis_empty_username() {
        let detector = DatabaseUriDetector::new();
        let line = "REDIS_URL=redis://:K8j2n9Xm4pL1qR5t@cache-cluster.internal:6379/0";
        let findings = detector.scan_line(line, 2, Path::new(".env"), &Config::default());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_database_uri_credential_free_ignored() {
        let detector = DatabaseUriDetector::new();
        let line = "DATABASE_URL=postgres://localhost:5432/production_db";
        let findings = detector.scan_line(line, 1, Path::new("config.toml"), &Config::default());
        assert!(
            findings.is_empty(),
            "Credential-free database URIs should not produce findings"
        );
    }
}
