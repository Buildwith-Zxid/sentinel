use crate::config::Config;
use crate::detector::Detector;
use crate::entropy::{is_likely_false_positive, shannon_entropy};
use crate::fingerprint::compute_fingerprint;
use crate::models::{Finding, Severity};
use regex::Regex;
use std::path::Path;

pub struct AwsDetector {
    access_key_regex: Regex,
    secret_key_regex: Regex,
}

impl Default for AwsDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AwsDetector {
    pub fn new() -> Self {
        Self {
            access_key_regex: Regex::new(r"\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b").unwrap(),
            secret_key_regex: Regex::new(
                r#"(?i)(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?"#,
            )
            .unwrap(),
        }
    }
}

impl Detector for AwsDetector {
    fn id(&self) -> &'static str {
        "aws_access_key"
    }

    fn name(&self) -> &'static str {
        "AWS Access Key"
    }

    fn category(&self) -> &'static str {
        "Cloud Credentials"
    }

    fn description(&self) -> &'static str {
        "Detects AWS Access Key IDs (AKIA/ABIA/ACCA/ASIA) and associated secret keys"
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

        // 1. AWS Access Key IDs
        for cap in self.access_key_regex.captures_iter(line) {
            if let Some(m) = cap.get(1) {
                let key_str = m.as_str();
                if is_likely_false_positive(key_str) {
                    continue;
                }

                let fp = compute_fingerprint(key_str);
                findings.push(Finding {
                    detector: self.id().to_string(),
                    category: self.category().to_string(),
                    severity: self.default_severity(),
                    file: file_path.to_string_lossy().to_string(),
                    line: line_num,
                    column: m.start() + 1,
                    fingerprint: fp,
                    confidence: 0.98,
                });
            }
        }

        // 2. AWS Secret Access Keys in context
        for cap in self.secret_key_regex.captures_iter(line) {
            if let Some(m) = cap.get(1) {
                let secret_str = m.as_str();
                if is_likely_false_positive(secret_str) {
                    continue;
                }

                // AWS secret keys have high character entropy
                let entropy = shannon_entropy(secret_str);
                if entropy < 3.5 {
                    continue;
                }

                let fp = compute_fingerprint(secret_str);
                findings.push(Finding {
                    detector: "aws_secret_key".to_string(),
                    category: self.category().to_string(),
                    severity: Severity::High,
                    file: file_path.to_string_lossy().to_string(),
                    line: line_num,
                    column: m.start() + 1,
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
    fn test_aws_access_key_detection() {
        let detector = AwsDetector::new();
        let line = "let key = \"AKIA1234567890ABCDEF\";";
        let findings = detector.scan_line(line, 10, Path::new("config.rs"), &Config::default());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].line, 10);
    }
}
