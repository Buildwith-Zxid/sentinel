use crate::config::Config;
use crate::detector::Detector;
use crate::entropy::is_likely_false_positive;
use crate::fingerprint::compute_fingerprint;
use crate::models::{Finding, Severity};
use regex::Regex;
use std::path::Path;

pub struct GitHubTokenDetector {
    token_regex: Regex,
}

impl Default for GitHubTokenDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl GitHubTokenDetector {
    pub fn new() -> Self {
        Self {
            token_regex: Regex::new(
                r"\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82})\b",
            )
            .unwrap(),
        }
    }
}

impl Detector for GitHubTokenDetector {
    fn id(&self) -> &'static str {
        "github_token"
    }

    fn name(&self) -> &'static str {
        "GitHub Token"
    }

    fn category(&self) -> &'static str {
        "Source Control"
    }

    fn description(&self) -> &'static str {
        "Detects GitHub Personal Access Tokens (classic and fine-grained), OAuth, and App tokens"
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

        for cap in self.token_regex.captures_iter(line) {
            if let Some(m) = cap.get(1) {
                let token_str = m.as_str();
                if is_likely_false_positive(token_str) {
                    continue;
                }

                let fp = compute_fingerprint(token_str);
                findings.push(Finding {
                    detector: self.id().to_string(),
                    category: self.category().to_string(),
                    severity: self.default_severity(),
                    file: file_path.to_string_lossy().to_string(),
                    line: line_num,
                    column: m.start() + 1,
                    fingerprint: fp,
                    confidence: 0.99,
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
    fn test_github_token_detection() {
        let detector = GitHubTokenDetector::new();
        let line = "export GITHUB_TOKEN=\"ghp_9876543210AbCdEfGhIjKlMnOpQrStUvWxYz\"";
        let findings = detector.scan_line(line, 4, Path::new("deploy.sh"), &Config::default());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }
}
