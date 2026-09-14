use crate::config::Config;
use crate::detector::Detector;
use crate::entropy::is_likely_false_positive;
use crate::fingerprint::compute_fingerprint;
use crate::models::{Finding, Severity};
use regex::Regex;
use std::path::Path;

pub struct JwtTokenDetector {
    jwt_regex: Regex,
}

impl Default for JwtTokenDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl JwtTokenDetector {
    pub fn new() -> Self {
        Self {
            jwt_regex: Regex::new(
                r"\b(ey[A-Za-z0-9_\-]{10,}\.ey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b",
            )
            .unwrap(),
        }
    }
}

impl Detector for JwtTokenDetector {
    fn id(&self) -> &'static str {
        "jwt_token"
    }

    fn name(&self) -> &'static str {
        "JSON Web Token (JWT)"
    }

    fn category(&self) -> &'static str {
        "Authentication Tokens"
    }

    fn description(&self) -> &'static str {
        "Detects JSON Web Tokens (JWT) containing three base64url-encoded parts"
    }

    fn default_severity(&self) -> Severity {
        Severity::Medium
    }

    fn scan_line(
        &self,
        line: &str,
        line_num: usize,
        file_path: &Path,
        _config: &Config,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for cap in self.jwt_regex.captures_iter(line) {
            if let Some(m) = cap.get(1) {
                let token_str = m.as_str();
                if is_likely_false_positive(token_str) || !is_valid_jwt_structure(token_str) {
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
                    confidence: 0.90,
                });
            }
        }

        findings
    }
}

/// Strictly validates 3-part base64url JWT structure with standard header and payload prefixes.
fn is_valid_jwt_structure(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    // Both header and payload in valid JWTs are base64url encoded JSON objects starting with '{"', which encodes to 'ey'
    if !parts[0].starts_with("ey") || parts[0].len() < 8 {
        return false;
    }
    if !parts[1].starts_with("ey") || parts[1].len() < 8 {
        return false;
    }
    if parts[2].len() < 8 {
        return false;
    }
    // Characters must strictly belong to base64url character set
    for part in parts {
        if !part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_detection() {
        let detector = JwtTokenDetector::new();
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let line = format!("const token = \"{}\";", token);
        let findings = detector.scan_line(&line, 1, Path::new("auth.js"), &Config::default());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_arbitrary_dotted_string_rejected() {
        let detector = JwtTokenDetector::new();
        let line = "import module from 'com.example.enterprise.service.v1.0.0';";
        let findings = detector.scan_line(line, 1, Path::new("app.js"), &Config::default());
        assert!(
            findings.is_empty(),
            "Dotted package identifiers must not trigger JWT detector"
        );
    }
}
