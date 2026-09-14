use crate::config::Config;
use crate::detector::Detector;
use crate::entropy::{is_likely_false_positive, shannon_entropy};
use crate::fingerprint::compute_fingerprint;
use crate::models::{Finding, Severity};
use regex::Regex;
use std::path::Path;

// ==========================================
// 1. Bearer Token Detector
// ==========================================
pub struct BearerTokenDetector {
    regex: Regex,
}

impl Default for BearerTokenDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BearerTokenDetector {
    pub fn new() -> Self {
        Self {
            regex: Regex::new(r"(?i)\bBearer\s+([A-Za-z0-9_\-\.+=]{20,})\b").unwrap(),
        }
    }
}

impl Detector for BearerTokenDetector {
    fn id(&self) -> &'static str {
        "bearer_token"
    }

    fn name(&self) -> &'static str {
        "Bearer Token"
    }

    fn category(&self) -> &'static str {
        "Authentication Tokens"
    }

    fn description(&self) -> &'static str {
        "Detects HTTP Bearer authentication tokens in headers and configuration"
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

        for cap in self.regex.captures_iter(line) {
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
                    confidence: 0.92,
                });
            }
        }

        findings
    }
}

// ==========================================
// 2. Generic API Key Detector
// ==========================================
pub struct GenericApiKeyDetector {
    regex: Regex,
}

impl Default for GenericApiKeyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl GenericApiKeyDetector {
    pub fn new() -> Self {
        Self {
            regex: Regex::new(
                r#"(?i)(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*["']([A-Za-z0-9_\-]{16,64})["']"#,
            )
            .unwrap(),
        }
    }
}

impl Detector for GenericApiKeyDetector {
    fn id(&self) -> &'static str {
        "generic_api_key"
    }

    fn name(&self) -> &'static str {
        "Generic API Key"
    }

    fn category(&self) -> &'static str {
        "API Keys"
    }

    fn description(&self) -> &'static str {
        "Detects assignments to common API key variables"
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

        for cap in self.regex.captures_iter(line) {
            if let Some(m) = cap.get(1) {
                let key_str = m.as_str();
                if is_likely_false_positive(key_str) {
                    continue;
                }

                let entropy = shannon_entropy(key_str);
                if entropy < 3.2 {
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
                    confidence: 0.85,
                });
            }
        }

        findings
    }
}

// ==========================================
// 3. Password Assignment Detector
// ==========================================
pub struct PasswordAssignmentDetector {
    regex: Regex,
}

impl Default for PasswordAssignmentDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordAssignmentDetector {
    pub fn new() -> Self {
        Self {
            regex: Regex::new(
                r#"(?i)(?:password|passwd|pwd|db_pass)\s*[:=]\s*["']([^"'\s]{8,64})["']"#,
            )
            .unwrap(),
        }
    }
}

impl Detector for PasswordAssignmentDetector {
    fn id(&self) -> &'static str {
        "password_assignment"
    }

    fn name(&self) -> &'static str {
        "Password Assignment"
    }

    fn category(&self) -> &'static str {
        "Credentials"
    }

    fn description(&self) -> &'static str {
        "Detects hardcoded password assignments in configuration or source code"
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

        for cap in self.regex.captures_iter(line) {
            if let Some(m) = cap.get(1) {
                let pwd_str = m.as_str();
                if is_likely_false_positive(pwd_str) {
                    continue;
                }

                let entropy = shannon_entropy(pwd_str);
                if entropy < 2.5 {
                    continue;
                }

                let fp = compute_fingerprint(pwd_str);
                findings.push(Finding {
                    detector: self.id().to_string(),
                    category: self.category().to_string(),
                    severity: self.default_severity(),
                    file: file_path.to_string_lossy().to_string(),
                    line: line_num,
                    column: m.start() + 1,
                    fingerprint: fp,
                    confidence: 0.80,
                });
            }
        }

        findings
    }
}

// ==========================================
// 4. Generic Credential Detector
// ==========================================
pub struct GenericCredentialDetector {
    regex: Regex,
}

impl Default for GenericCredentialDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl GenericCredentialDetector {
    pub fn new() -> Self {
        Self {
            regex: Regex::new(
                r#"(?i)(?:auth[_-]?token|access[_-]?token|client[_-]?secret|webhook[_-]?secret|app[_-]?secret)\s*[:=]\s*["']([A-Za-z0-9_\-]{16,64})["']"#,
            )
            .unwrap(),
        }
    }
}

impl Detector for GenericCredentialDetector {
    fn id(&self) -> &'static str {
        "generic_credential"
    }

    fn name(&self) -> &'static str {
        "Generic Credential"
    }

    fn category(&self) -> &'static str {
        "Credentials"
    }

    fn description(&self) -> &'static str {
        "Detects generic credential variables such as client secrets, auth tokens, and webhook secrets"
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

        for cap in self.regex.captures_iter(line) {
            if let Some(m) = cap.get(1) {
                let cred_str = m.as_str();
                if is_likely_false_positive(cred_str) {
                    continue;
                }

                let entropy = shannon_entropy(cred_str);
                if entropy < 3.2 {
                    continue;
                }

                let fp = compute_fingerprint(cred_str);
                findings.push(Finding {
                    detector: self.id().to_string(),
                    category: self.category().to_string(),
                    severity: self.default_severity(),
                    file: file_path.to_string_lossy().to_string(),
                    line: line_num,
                    column: m.start() + 1,
                    fingerprint: fp,
                    confidence: 0.85,
                });
            }
        }

        findings
    }
}

// ==========================================
// 5. High-Entropy Credential Candidate
// ==========================================
pub struct HighEntropyCandidateDetector {
    candidate_regex: Regex,
}

impl Default for HighEntropyCandidateDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl HighEntropyCandidateDetector {
    pub fn new() -> Self {
        Self {
            candidate_regex: Regex::new(r#"["']([A-Za-z0-9_\-\+/=]{20,80})["']"#).unwrap(),
        }
    }
}

impl Detector for HighEntropyCandidateDetector {
    fn id(&self) -> &'static str {
        "high_entropy_candidate"
    }

    fn name(&self) -> &'static str {
        "High-Entropy Secret Candidate"
    }

    fn category(&self) -> &'static str {
        "Entropy Analysis"
    }

    fn description(&self) -> &'static str {
        "Detects unclassified strings exceeding Shannon entropy thresholds in suspicious contexts"
    }

    fn default_severity(&self) -> Severity {
        Severity::Low
    }

    fn scan_line(
        &self,
        line: &str,
        line_num: usize,
        file_path: &Path,
        config: &Config,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let lower_line = line.to_lowercase();

        // Must be in a suspicious context to avoid flagging random strings/blobs
        let has_context = lower_line.contains("key")
            || lower_line.contains("token")
            || lower_line.contains("secret")
            || lower_line.contains("auth")
            || lower_line.contains("cred")
            || lower_line.contains("pass");

        if !has_context {
            return findings;
        }

        for cap in self.candidate_regex.captures_iter(line) {
            if let Some(m) = cap.get(1) {
                let candidate = m.as_str();
                if is_likely_false_positive(candidate) {
                    continue;
                }

                let entropy = shannon_entropy(candidate);
                if entropy >= config.entropy.minimum {
                    let fp = compute_fingerprint(candidate);
                    findings.push(Finding {
                        detector: self.id().to_string(),
                        category: self.category().to_string(),
                        severity: self.default_severity(),
                        file: file_path.to_string_lossy().to_string(),
                        line: line_num,
                        column: m.start() + 1,
                        fingerprint: fp,
                        confidence: 0.65,
                    });
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bearer_token() {
        let detector = BearerTokenDetector::new();
        let line = "Authorization: Bearer dXNlcl9zZWNyZXRfdG9rZW5fMTIzNDU2";
        let findings = detector.scan_line(line, 1, Path::new("req.http"), &Config::default());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_generic_api_key() {
        let detector = GenericApiKeyDetector::new();
        let line = "api_key = \"n8fB32kLs91qMzXp78vRt45w\"";
        let findings = detector.scan_line(line, 2, Path::new("app.env"), &Config::default());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_password_assignment() {
        let detector = PasswordAssignmentDetector::new();
        let line = "password = \"N3v3rGu3ssTh1sP@ss!\"";
        let findings = detector.scan_line(line, 3, Path::new("db.cfg"), &Config::default());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }
}
