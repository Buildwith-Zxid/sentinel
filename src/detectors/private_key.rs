use crate::config::Config;
use crate::detector::Detector;
use crate::fingerprint::compute_fingerprint;
use crate::models::{Finding, Severity};
use regex::Regex;
use std::path::Path;

pub struct PrivateKeyDetector {
    header_regex: Regex,
}

impl Default for PrivateKeyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivateKeyDetector {
    pub fn new() -> Self {
        Self {
            header_regex: Regex::new(
                r"-----BEGIN\s+(?:[A-Z0-9_\-]+\s+)?PRIVATE\s+KEY(?:\s+BLOCK)?-----",
            )
            .unwrap(),
        }
    }
}

impl Detector for PrivateKeyDetector {
    fn id(&self) -> &'static str {
        "private_key"
    }

    fn name(&self) -> &'static str {
        "Private Key"
    }

    fn category(&self) -> &'static str {
        "Cryptographic Material"
    }

    fn description(&self) -> &'static str {
        "Detects RSA, DSA, EC, OpenSSH, and PKCS#8 private key header blocks"
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn scan_line(
        &self,
        line: &str,
        line_num: usize,
        file_path: &Path,
        _config: &Config,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(m) = self.header_regex.find(line) {
            // Fingerprint the header itself without storing/reading the private key body
            let header_str = m.as_str();
            let fp = compute_fingerprint(header_str);

            findings.push(Finding {
                detector: self.id().to_string(),
                category: self.category().to_string(),
                severity: self.default_severity(),
                file: file_path.to_string_lossy().to_string(),
                line: line_num,
                column: m.start() + 1,
                fingerprint: fp,
                confidence: 1.0,
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_key_detection() {
        let detector = PrivateKeyDetector::new();
        let samples = [
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN DSA PRIVATE KEY-----",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        ];

        for sample in samples {
            let findings = detector.scan_line(sample, 1, Path::new("id_rsa"), &Config::default());
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Critical);
        }
    }
}
