use crate::config::Config;
use crate::models::{DetectorRuleInfo, Finding, Severity};
use std::path::Path;

/// Common interface for all modular secret detectors.
pub trait Detector: Send + Sync {
    /// Unique machine-readable identifier (e.g., "aws_access_key").
    fn id(&self) -> &'static str;

    /// Human-readable title (e.g., "AWS Access Key").
    fn name(&self) -> &'static str;

    /// Category of secret (e.g., "Cloud Provider", "VCS", "Cryptographic").
    fn category(&self) -> &'static str;

    /// Technical description of what the detector looks for.
    fn description(&self) -> &'static str;

    /// Default heuristic severity level.
    fn default_severity(&self) -> Severity;

    /// Scan a single line of text for secrets.
    ///
    /// Never stores or leaks the raw secret in the returned `Finding`s.
    fn scan_line(
        &self,
        line: &str,
        line_num: usize,
        file_path: &Path,
        config: &Config,
    ) -> Vec<Finding>;
}

/// Registry holding all active detectors in the pipeline.
pub struct DetectorRegistry {
    detectors: Vec<Box<dyn Detector>>,
}

impl DetectorRegistry {
    pub fn new(detectors: Vec<Box<dyn Detector>>) -> Self {
        Self { detectors }
    }

    /// Construct registry with all 10 default built-in detectors.
    pub fn default_registry() -> Self {
        use crate::detectors::{
            aws::AwsDetector,
            database::DatabaseUriDetector,
            generic::{
                BearerTokenDetector, GenericApiKeyDetector, GenericCredentialDetector,
                HighEntropyCandidateDetector, PasswordAssignmentDetector,
            },
            github::GitHubTokenDetector,
            jwt::JwtTokenDetector,
            private_key::PrivateKeyDetector,
        };

        let detectors: Vec<Box<dyn Detector>> = vec![
            Box::new(AwsDetector::new()),
            Box::new(GitHubTokenDetector::new()),
            Box::new(PrivateKeyDetector::new()),
            Box::new(DatabaseUriDetector::new()),
            Box::new(JwtTokenDetector::new()),
            Box::new(BearerTokenDetector::new()),
            Box::new(GenericApiKeyDetector::new()),
            Box::new(PasswordAssignmentDetector::new()),
            Box::new(GenericCredentialDetector::new()),
            Box::new(HighEntropyCandidateDetector::new()),
        ];

        Self { detectors }
    }

    /// Return metadata for all registered detector rules (used by `leakguard rules`).
    pub fn rules(&self) -> Vec<DetectorRuleInfo> {
        self.detectors
            .iter()
            .map(|d| DetectorRuleInfo {
                id: d.id().to_string(),
                name: d.name().to_string(),
                category: d.category().to_string(),
                description: d.description().to_string(),
                default_severity: d.default_severity(),
            })
            .collect()
    }

    /// Execute all registered detectors across a single line.
    pub fn scan_line(
        &self,
        line: &str,
        line_num: usize,
        file_path: &Path,
        config: &Config,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        for detector in &self.detectors {
            let mut line_findings = detector.scan_line(line, line_num, file_path, config);
            findings.append(&mut line_findings);
        }
        findings
    }
}
