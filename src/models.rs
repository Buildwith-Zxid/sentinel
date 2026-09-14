use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

/// Severity level heuristic for detected findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Return the numerical rank for comparison (Critical > High > Medium > Low).
    pub fn rank(&self) -> u8 {
        match self {
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Severity {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "low" => Ok(Severity::Low),
            "medium" | "med" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" | "crit" => Ok(Severity::Critical),
            other => Err(format!(
                "Unknown severity '{}'. Expected: low, medium, high, critical",
                other
            )),
        }
    }
}

/// Metadata model for a detected finding.
///
/// Crucial security guarantee: raw secrets are NEVER persisted in this model
/// to ensure no credential leakage in memory or outputs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub detector: String,
    pub category: String,
    pub severity: Severity,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub fingerprint: String,
    pub confidence: f32,
}

impl Finding {
    /// Produces a human-friendly title for terminal reports.
    pub fn detector_title(&self) -> &str {
        match self.detector.as_str() {
            "aws_access_key" => "AWS Access Key",
            "aws_secret_key" => "AWS Secret Key",
            "github_token" => "GitHub Token",
            "private_key" => "Private Key",
            "database_connection_string" => "Database Connection String",
            "jwt_token" => "JSON Web Token (JWT)",
            "bearer_token" => "Bearer Token",
            "generic_api_key" => "Generic API Key",
            "password_assignment" => "Password Assignment",
            "generic_credential" => "Generic Credential",
            "high_entropy_candidate" => "High-Entropy Secret Candidate",
            _ => &self.category,
        }
    }

    /// Produces a human-friendly redacted fingerprint: first 4 chars + •••• + last 4 chars.
    pub fn redacted_fingerprint(&self) -> String {
        if self.fingerprint.len() >= 8 {
            let start = &self.fingerprint[..4];
            let end = &self.fingerprint[self.fingerprint.len() - 4..];
            format!("{}••••{}", start, end)
        } else {
            "••••".to_string()
        }
    }
}

/// Statistics collected during a scan run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanStats {
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub duration_ms: u128,
}

/// Versioned machine-readable report schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema_version: u32,
    pub leakguard_version: String,
    pub path: String,
    pub stats: ScanStats,
    pub findings: Vec<Finding>,
}

impl ScanReport {
    pub const CURRENT_SCHEMA_VERSION: u32 = 1;

    pub fn new(path: String, stats: ScanStats, findings: Vec<Finding>) -> Self {
        Self {
            schema_version: Self::CURRENT_SCHEMA_VERSION,
            leakguard_version: env!("CARGO_PKG_VERSION").to_string(),
            path,
            stats,
            findings,
        }
    }
}

/// Rule metadata exposed via `leakguard rules`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorRuleInfo {
    pub id: String,
    pub name: String,
    pub category: String,
    pub description: String,
    pub default_severity: Severity,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
    }

    #[test]
    fn test_severity_from_str() {
        assert_eq!(Severity::from_str("high").unwrap(), Severity::High);
        assert_eq!(Severity::from_str("CRITICAL").unwrap(), Severity::Critical);
        assert!(Severity::from_str("invalid").is_err());
    }

    #[test]
    fn test_redacted_fingerprint() {
        let finding = Finding {
            detector: "test".into(),
            category: "test".into(),
            severity: Severity::High,
            file: "test.rs".into(),
            line: 1,
            column: 1,
            fingerprint: "8a21c43f9a72d3e18502f61e7b99c018a1a3b8d9e2f4c5b6a7d8e9f0123491cf".into(),
            confidence: 1.0,
        };
        assert_eq!(finding.redacted_fingerprint(), "8a21••••91cf");
    }
}
