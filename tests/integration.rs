use sentinel::config::Config;
use sentinel::models::{ScanReport, Severity};
use sentinel::scanner::Scanner;
use std::path::Path;

#[test]
fn test_scan_fixtures_detects_secrets() {
    let mut config = Config::default();
    // Do not ignore tests/fixtures for this scan
    config.ignore.patterns = vec![];

    let scanner = Scanner::new(config, None);
    let report = scanner
        .scan(Path::new("tests/fixtures"))
        .expect("Scan should succeed");

    assert!(report.stats.files_scanned > 0);
    assert!(
        !report.findings.is_empty(),
        "Should detect secrets in fixtures"
    );

    // Verify detection of AWS key
    let has_aws = report
        .findings
        .iter()
        .any(|f| f.detector == "aws_access_key");
    assert!(has_aws, "Should detect fake AWS access key");

    // Verify detection of GitHub token
    let has_github = report.findings.iter().any(|f| f.detector == "github_token");
    assert!(has_github, "Should detect fake GitHub token");

    // Verify detection of Private Key
    let has_pk = report.findings.iter().any(|f| f.detector == "private_key");
    assert!(has_pk, "Should detect fake private key");

    // Verify detection of Database URI
    let has_db = report
        .findings
        .iter()
        .any(|f| f.detector == "database_connection_string");
    assert!(has_db, "Should detect fake database URI");

    // Verify detection of JWT
    let has_jwt = report.findings.iter().any(|f| f.detector == "jwt_token");
    assert!(has_jwt, "Should detect fake JWT");
}

#[test]
fn test_secret_redaction_guarantee() {
    // Critical security test: verify raw credentials are NEVER present in finding models
    let mut config = Config::default();
    config.ignore.patterns = vec![];

    let scanner = Scanner::new(config, None);
    let report = scanner
        .scan(Path::new("tests/fixtures"))
        .expect("Scan should succeed");

    let fake_raw_secrets = [
        "AKIA9988776655443322",
        "ghp_11223344556677889900aabbccddeeffgghh",
        "SecretPassphrase987!",
        "K8j2n9Xm4pL1qR5t",
        "V3ryStr0ngP@ssw0rd!#99",
        "cs_live_44556677889900112233aabbccddeeff",
        "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
    ];

    let json_output = serde_json::to_string_pretty(&report).unwrap();

    for raw_secret in fake_raw_secrets {
        assert!(
            !json_output.contains(raw_secret),
            "CRITICAL SECURITY FAILURE: Raw secret '{}' found in JSON report output!",
            raw_secret
        );
    }

    for finding in &report.findings {
        let redacted = finding.redacted_fingerprint();
        assert!(
            redacted.contains("••••"),
            "Redacted fingerprint should contain •••• mask"
        );
        for raw_secret in fake_raw_secrets {
            assert_ne!(finding.fingerprint, raw_secret);
        }
    }
}

#[test]
fn test_false_positive_suppression() {
    let mut config = Config::default();
    config.ignore.patterns = vec![];

    let scanner = Scanner::new(config, None);
    let report = scanner
        .scan(Path::new("tests/fixtures"))
        .expect("Scan should succeed");

    // Safe UUIDs, safe commit SHAs, documentation examples, SHA-256, Docker digests, SRI hashes, templates, etc.
    for finding in &report.findings {
        let file = &finding.file;
        assert!(
            !file.contains("safe_uuid.json"),
            "Safe UUID file produced finding: {:?}",
            finding
        );
        assert!(
            !file.contains("safe_sha.txt"),
            "Safe Git SHA file produced finding: {:?}",
            finding
        );
        assert!(
            !file.contains("safe_sha256.txt"),
            "Safe SHA-256 file produced finding: {:?}",
            finding
        );
        assert!(
            !file.contains("safe_docker.yaml"),
            "Safe Docker digest file produced finding: {:?}",
            finding
        );
        assert!(
            !file.contains("safe_integrity.html"),
            "Safe SRI integrity file produced finding: {:?}",
            finding
        );
        assert!(
            !file.contains("safe_lockfile.json"),
            "Safe lockfile produced finding: {:?}",
            finding
        );
        assert!(
            !file.contains("safe_sourcemap.js"),
            "Safe sourcemap produced finding: {:?}",
            finding
        );
        assert!(
            !file.contains("safe_templates.env"),
            "Safe template env produced finding: {:?}",
            finding
        );
        assert!(
            !file.contains("safe_placeholders.yaml"),
            "Safe placeholders file produced finding: {:?}",
            finding
        );
        assert!(
            !file.contains("safe_docs.md"),
            "Safe docs file produced finding: {:?}",
            finding
        );
    }
}

#[test]
fn test_detector_overlap_deduplication() {
    let mut config = Config::default();
    config.ignore.patterns = vec![];

    let scanner = Scanner::new(config, None);
    let report = scanner
        .scan(Path::new("tests/fixtures"))
        .expect("Scan should succeed");

    // Ensure that no single line in any file has duplicate findings sharing the same fingerprint
    let mut seen_line_fingerprints = std::collections::HashSet::new();
    for finding in &report.findings {
        let key = (
            finding.file.clone(),
            finding.line,
            finding.fingerprint.clone(),
        );
        assert!(
            seen_line_fingerprints.insert(key.clone()),
            "Duplicate finding detected on same line with same fingerprint: {:?}",
            key
        );
    }
}

#[test]
fn test_binary_file_skipped() {
    let mut config = Config::default();
    config.ignore.patterns = vec![];

    let scanner = Scanner::new(config, None);
    let report = scanner
        .scan(Path::new("tests/fixtures"))
        .expect("Scan should succeed");

    for finding in &report.findings {
        assert!(
            !finding.file.contains("binary.dat"),
            "Binary file binary.dat should be skipped"
        );
    }
}

#[test]
fn test_severity_filter() {
    let mut config = Config::default();
    config.ignore.patterns = vec![];

    // Scan only for CRITICAL severity
    let scanner = Scanner::new(config, Some(Severity::Critical));
    let report = scanner
        .scan(Path::new("tests/fixtures"))
        .expect("Scan should succeed");

    for finding in &report.findings {
        assert_eq!(
            finding.severity,
            Severity::Critical,
            "Finding should be Critical"
        );
    }
    assert!(
        !report.findings.is_empty(),
        "Should find at least the fake private key"
    );
}

#[test]
fn test_allowlist_fingerprint_suppression() {
    let mut config = Config::default();
    config.ignore.patterns = vec![];

    let scanner_initial = Scanner::new(config.clone(), None);
    let initial_report = scanner_initial.scan(Path::new("tests/fixtures")).unwrap();

    let target_finding = initial_report
        .findings
        .first()
        .expect("Need a finding to allowlist");
    let target_fp = target_finding.fingerprint.clone();

    // Add fingerprint to allowlist
    config.allowlist.fingerprints.push(target_fp.clone());

    let scanner_filtered = Scanner::new(config, None);
    let filtered_report = scanner_filtered.scan(Path::new("tests/fixtures")).unwrap();

    assert!(
        filtered_report
            .findings
            .iter()
            .all(|f| f.fingerprint != target_fp),
        "Allowlisted fingerprint should be excluded"
    );
    assert_eq!(
        filtered_report.findings.len(),
        initial_report.findings.len() - 1
    );
}

#[test]
fn test_custom_ignore_pattern() {
    let mut config = Config::default();
    // Ignore all python files in fixtures
    config.ignore.patterns = vec!["**/*.py".to_string()];

    let scanner = Scanner::new(config, None);
    let report = scanner
        .scan(Path::new("tests/fixtures"))
        .expect("Scan should succeed");

    for finding in &report.findings {
        assert!(
            !finding.file.ends_with(".py"),
            "Python files should be ignored"
        );
    }
}

#[test]
fn test_max_file_size_filter() {
    let mut config = Config::default();
    // Set max file size to 10 bytes so all fixtures are skipped
    config.scan.max_file_size = 10;
    config.ignore.patterns = vec![];

    let scanner = Scanner::new(config, None);
    let report = scanner
        .scan(Path::new("tests/fixtures"))
        .expect("Scan should succeed");

    assert_eq!(report.findings.len(), 0);
    assert!(report.stats.files_skipped > 0);
}

#[test]
fn test_nonexistent_path_returns_error() {
    let config = Config::default();
    let scanner = Scanner::new(config, None);
    let result = scanner.scan(Path::new("this_path_does_not_exist_xyz123"));
    assert!(result.is_err(), "Nonexistent scan path should return Err");
}

#[test]
fn test_malformed_toml_returns_error() {
    let bad_toml = "this is not valid toml syntax = [";
    let tmp_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp_file.path(), bad_toml).unwrap();

    let result = Config::from_file(tmp_file.path());
    assert!(result.is_err(), "Malformed config must return Err");
}

#[test]
fn test_unicode_and_spaces_in_paths() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let sub_dir = tmp_dir.path().join("sub folder with spaces");
    std::fs::create_dir_all(&sub_dir).unwrap();
    let file_path = sub_dir.join("unicode_🚀_secret.env");
    std::fs::write(&file_path, "AWS_KEY=AKIA1122334455667788\n").unwrap();

    let config = Config::default();
    let scanner = Scanner::new(config, None);
    let report = scanner
        .scan(tmp_dir.path())
        .expect("Scan should succeed on Unicode paths");

    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].detector, "aws_access_key");
}

#[test]
fn test_extremely_long_line_handled_safely() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let file_path = tmp_dir.path().join("minified.js");
    // Write 200KB of repetitive non-secret text on a single line
    let huge_line = format!("var dummy = '{}';\n", "x".repeat(200_000));
    std::fs::write(&file_path, huge_line).unwrap();

    let config = Config::default();
    let scanner = Scanner::new(config, None);
    let report = scanner
        .scan(tmp_dir.path())
        .expect("Scan on long line should succeed safely");

    assert_eq!(report.findings.len(), 0);
    assert_eq!(report.stats.files_scanned, 1);
}

#[test]
fn test_versioned_json_schema() {
    let stats = sentinel::models::ScanStats {
        files_scanned: 10,
        files_skipped: 2,
        duration_ms: 15,
    };
    let report = ScanReport::new(".".to_string(), stats, vec![]);
    let json_val: serde_json::Value = serde_json::to_value(&report).unwrap();

    assert_eq!(json_val["schema_version"], 1);
    assert_eq!(json_val["sentinel_version"], "0.1.0");
    assert_eq!(json_val["stats"]["files_scanned"], 10);
    assert_eq!(json_val["stats"]["files_skipped"], 2);
    assert!(json_val["findings"].is_array());
}
