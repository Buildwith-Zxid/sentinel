//! Example: Running LeakGuard programmatically via Rust API
use leakguard::{Config, Scanner, Severity};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Initializing LeakGuard programmatic scanner...");

    let config = Config::default();
    let scanner = Scanner::new(config, Some(Severity::Low));

    let report = scanner.scan(Path::new("."))?;

    println!("Scanned {} files", report.stats.files_scanned);
    println!("Skipped {} files", report.stats.files_skipped);
    println!("Findings: {}", report.findings.len());

    for finding in report.findings {
        println!(
            "[{}] {} at {}:{} (fingerprint: {})",
            finding.severity,
            finding.detector,
            finding.file,
            finding.line,
            finding.redacted_fingerprint()
        );
    }

    Ok(())
}
