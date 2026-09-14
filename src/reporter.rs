use crate::models::{DetectorRuleInfo, Finding, ScanReport, Severity};
use std::io::{self, Write};

pub struct Reporter {
    no_color: bool,
}

impl Reporter {
    pub fn new(no_color: bool) -> Self {
        // Respect NO_COLOR standard (https://no-color.org/)
        let env_no_color = std::env::var("NO_COLOR").is_ok();
        Self {
            no_color: no_color || env_no_color,
        }
    }

    // Lightweight ANSI styling
    fn color_bold(&self, text: &str) -> String {
        if self.no_color {
            text.to_string()
        } else {
            format!("\x1b[1m{}\x1b[0m", text)
        }
    }

    fn color_dim(&self, text: &str) -> String {
        if self.no_color {
            text.to_string()
        } else {
            format!("\x1b[2m{}\x1b[0m", text)
        }
    }

    fn color_severity(&self, severity: Severity) -> String {
        if self.no_color {
            severity.to_string()
        } else {
            match severity {
                Severity::Critical => format!("\x1b[1;35m{}\x1b[0m", severity), // Bold Magenta
                Severity::High => format!("\x1b[1;31m{}\x1b[0m", severity),     // Bold Red
                Severity::Medium => format!("\x1b[1;33m{}\x1b[0m", severity),   // Bold Yellow
                Severity::Low => format!("\x1b[1;36m{}\x1b[0m", severity),      // Bold Cyan
            }
        }
    }

    fn color_success(&self, text: &str) -> String {
        if self.no_color {
            text.to_string()
        } else {
            format!("\x1b[1;32m{}\x1b[0m", text)
        }
    }

    fn color_danger(&self, text: &str) -> String {
        if self.no_color {
            text.to_string()
        } else {
            format!("\x1b[1;31m{}\x1b[0m", text)
        }
    }

    /// Outputs clean, professional human-readable terminal report.
    ///
    /// Never outputs raw secret contents.
    pub fn print_terminal(&self, report: &ScanReport) -> io::Result<()> {
        let stdout = io::stdout();
        let mut handle = stdout.lock();

        writeln!(handle, "{}", self.color_bold("LEAKGUARD SECURITY SCAN"))?;
        writeln!(
            handle,
            "{}",
            self.color_dim("────────────────────────────────────")
        )?;
        writeln!(handle)?;
        writeln!(handle, "Repository: {}", report.path)?;
        writeln!(handle)?;
        writeln!(handle, "Files scanned       {}", report.stats.files_scanned)?;
        writeln!(
            handle,
            "Files skipped        {}",
            report.stats.files_skipped
        )?;
        writeln!(handle, "Scan duration       {}ms", report.stats.duration_ms)?;
        writeln!(handle)?;
        writeln!(handle, "Findings             {}", report.findings.len())?;
        writeln!(handle)?;

        if !report.findings.is_empty() {
            for finding in &report.findings {
                self.print_finding(&mut handle, finding)?;
            }
            writeln!(
                handle,
                "{}",
                self.color_dim("────────────────────────────────────")
            )?;
            let msg = format!("✖ {} potential secret(s) detected", report.findings.len());
            writeln!(handle, "{}", self.color_danger(&msg))?;
        } else {
            writeln!(
                handle,
                "{}",
                self.color_dim("────────────────────────────────────")
            )?;
            writeln!(handle, "{}", self.color_success("✔ No secrets detected"))?;
        }

        handle.flush()
    }

    fn print_finding(&self, handle: &mut impl Write, finding: &Finding) -> io::Result<()> {
        let normalized_file = finding.file.replace('\\', "/");
        writeln!(handle, "{}", self.color_severity(finding.severity))?;
        writeln!(handle, "  {}", finding.detector_title())?;
        writeln!(handle, "  {}:{}", normalized_file, finding.line)?;
        writeln!(handle, "  fingerprint: {}", finding.redacted_fingerprint())?;
        writeln!(handle)
    }

    /// Outputs strictly valid machine-readable JSON to stdout.
    pub fn print_json(&self, report: &ScanReport) -> io::Result<()> {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        let json_str = serde_json::to_string_pretty(report).map_err(io::Error::other)?;
        writeln!(handle, "{}", json_str)?;
        handle.flush()
    }

    /// Formats the detector rules list for `leakguard rules`.
    pub fn print_rules(&self, rules: &[DetectorRuleInfo]) -> io::Result<()> {
        let stdout = io::stdout();
        let mut handle = stdout.lock();

        writeln!(handle, "{}", self.color_bold("LEAKGUARD DETECTOR RULES"))?;
        writeln!(
            handle,
            "{}",
            self.color_dim(
                "────────────────────────────────────────────────────────────────────────────────"
            )
        )?;
        writeln!(
            handle,
            "{:<26} {:<24} {:<10} DESCRIPTION",
            "RULE ID", "CATEGORY", "SEVERITY"
        )?;
        writeln!(
            handle,
            "{}",
            self.color_dim(
                "────────────────────────────────────────────────────────────────────────────────"
            )
        )?;

        for rule in rules {
            let sev_raw = rule.default_severity.to_string();
            let sev_str = self.color_severity(rule.default_severity);
            let padding = " ".repeat(10usize.saturating_sub(sev_raw.len()));
            writeln!(
                handle,
                "{:<26} {:<24} {}{} {}",
                rule.id, rule.category, sev_str, padding, rule.description
            )?;
        }
        writeln!(
            handle,
            "{}",
            self.color_dim(
                "────────────────────────────────────────────────────────────────────────────────"
            )
        )?;
        handle.flush()
    }
}
