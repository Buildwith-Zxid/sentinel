use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use rayon::prelude::*;

use crate::config::Config;
use crate::detector::DetectorRegistry;
use crate::ignore::IgnoreEngine;
use crate::models::{Finding, ScanReport, ScanStats, Severity};

pub struct Scanner {
    config: Config,
    registry: DetectorRegistry,
    min_severity: Option<Severity>,
}

pub const MAX_INSPECTED_LINE_BYTES: usize = 65_536; // 64 KB max per line

impl Scanner {
    pub fn new(config: Config, min_severity: Option<Severity>) -> Self {
        Self {
            config,
            registry: DetectorRegistry::default_registry(),
            min_severity,
        }
    }

    /// Recursively scan a target path for exposed secrets.
    pub fn scan<P: AsRef<Path>>(&self, target_path: P) -> Result<ScanReport, String> {
        let start_time = Instant::now();
        let target = target_path.as_ref();

        if !target.exists() {
            return Err(format!("Scan path does not exist: {}", target.display()));
        }

        // Configure Rayon worker pool if explicitly specified
        if self.config.scan.workers > 0 {
            let _ = rayon::ThreadPoolBuilder::new()
                .num_threads(self.config.scan.workers)
                .build_global();
        }

        // Build directory traversal with ignore rules
        let ignore_engine = IgnoreEngine::new(self.config.ignore.patterns.clone());
        let overrides = ignore_engine.build_overrides(target)?;

        let mut walk_builder = ignore::WalkBuilder::new(target);
        walk_builder
            .follow_links(self.config.scan.follow_symlinks)
            .standard_filters(true)
            .overrides(overrides);

        let files_scanned_count = AtomicUsize::new(0);
        let files_skipped_count = AtomicUsize::new(0);

        // Collect all file paths
        let mut candidate_files: Vec<PathBuf> = Vec::new();
        for result in walk_builder.build() {
            match result {
                Ok(entry) => {
                    let path = entry.path();
                    if path.is_file() {
                        // Check if file is in default ignored directory
                        if IgnoreEngine::is_default_ignored_dir(path) {
                            files_skipped_count.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        candidate_files.push(path.to_path_buf());
                    }
                }
                Err(_) => {
                    // Gracefully skip unreadable or broken files/symlinks
                    files_skipped_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        // Parallel scan over candidate files
        let all_findings: Vec<Finding> = candidate_files
            .par_iter()
            .flat_map(|path| match self.scan_file(path) {
                Ok(findings) => {
                    files_scanned_count.fetch_add(1, Ordering::Relaxed);
                    findings
                }
                Err(_) => {
                    files_skipped_count.fetch_add(1, Ordering::Relaxed);
                    Vec::new()
                }
            })
            .collect();

        // Filter by allowlist and minimum severity
        let filtered_findings: Vec<Finding> = all_findings
            .into_iter()
            .filter(|f| {
                // Check allowlist
                if self.config.allowlist.fingerprints.contains(&f.fingerprint) {
                    return false;
                }
                // Check severity threshold
                if let Some(min_sev) = self.min_severity {
                    if f.severity < min_sev {
                        return false;
                    }
                }
                true
            })
            .collect();

        let duration = start_time.elapsed().as_millis();
        let stats = ScanStats {
            files_scanned: files_scanned_count.load(Ordering::SeqCst),
            files_skipped: files_skipped_count.load(Ordering::SeqCst),
            duration_ms: duration,
        };

        let normalized_root = target.to_string_lossy().replace('\\', "/");
        Ok(ScanReport::new(normalized_root, stats, filtered_findings))
    }

    /// Inspects and scans an individual file.
    fn scan_file(&self, path: &Path) -> Result<Vec<Finding>, String> {
        let metadata = std::fs::metadata(path)
            .map_err(|e| format!("Failed to read metadata for {}: {}", path.display(), e))?;

        // 1. File size check
        if metadata.len() > self.config.scan.max_file_size {
            return Err("File exceeds max_file_size limit".to_string());
        }

        // 2. Binary preflight check
        let mut file = File::open(path)
            .map_err(|e| format!("Failed to open file {}: {}", path.display(), e))?;

        if is_binary_file(&mut file)? {
            return Err("Binary file detected".to_string());
        }

        // Reset file pointer to beginning for scanning
        use std::io::Seek;
        file.rewind()
            .map_err(|e| format!("Failed to rewind file {}: {}", path.display(), e))?;

        // 3. Line-based content scan using bounded buffer reader
        let mut reader = BufReader::new(file);
        let mut findings = Vec::new();
        let mut line_buf = String::new();
        let mut line_num = 0usize;

        while let Ok(Some(_)) =
            read_bounded_line(&mut reader, &mut line_buf, MAX_INSPECTED_LINE_BYTES)
        {
            line_num += 1;
            let mut line_findings =
                self.registry
                    .scan_line(&line_buf, line_num, path, &self.config);

            // Deterministic deduplication: if multiple detectors match the same
            // secret (identical fingerprint) on the same line, keep the one with
            // highest severity rank and highest confidence.
            line_findings.sort_by(|a, b| {
                b.severity.cmp(&a.severity).then_with(|| {
                    b.confidence
                        .partial_cmp(&a.confidence)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
            });

            let mut seen_fingerprints = std::collections::HashSet::new();
            line_findings.retain(|f| seen_fingerprints.insert(f.fingerprint.clone()));

            for f in &mut line_findings {
                f.file = f.file.replace('\\', "/");
            }
            findings.append(&mut line_findings);
        }

        Ok(findings)
    }
}

/// Reads a line from `reader` up to `max_bytes` into `line_buf`.
///
/// If a line exceeds `max_bytes`, the excess bytes on that line are consumed and
/// discarded until `\n` without allocating unbounded memory.
fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    line_buf: &mut String,
    max_bytes: usize,
) -> std::io::Result<Option<usize>> {
    line_buf.clear();
    let mut raw_bytes = Vec::new();
    let mut total_bytes = 0usize;
    let mut truncated = false;

    loop {
        let available = match reader.fill_buf() {
            Ok([]) => break,
            Ok(buf) => buf,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };

        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            let consume_len = pos + 1;
            if !truncated {
                let remaining = max_bytes.saturating_sub(raw_bytes.len());
                let take = consume_len.min(remaining);
                raw_bytes.extend_from_slice(&available[..take]);
            }
            total_bytes += consume_len;
            reader.consume(consume_len);
            break;
        } else {
            let chunk_len = available.len();
            if !truncated {
                let remaining = max_bytes.saturating_sub(raw_bytes.len());
                let take = chunk_len.min(remaining);
                raw_bytes.extend_from_slice(&available[..take]);
                if raw_bytes.len() >= max_bytes {
                    truncated = true;
                }
            }
            total_bytes += chunk_len;
            reader.consume(chunk_len);
        }
    }

    if total_bytes == 0 {
        return Ok(None);
    }

    *line_buf = String::from_utf8_lossy(&raw_bytes).to_string();
    Ok(Some(total_bytes))
}

/// Content-based binary preflight check:
/// Inspects the first 8192 bytes for null bytes or a high ratio of non-printable control characters.
fn is_binary_file(file: &mut File) -> Result<bool, String> {
    let mut buffer = [0u8; 8192];
    let bytes_read = file
        .read(&mut buffer)
        .map_err(|e| format!("Failed to read preflight buffer: {}", e))?;

    if bytes_read == 0 {
        return Ok(false); // Empty files are safe to treat as text
    }

    let slice = &buffer[..bytes_read];

    // Null bytes strongly indicate binary files
    if slice.contains(&0) {
        return Ok(true);
    }

    // Check non-text byte ratio (excluding common whitespace \t, \n, \r)
    let non_text_count = slice
        .iter()
        .filter(|&&b| b < 32 && b != b'\t' && b != b'\n' && b != b'\r')
        .count();

    if (non_text_count as f64 / bytes_read as f64) > 0.10 {
        return Ok(true);
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_binary_detection_null_byte() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"Hello\x00World").unwrap();
        let mut f = File::open(file.path()).unwrap();
        assert!(is_binary_file(&mut f).unwrap());
    }

    #[test]
    fn test_binary_detection_text_file() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"Hello, this is a plain text file with normal words\nline 2")
            .unwrap();
        let mut f = File::open(file.path()).unwrap();
        assert!(!is_binary_file(&mut f).unwrap());
    }

    #[test]
    fn test_bounded_line_reader_truncates_safely() {
        use std::io::Cursor;
        // Create a line of 1000 'A' characters followed by newline
        let long_data = format!("{}\nline 2", "A".repeat(1000));
        let mut cursor = Cursor::new(long_data.as_bytes());

        let mut buf = String::new();
        // Limit line read to 100 bytes
        let bytes_consumed = read_bounded_line(&mut cursor, &mut buf, 100).unwrap();
        assert!(bytes_consumed.is_some());
        assert_eq!(buf.len(), 100);
        assert_eq!(buf, "A".repeat(100));

        // Next line should be "line 2"
        let next_consumed = read_bounded_line(&mut cursor, &mut buf, 100).unwrap();
        assert!(next_consumed.is_some());
        assert_eq!(buf, "line 2");
    }
}
