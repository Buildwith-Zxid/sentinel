# LeakGuard

> Native Rust secret and credential scanner for source repositories.

[![Rust](https://img.shields.io/badge/rust-stable-brightgreen.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Overview

LeakGuard is a Rust-only, local-first security CLI that detects accidentally exposed secrets and credentials in source repositories without uploading repository contents or requiring an external runtime.

LeakGuard scans source repositories locally for accidentally exposed credentials and secret-like values. It is designed around deterministic detection, bounded file processing, false-positive filtering, safe reporting, and zero repository uploads.

### Why LeakGuard?

Accidental credential exposure in source control is a frequent vulnerability in software engineering. Developers frequently hardcode tokens during debugging, embed credentials in local configuration files, or inadvertently commit `.env` files.

Existing scanners often introduce significant operational trade-offs:
- Requiring runtime dependencies such as Python, Node.js, or Docker containers.
- Emitting excessive false alarms on UUIDs, commit SHAs, lockfile integrity hashes, and template placeholders.
- Leaking credentials by printing raw matched text verbatim into console streams, CI logs, or error messages.
- Lacking deterministic exit codes or structured, machine-safe JSON schemas.

LeakGuard provides a single, self-contained native executable that prioritizes scanning speed, low false positive rates, bounded memory consumption, and strict non-leakage security guarantees.

---

## Architecture

LeakGuard executes an independent, deterministic multi-stage scanning pipeline:

```
Repository Root
      ↓
File Discovery (ignore::WalkBuilder - Gitignore-aware, hidden files, loop protection)
      ↓
Ignore / Filtering (.gitignore + .leakguard.toml + CLI --ignore + default skips)
      ↓
File Size Check (Filesystem metadata preflight against max_file_size, default 5MB)
      ↓
Binary Preflight (Initial 8KB inspection: null-byte detection & control-byte ratio)
      ↓
Bounded Buffered Reader (Capped line reading at 64KB to prevent memory exhaustion)
      ↓
Detector Registry (Trait-based modular detectors executed concurrently via Rayon)
      ↓
Pattern / Context / Entropy Analysis (Regex matching, identifier context, Shannon entropy)
      ↓
False Positive Filtering (UUIDs, commit SHAs, SHA-256 hashes, SRI digests, templates)
      ↓
Detector Deduplication (Retains highest severity/confidence on identical line findings)
      ↓
SHA-256 Fingerprinting (Immediate cryptographic digest; zero raw secret persistence)
      ↓
Terminal / JSON Reporter (Redacted console output or versioned schema v1 JSON)
```

### Pipeline Details

1. **File Discovery**: Recursively traverses directories using the `ignore` crate, respecting `.gitignore` files, parent ignore rules, and symlink protection (symlinks are not followed by default).
2. **Ignore / Filtering**: Skips built-in artifact directories (`.git`, `node_modules`, `target`, `dist`, `build`, `.venv`) and patterns declared in configuration or CLI flags.
3. **File Size Check**: Queries filesystem metadata prior to reading file contents, skipping files exceeding the configured limit (default: 5MB).
4. **Binary Preflight**: Evaluates the initial 8KB window for null bytes and excessive non-text control characters to skip compiled binaries and non-text media early.
5. **Bounded Buffered Reader**: Reads files using an internal 64KB bounded line buffer (`MAX_INSPECTED_LINE_BYTES`), guarding against memory exhaustion from gigantic single-line files (such as minified JavaScript bundles).
6. **Detector Registry**: Evaluates candidate lines concurrently across logical CPU cores using a thread-safe `rayon` worker pool.
7. **Pattern / Context / Entropy Analysis**: Combines structural signatures, assignment variable identifiers (`api_key`, `password`), and Shannon entropy thresholds ($H \ge 4.0$).
8. **False Positive Filtering**: Suppresses known non-secret patterns, digests, template syntax, and dummy credentials.
9. **Detector Deduplication**: When multiple detectors flag the same secret on the same line (e.g. `generic_credential` and `high_entropy_candidate`), findings are sorted by severity and confidence descending, retaining only the highest-priority finding.
10. **SHA-256 Fingerprinting**: Generates a deterministic SHA-256 digest of the match for machine-safe reporting and allowlisting.
11. **Terminal / JSON Reporter**: Formats findings for console output with safe masked fingerprints (`8a21••••91cf`) or strict machine-readable JSON.

---

## Detection Engine

LeakGuard includes 10 built-in detector rules implemented as trait-based modules:

| Detector ID | Category | Default Severity | Target Signatures & Validation Rules |
|:---|:---|:---|:---|
| `aws_access_key` | Cloud Credentials | `HIGH` | AWS Access Key IDs (`AKIA`, `ABIA`, `ACCA`, `ASIA` [20 characters]) and context-bound secret keys (40-char base64). |
| `github_token` | Source Control | `HIGH` | GitHub Personal Access Tokens (classic `ghp_`, fine-grained `github_pat_`, OAuth `gho_`, user/server `ghu_`/`ghs_`, refresh `ghr_`). |
| `private_key` | Cryptographic Material | `CRITICAL` | PEM header blocks: RSA, DSA, EC, OPENSSH, PGP, ENCRYPTED, and generic PKCS#8 (`BEGIN ... PRIVATE KEY`). |
| `database_connection_string` | Database Credentials | `HIGH` | Connection URIs containing embedded passwords for PostgreSQL, MySQL, MongoDB, Redis, AMQP, MSSQL (`scheme://[user]:password@host`). Excludes credential-free URIs. |
| `jwt_token` | Authentication Tokens | `MEDIUM` | Strict three-part base64url tokens starting with standard `ey...` header and payload prefixes. Rejects dotted package paths and documentation samples. |
| `bearer_token` | Authentication Tokens | `HIGH` | HTTP `Authorization: Bearer <token>` headers and bearer variable assignments with verified entropy. |
| `generic_api_key` | API Keys | `MEDIUM` | Assignment identifiers (`api_key`, `apikey`, `secret_key`, etc.) paired with high-entropy token strings. |
| `password_assignment` | Credentials | `MEDIUM` | Explicit password variable assignments (`password = "..."`, `db_pass = "..."`) excluding templates and placeholders. |
| `generic_credential` | Credentials | `MEDIUM` | Assignments to generic credential identifiers (`client_secret`, `auth_token`, `access_token`) with entropy verification. |
| `high_entropy_candidate` | Entropy Analysis | `LOW` | Unclassified candidate strings exceeding Shannon entropy thresholds ($H \ge 4.0$) inside credential-relevant contexts. |

---

## Security Model

LeakGuard adheres to explicit, privacy-preserving security invariants:

### Local-First
Repository contents remain strictly on the user's local machine. Scanning executes entirely offline.

### No Telemetry
LeakGuard contains no telemetry, tracking, phone-home mechanisms, or remote analytics. It never transmits repository metadata or source code.

### No External Runtime
LeakGuard compiles directly into a standalone native binary without dependencies on Python, Node.js, Docker, Java, or external runtime interpreters.

### Secret Redaction
Raw detected secret values are **never** persisted in `Finding` structs, never stored in `ScanReport`, never logged, never printed to `stdout` or `stderr`, and never serialized into JSON output.

### Fingerprinting
Upon detection, every candidate secret is immediately digested into a full 64-character SHA-256 hash (`hex(sha256(secret))`). Terminal reports only display safely masked fingerprints (`8a21••••91cf`), preventing shoulder surfing and credential leakage in CI console logs.

*(Note: While raw secret substrings temporarily reside in process memory buffers during line inspection and hashing, they are strictly ephemeral and dropped immediately after hashing and context filtering. They are never retained in persistent data structures.)*

---

## False Positive Handling

Heuristic secret detection requires balancing recall against false alarms. LeakGuard implements a multi-layer suppression engine:

- **UUID Suppression**: Standard 36-character UUIDs (`[0-9a-f]{8}-[0-9a-f]{4}-...`) are recognized and filtered.
- **Git Commit SHA Suppression**: 40-character hexadecimal commit hashes are suppressed.
- **SHA-256 Suppression**: 64-character hexadecimal digests are recognized and suppressed.
- **Docker Image Digest Suppression**: `sha256:[a-f0-9]{64}` image identifiers are suppressed.
- **SRI & Package Hashes**: Subresource Integrity and lockfile digests prefixed with `sha256-`, `sha384-`, or `sha512-` are recognized and suppressed.
- **Environment & Template Placeholders**: Expressions such as `${...}`, `$VAR`, `<YOUR_KEY>`, `{{API_KEY}}`, `%VAR%`, and `process.env.` are suppressed.
- **Dummy & Example Credentials**: Common development placeholders (`YOUR_API_KEY`, `CHANGE_ME`, `admin/admin`, `test/test`, `password123`, `example/example`) are ignored.
- **Context & Entropy Evaluation**: Candidates must appear in plausible variable or header contexts and exceed Shannon entropy thresholds ($H \ge 4.0$). Low-entropy and monotonic strings (`AAAA...`, `123456...`) are rejected.
- **Detector Deduplication**: Overlapping detections on the same line sharing the same secret fingerprint are deduplicated deterministically.

> **Important**: These mechanisms reduce false positives but cannot eliminate them completely.

---

## Installation

Repository: [https://github.com/Buildwith-Zxid/leakguard](https://github.com/Buildwith-Zxid/leakguard)

### Prerequisites

Ensure you have a stable Rust toolchain installed (Rust 1.75+ recommended):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Build and Install from Source

```bash
git clone https://github.com/Buildwith-Zxid/leakguard.git
cd leakguard
cargo install --path .
```

Verify installation:

```bash
leakguard version
```

### Building Release Executable

To produce an optimized standalone binary without installing to Cargo's global bin:

```bash
cargo build --release
```

The resulting executable will be located at:
- **Linux / macOS**: `target/release/leakguard`
- **Windows**: `target/release/leakguard.exe`

---

## Usage

### Basic Scan

Scan the current working directory:

```bash
leakguard scan .
```

Scan an explicit directory path:

```bash
leakguard scan /path/to/project
```

### Machine-Readable JSON Mode

Generate versioned, machine-readable JSON for CI/CD pipelines and security audits:

```bash
leakguard scan . --json
```

### Filter by Minimum Severity

Filter findings by severity level (`low`, `medium`, `high`, `critical`):

```bash
leakguard scan . --severity high
```

### Custom Ignore Patterns

Exclude specific paths or globs from the scan:

```bash
leakguard scan . --ignore "fixtures/**" --ignore "*.generated.ts"
```

### Plain-Text / CI Terminal Output

Disable ANSI terminal colors via flag or standard environment variable:

```bash
leakguard scan . --no-color
# or
NO_COLOR=1 leakguard scan .
```

### Inspect Active Detector Rules

List all built-in detection rules, categories, and default severities:

```bash
leakguard rules
```

---

## Example Output

### Terminal Output

```text
LEAKGUARD SECURITY SCAN
────────────────────────────────────

Repository: ./services/payment-gateway

Files scanned       142
Files skipped        28
Scan duration       34ms

Findings             2

HIGH
  AWS Access Key
  config/settings.rs:18
  fingerprint: 8a21••••91cf

CRITICAL
  Private Key
  certs/server.pem:1
  fingerprint: f4e8••••3b12

────────────────────────────────────
✖ 2 potential secret(s) detected
```

### Clean Scan Terminal Output

```text
LEAKGUARD SECURITY SCAN
────────────────────────────────────

Repository: ./src

Files scanned       89
Files skipped        4
Scan duration       18ms

Findings             0

────────────────────────────────────
✔ No secrets detected
```

### Machine-Readable JSON Output (`--json`)

```json
{
  "schema_version": 1,
  "leakguard_version": "0.1.0",
  "path": "./services/payment-gateway",
  "stats": {
    "files_scanned": 142,
    "files_skipped": 28,
    "duration_ms": 34
  },
  "findings": [
    {
      "detector": "aws_access_key",
      "category": "Cloud Credentials",
      "severity": "HIGH",
      "file": "config/settings.rs",
      "line": 18,
      "column": 12,
      "fingerprint": "8a21c43f9a72d3e18502f61e7b99c018a1a3b8d9e2f4c5b6a7d8e9f0123491cf",
      "confidence": 0.98
    },
    {
      "detector": "private_key",
      "category": "Cryptographic Material",
      "severity": "CRITICAL",
      "file": "certs/server.pem",
      "line": 1,
      "column": 1,
      "fingerprint": "f4e8b192809d43ec8b251284a7e91122a6136d89551c098df241ba9256903b12",
      "confidence": 1.0
    }
  ]
}
```

---

## Configuration

LeakGuard can be configured using a `.leakguard.toml` file in the scan target directory or specified via `--config <path>`.

*(Note: For backward compatibility, `.sentinel.toml` is also supported if `.leakguard.toml` is not present).*

### Configuration Precedence

1. **CLI Arguments** (e.g. `--severity`, `--ignore`, `--no-color`)
2. **`.leakguard.toml`** configuration file
3. **Built-in Defaults**

If a configuration file exists but contains syntax or validation errors, LeakGuard exits immediately with exit code `2`.

### Example `.leakguard.toml`

```toml
[scan]
# Maximum file size in bytes to scan (default: 5MB = 5242880)
max_file_size = 5242880

# Whether to follow filesystem symlinks (default: false)
follow_symlinks = false

# Number of worker threads for scanning (0 = auto-detect based on logical CPU cores)
workers = 0

[ignore]
# Glob patterns to ignore in addition to .gitignore and default ignore lists
patterns = [
    "node_modules/**",
    "target/**",
    "dist/**",
    "**/*.min.js",
    "tests/fixtures/**"
]

[allowlist]
# SHA-256 fingerprints of verified non-secrets to suppress from reports
fingerprints = [
    "8a21c43f9a72d3e18502f61e7b99c018a1a3b8d9e2f4c5b6a7d8e9f0123491cf"
]

[entropy]
# Shannon entropy threshold for high-entropy secret candidates (default: 4.0)
minimum = 4.0
```

---

## Exit Codes

LeakGuard produces deterministic process exit codes designed for automated tooling and CI pipelines:

| Exit Code | Meaning | Description |
|:---:|:---|:---|
| `0` | **Clean** | Scan completed successfully with zero unsuppressed findings. |
| `1` | **Findings Detected** | One or more active secrets were identified. |
| `2` | **Configuration / Argument Error** | Invalid CLI options, unknown arguments, or malformed `.leakguard.toml`. |
| `3` | **Runtime / I/O Error** | Nonexistent scan path, permission denied, or unrecoverable filesystem failure. |

---

## Performance

LeakGuard is engineered for bounded resource consumption and high throughput:
- **Filesystem Traversal**: Leverages the multi-threaded `ignore` crate for fast directory traversal.
- **Parallel Scanning**: Work-stealing threadpool across CPU cores via `rayon`.
- **Preflight Guards**: Metadata inspection skips files exceeding `max_file_size` before buffer allocation; binary inspection evaluates only the initial 8KB.
- **Bounded Buffer Inspection**: Lines are read with a 64KB bounded reader to avoid large allocations on minified assets.

### Measured Microbenchmarks (Criterion on Rust Stable)

*Measured on x86_64 Windows (AMD Ryzen, 100 samples per test via Criterion):*

| Benchmark Target | Operation | Median Latency | Measured Rate |
|:---|:---|:---:|:---:|
| `shannon_entropy_sample` | 20-char candidate entropy calculation | ~2.39 µs | ~418,000 evaluations / sec / core |
| `shannon_entropy_high` | 60-char candidate entropy calculation | ~3.34 µs | ~299,000 evaluations / sec / core |
| `detector_scan_clean_line` | All 10 modular detectors on clean line | ~4.34 µs | ~230,000 lines / sec / core |
| `detector_scan_secret_line` | Full pipeline on secret match (regex, entropy, context, SHA-256) | ~19.63 µs | ~51,000 lines / sec / core |

*Note: These latency and rate numbers represent microbenchmarks of the detector engine and entropy calculations on individual lines. They do not represent end-to-end repository scanning throughput, which also depends on filesystem I/O, directory traversal, gitignore evaluation, and disk caching.*

---

## Testing

LeakGuard maintains a comprehensive automated test matrix spanning unit tests, integration tests, security invariant checks, and regression fixtures:

```bash
# Run all unit and integration tests
cargo test --all-targets

# Check code formatting
cargo fmt --check

# Run Clippy linter with strict warning rejection
cargo clippy --all-targets -- -D warnings

# Verify benchmarks compile cleanly
cargo bench --no-run
```

---

## Limitations

- **Heuristic Boundaries**: Pattern matching and Shannon entropy cannot guarantee detection of every novel, custom, or encrypted credential format.
- **Obfuscated Secrets**: Programmatically assembled strings, multi-variable concatenations, or base64-nested credentials cannot be reliably detected via static line inspection.
- **Short High-Entropy Strings**: Strings shorter than 16 characters cannot be classified reliably via Shannon entropy without unacceptable false positive rates.
- **Line-Oriented Processing**: Detectors operate on individual lines; multi-line split secrets without standard header/footer blocks (such as PEM blocks) are not correlated across line boundaries.

---

## Roadmap

- [ ] Interactive pre-commit hook installer (`leakguard init-hook`)
- [ ] SARIF (Static Analysis Results Interchange Format) output for GitHub Code Scanning integration
- [ ] Baseline snapshot management (`leakguard baseline record / check`)
- [ ] Additional specialized detectors (e.g. Stripe API keys, Slack webhooks, GitLab tokens)
- [ ] Custom user-defined regex rules via `.leakguard.toml`

---

## Project Structure

```
leakguard/
├── .github/
│   └── workflows/
│       └── ci.yml
├── benches/
│   └── scan_bench.rs
├── examples/
│   └── programmatic_scan.rs
├── src/
│   ├── detectors/
│   │   ├── mod.rs
│   │   ├── aws.rs
│   │   ├── database.rs
│   │   ├── generic.rs
│   │   ├── github.rs
│   │   ├── jwt.rs
│   │   └── private_key.rs
│   ├── cli.rs
│   ├── config.rs
│   ├── detector.rs
│   ├── entropy.rs
│   ├── fingerprint.rs
│   ├── ignore.rs
│   ├── lib.rs
│   ├── main.rs
│   ├── models.rs
│   ├── reporter.rs
│   └── scanner.rs
├── tests/
│   ├── fixtures/
│   │   ├── binary.dat
│   │   ├── fake_aws.env
│   │   ├── fake_credentials.py
│   │   ├── fake_db.cfg
│   │   ├── fake_github.sh
│   │   ├── fake_jwt.js
│   │   ├── fake_private_key.pem
│   │   ├── safe_docker.yaml
│   │   ├── safe_docs.md
│   │   ├── safe_integrity.html
│   │   ├── safe_lockfile.json
│   │   ├── safe_placeholders.yaml
│   │   ├── safe_sha.txt
│   │   ├── safe_sha256.txt
│   │   ├── safe_sourcemap.js
│   │   ├── safe_templates.env
│   │   └── safe_uuid.json
│   └── integration.rs
├── .gitignore
├── .leakguard.toml.example
├── Cargo.toml
├── CHANGELOG.md
├── LICENSE
└── README.md
```

---

## License

This project is licensed under the [MIT License](LICENSE).

Copyright (c) 2026 Mohd Zaid.
