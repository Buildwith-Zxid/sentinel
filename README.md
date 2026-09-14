# Sentinel

A fast, local-first security CLI for detecting accidentally exposed secrets and credentials in source code.

[![Rust](https://img.shields.io/badge/rust-stable-brightgreen.svg)](https://www.rust-lang.org/)
[![CI](https://github.com/buildwith-zxid/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/buildwith-zxid/sentinel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Overview

Sentinel is an independent command-line security tool written in pure Rust. It inspects local source repositories to identify unencrypted secrets—such as API keys, authentication tokens, private keys, database connection strings, and high-entropy credentials—before they are committed or pushed to remote repositories.

Sentinel operates entirely offline. It does not perform network requests, does not upload source code, and never retains or displays raw credentials in terminal output or exported reports.

---

## Why Sentinel?

Accidental secret leakage in source control remains one of the most prevalent attack vectors in software engineering. Developers frequently hardcode tokens during debugging or inadvertently commit `.env` files and configuration dumps.

Existing scanning utilities often introduce heavy runtime requirements (e.g., Python or Node runtimes, Docker containers, or external cloud dependencies), struggle with excessive false positives, or risk credential leakage by printing matched secrets directly to console logs. Sentinel solves this by providing:

1. **Zero Runtime Dependencies**: Compiled into a single, self-contained native executable.
2. **Leak-Proof Reporting**: Raw secret values are immediately digested into cryptographic SHA-256 fingerprints upon detection; findings and reports only display truncated hashes (`8a21••••91cf`).
3. **Layered Detection**: Combines regex pattern matching, assignment context evaluation, Shannon entropy distribution, and false-positive suppression.
4. **Local-First Privacy**: Audits stay strictly on your local machine.

---

## Features

- **10 Modular Detectors**: Dedicated engines for AWS, GitHub, Private Keys, Database connection URLs, JWTs, Bearer tokens, Generic API keys, Passwords, Generic credentials, and High-entropy candidates.
- **Gitignore & Custom Ignore Engine**: Honors `.gitignore` hierarchies, built-in directory exclusions (`.git`, `node_modules`, `target`, `dist`, `.venv`), and custom glob patterns.
- **Binary Preflight Filter**: Content-based inspection analyzing null bytes and control character ratios in the initial 8KB to skip compiled objects and binary assets without parsing overhead.
- **Safe File Size Handling**: Skips files exceeding the configurable size threshold (default 5MB) before allocating memory buffers.
- **Multi-Threaded Traversal**: Leverages `rayon` for safe, parallel multi-core scanning across file trees.
- **Shannon Entropy Analysis**: Measures character diversity to detect high-entropy secrets while rejecting repetitive sequences and predictable identifiers.
- **False-Positive Suppression**: Built-in suppressors for standard UUIDs, 40-character Git commit SHAs, and common placeholder strings (`YOUR_KEY`, `EXAMPLE`, `CHANGE_ME`).
- **Cryptographic Fingerprinting & Allowlists**: Generates SHA-256 digests of matches to allow safe suppression of verified non-secrets via `.sentinel.toml`.
- **Flexible Reporting**: Professional ANSI terminal output (with `--no-color` and `NO_COLOR` support) or strict machine-readable versioned JSON (`schema_version: 1`).
- **Deterministic Exit Codes**: Designed for seamless CI/CD integration and pre-commit hooks.

---

## How It Works

Sentinel processes repositories through an independent, deterministic multi-stage pipeline:

```
Repository Root
       ↓
File Discovery (ignore::WalkBuilder - Gitignore-aware, hidden files, symlinks)
       ↓
Ignore Engine (.gitignore + .sentinel.toml + CLI --ignore + default skips)
       ↓
File Size Filter (checks filesystem metadata against max_file_size)
       ↓
Binary Preflight Inspection (content-based check on first 8KB: null-bytes, control ratio)
       ↓
Buffered Line Reader (safe UTF-8 decoding, skipping non-text streams)
       ↓
Detector Pipeline (Trait-based modular detectors: Send + Sync)
  ├── AWS Access Key & Secrets
  ├── GitHub Tokens (classic, fine-grained, app, OAuth)
  ├── Private Key blocks (RSA, OpenSSH, EC, generic PKCS#8)
  ├── Database Connection URIs (Postgres, MySQL, Mongo, Redis, AMQP, MSSQL)
  ├── JWT Tokens
  ├── Bearer Tokens
  ├── Password-like assignments
  ├── Generic API & Secret Keys
  ├── Generic Credential-like strings
  └── High-Entropy Secret Candidates
       ↓
Context, Entropy & False-Positive Filter (UUIDs, Git commit SHAs, placeholders)
       ↓
Finding Aggregator & Allowlist Filter (SHA-256 fingerprint matching against .sentinel.toml)
       ↓
Terminal Reporter / Versioned JSON Reporter
```

---

## Architecture

Sentinel is organized into modular Rust components within `src/`:

- **`cli`** (`src/cli.rs`): Defines the command-line interface using `clap` (derive), managing subcommands, arguments, and validation.
- **`scanner`** (`src/scanner.rs`): Orchestrates directory traversal, file size filtering, binary preflight inspection, and parallel line execution via `rayon`.
- **`detector`** (`src/detector.rs`): Defines the `Detector` trait and `DetectorRegistry` for registering and dispatching rules.
- **`detectors/`** (`src/detectors/*`): Individual detector implementations:
  - `aws.rs`: AWS Access Key IDs and secret keys in context.
  - `github.rs`: GitHub PATs (classic & fine-grained), OAuth tokens, and app keys.
  - `private_key.rs`: Cryptographic private key headers (RSA, OpenSSH, EC, etc.).
  - `database.rs`: Database connection strings with embedded authentication.
  - `jwt.rs`: JSON Web Tokens (3-part base64url).
  - `generic.rs`: Bearer tokens, generic API keys, passwords, credentials, and high-entropy candidates.
- **`models`** (`src/models.rs`): Data contracts for findings, severity levels, scan statistics, and report schemas.
- **`config`** (`src/config.rs`): Parses `.sentinel.toml` configurations with fallback defaults.
- **`ignore`** (`src/ignore.rs`): Implements default ignore rules and integrates custom glob overrides.
- **`entropy`** (`src/entropy.rs`): Calculates Shannon entropy and contains false-positive filter logic.
- **`fingerprint`** (`src/fingerprint.rs`): Computes SHA-256 hashes and redacted representations (`8a21••••91cf`).
- **`reporter`** (`src/reporter.rs`): Formats human-readable console summaries and versioned JSON outputs.

---

## Detection Engine

Regex alone is insufficient for reliable credential detection. Pure regex produces excessive false alarms on identifiers, test mocks, and UUIDs, or misses credentials with novel prefixes.

Sentinel uses a four-layer detection strategy:

1. **Pattern Matching**: Target regexes locate known credential structures (e.g., `AKIA...`, `ghp_...`, `-----BEGIN...`).
2. **Context Analysis**: Evaluates surrounding variable assignments and keywords (e.g., `api_key =`, `password =`, `db_pass =`).
3. **Entropy Validation**: Measures character randomness using Shannon entropy ($H(X) = -\sum P(x_i) \log_2 P(x_i)$). High-entropy detectors ensure unclassified candidates possess sufficient unpredictability to warrant inspection.
4. **False-Positive Suppression**: Proactively removes standard UUIDs, 40-character Git commit SHAs, documentation samples, and common placeholder strings (`YOUR_API_KEY_HERE`, `CHANGE_ME`, `test_secret`).

---

## Supported Detectors

| Detector ID | Category | Default Severity | Description |
|:---|:---|:---|:---|
| `aws_access_key` | Cloud Credentials | `HIGH` | Detects AWS Access Key IDs (`AKIA`, `ABIA`, `ACCA`, `ASIA`) and context-bound secret keys |
| `github_token` | Source Control | `HIGH` | Detects GitHub Personal Access Tokens (classic `ghp_`, fine-grained `github_pat_`, OAuth `gho_`, app `ghs_`/`ghu_`) |
| `private_key` | Cryptographic Material | `CRITICAL` | Detects RSA, DSA, EC, OpenSSH, and PKCS#8 private key header blocks without exposing key data |
| `database_connection_string` | Database Credentials | `HIGH` | Detects connection URIs (`postgres://`, `mysql://`, `mongodb://`, `redis://`, etc.) containing passwords |
| `jwt_token` | Authentication Tokens | `MEDIUM` | Detects standard three-part base64url encoded JSON Web Tokens |
| `bearer_token` | Authentication Tokens | `HIGH` | Detects HTTP `Bearer <token>` authentication headers and config tokens |
| `generic_api_key` | API Keys | `MEDIUM` | Detects variable assignments matching common API key naming conventions with verified entropy |
| `password_assignment` | Credentials | `MEDIUM` | Detects hardcoded password variable assignments in source code and configuration files |
| `generic_credential` | Credentials | `MEDIUM` | Detects assignments to generic credential variables (e.g., `client_secret`, `auth_token`) |
| `high_entropy_candidate` | Entropy Analysis | `LOW` | Detects unclassified strings exceeding Shannon entropy thresholds inside credential-relevant contexts |

---

## Installation

### Building from Source

Ensure a stable Rust toolchain is installed ([rustup.rs](https://rustup.rs/)):

```bash
# Clone the repository
git clone https://github.com/buildwith-zxid/sentinel.git
cd sentinel

# Build and install locally via Cargo
cargo install --path .
```

Verify installation:

```bash
sentinel version
```

### Future Distribution

Sentinel is engineered to compile down to a standalone static native executable. Binary releases for Linux, macOS, and Windows can be produced using `cargo build --release` without requiring any external runtimes on client machines.

---

## Usage

### Basic Scan

Scan the current repository:

```bash
sentinel scan .
```

Scan an explicit directory path:

```bash
sentinel scan ./my-project
```

### JSON Output

Generate versioned, machine-readable JSON (ideal for CI pipelines, automated tooling, or security dashboards):

```bash
sentinel scan . --json
```

### Severity Filtering

Filter findings by minimum severity (`low`, `medium`, `high`, `critical`):

```bash
sentinel scan . --severity high
```

### Custom Ignore Patterns

Exclude specific paths or globs from the scan:

```bash
sentinel scan . --ignore "fixtures/**" --ignore "*.generated.ts"
```

### Color Control

Disable colored ANSI output for plain-text logs or CI environments:

```bash
sentinel scan . --no-color
```

*(Note: Sentinel also respects the standard `NO_COLOR` environment variable).*

### Inspect Detector Rules

List all active detector rules, categories, and default severities:

```bash
sentinel rules
```

---

## Example Output

### Terminal Output

```text
SENTINEL SECURITY SCAN
────────────────────────────────────

Repository: ./backend-service

Files scanned       184
Files skipped        37
Scan duration       42ms

Findings             2

HIGH
  AWS Access Key
  config/settings.rs:18
  fingerprint: 8a21••••91cf

MEDIUM
  Generic API Key
  src/client.rs:42
  fingerprint: c731••••82aa

────────────────────────────────────
✖ 2 potential secret(s) detected
```

### Machine-Readable JSON Output (`--json`)

```json
{
  "schema_version": 1,
  "sentinel_version": "0.1.0",
  "path": "./backend-service",
  "stats": {
    "files_scanned": 184,
    "files_skipped": 37,
    "duration_ms": 42
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
    }
  ]
}
```

---

## Configuration

Sentinel can be configured using a `.sentinel.toml` file in the target directory or specified via `--config <path>`.

```toml
[scan]
# Maximum file size in bytes to scan (default: 5MB = 5242880)
max_file_size = 5242880

# Whether to follow filesystem symlinks during scan (default: false)
follow_symlinks = false

# Worker threads for scanning (0 = auto-detect based on CPU cores)
workers = 0

[ignore]
# Glob patterns to ignore in addition to .gitignore and default ignore lists
patterns = [
    "node_modules/**",
    "target/**",
    "tests/fixtures/**",
    "**/*.min.js"
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

## Ignore Rules

Sentinel skips files through three distinct mechanisms:

1. **Default Exclusions**: Standard build and version-control artifacts (`.git`, `node_modules`, `target`, `dist`, `build`, `.venv`, `venv`, `__pycache__`) are automatically skipped.
2. **Gitignore Rules**: Respects `.gitignore` and parent ignore configurations encountered during traversal.
3. **Custom Glob Patterns**: Additional patterns supplied in `.sentinel.toml` under `[ignore].patterns` or passed via `--ignore <PATTERN>` flags on the CLI.

---

## Exit Codes

Sentinel returns deterministic process exit codes suitable for scripting and CI gates:

| Exit Code | Meaning | Description |
|:---:|:---|:---|
| `0` | Clean | Scan completed successfully with zero findings (or all matches were allowlisted/filtered) |
| `1` | Secrets Detected | One or more active findings were identified |
| `2` | Configuration Error | Invalid command-line arguments or malformed configuration file |
| `3` | Runtime Error | Unrecoverable filesystem or I/O error during scanning |

---

## Security & Privacy

- **Strictly Local-First**: Sentinel does not connect to the internet, performs no telemetry, and does not transmit repository code.
- **Redaction by Design**: Raw matched credentials are never saved to finding records, reports, or stdout. Findings store only a SHA-256 digest, and terminal output displays a masked representation (`8a21••••91cf`).
- **Safe Test Fixtures**: All repository test fixtures contain strictly synthetic, non-functional credentials.

---

## False Positives

Heuristic secret detection balances precision and recall. Sentinel manages false positives through:

- **Format Suppression**: Automatic suppression of standard UUIDs, 40-character Git commit SHAs, and monotonic sequences.
- **Placeholder Filtering**: Rejection of common template values (e.g., `your_api_key`, `CHANGE_ME`, `sample_token`, `xxxxxxxx`).
- **Fingerprint Allowlists**: When an audited finding is verified as a non-secret, adding its full SHA-256 fingerprint to `[allowlist].fingerprints` in `.sentinel.toml` permanently suppresses it from future reports.

---

## Performance

Sentinel is built for maximum throughput with minimal CPU and memory overhead:

- **Fast Traversal**: Uses `ignore` for fast, Gitignore-aware recursive directory traversal.
- **Parallel Scanning**: Dispatches file scanning concurrently across CPU cores using `rayon`.
- **Pre-allocation & Memory Guards**: Files larger than `max_file_size` are skipped via metadata inspection prior to allocation. Binary files are detected and skipped in the initial 8KB.
- **Zero Heavy Runtimes**: Minimal memory footprint compiled directly to machine code.

### Measured Benchmarks (Criterion on Rust Stable)

Microbenchmarks measured on AMD Ryzen / x86_64 Windows (100 samples per test via Criterion):

| Benchmark Target | Operation | Measured Median Latency | Throughput / Rate |
|:---|:---|:---:|:---:|
| `shannon_entropy_sample` | 20-char candidate entropy calculation | ~2.39 µs | ~418,000 evaluations / sec / core |
| `shannon_entropy_high` | 60-char candidate entropy calculation | ~3.34 µs | ~299,000 evaluations / sec / core |
| `detector_scan_clean_line` | All 10 modular detectors evaluated on clean line | ~4.34 µs | ~230,000 lines / sec / core |
| `detector_scan_secret_line` | Full pipeline on secret line (regex, context, entropy, SHA-256) | ~19.63 µs | ~51,000 lines / sec / core |

---

## Testing

Sentinel maintains a comprehensive automated test suite:

- **Unit Tests**: Verify entropy calculation, false positive suppression, SHA-256 fingerprinting, configuration parsing, and detector logic.
- **Integration Tests**: Verify end-to-end repository scanning against realistic fixtures, exit codes, binary detection, allowlist suppression, and strict credential non-leakage.
- **Redaction Verification**: Automated test suites assert that zero raw fixture credentials appear in report outputs.

Run the test suite:

```bash
cargo test --all-targets
```

---

## Limitations

- **Heuristic Boundaries**: Detection is based on patterns, entropy, and context. Novel or non-standard token formats may not match existing rules.
- **Obfuscated Credentials**: Base64-nested or programmatically assembled strings across multiple lines or concatenations cannot be guaranteed detection.
- **Trade-offs in Entropy**: Extremely short high-entropy strings (<16 characters) cannot be safely flagged without inducing false positive noise.

---

## Roadmap

- [ ] Git pre-commit hook integration helper (`sentinel install-hook`)
- [ ] SARIF (Static Analysis Results Interchange Format) output support for GitHub Code Scanning
- [ ] Baseline snapshot management (`sentinel baseline record / check`)
- [ ] Additional specialized detectors (e.g., Slack Webhooks, Stripe Keys, GitLab Tokens)
- [ ] Custom regex rule definitions via `.sentinel.toml`

---

## Project Structure

```
sentinel/
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
│   │   ├── safe_docs.md
│   │   ├── safe_placeholders.yaml
│   │   ├── safe_sha.txt
│   │   └── safe_uuid.json
│   └── integration.rs
├── .gitignore
├── .sentinel.toml.example
├── Cargo.toml
├── CHANGELOG.md
├── LICENSE
└── README.md
```

---

## Contributing

Contributions are welcome. Please ensure that:

1. Code is formatted: `cargo fmt --check`
2. Clippy is satisfied: `cargo clippy --all-targets -- -D warnings`
3. All tests pass: `cargo test --all-targets`
4. No real secrets or credentials are ever committed to the repository or test fixtures.

---

## License

This project is licensed under the [MIT License](LICENSE).

Copyright (c) 2026 Mohd Zaid.
