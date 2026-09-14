# Sentinel

A fast, local-first security CLI for detecting accidentally exposed secrets and credentials in source code repositories.

[![Rust](https://img.shields.io/badge/rust-stable-brightgreen.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## What It Does

Sentinel is an independent command-line security tool written in 100% native Rust. It recursively inspects source-code repositories to identify unencrypted secrets—such as cloud access keys, authentication tokens, private key blocks, database connection strings, and high-entropy credentials—before they are committed or pushed to remote repositories.

Sentinel operates strictly offline. It never executes network calls, collects no telemetry, and immediately digests any detected credential into a deterministic SHA-256 fingerprint. Raw secret values are never saved in finding objects, serialized in reports, or printed to terminal or JSON streams.

---

## Why It Exists

Accidental credential exposure in source repositories remains one of the primary attack vectors in software development. Developers often temporarily hardcode tokens during testing, leave credentials in local configuration files, or inadvertently check in `.env` files.

Existing scanners frequently introduce significant drawbacks:
- They require runtime dependencies like Python, Node.js, or Docker containers.
- They generate excessive false positives on UUIDs, commit SHAs, content hashes, and documentation samples.
- Some tools inadvertently leak credentials by printing matched text verbatim in console output or unredacted log lines.
- Many tools lack deterministic exit codes and machine-readable output suitable for CI/CD pipelines.

Sentinel addresses these issues with a single, standalone native binary that emphasizes speed, low false positives, and strict non-leakage security invariants.

---

## Architecture

Sentinel implements a modular, streaming pipeline built entirely on Rust standard library primitives and lightweight crates (`rayon`, `ignore`, `regex`, `sha2`, `serde`, `clap`):

```
                        Repository Root Path
                                 │
                                 ▼
                     Target & Path Validation
                     (Checks path existence; exit code 3 on error)
                                 │
                                 ▼
                         Directory Traversal
              (ignore::WalkBuilder - Gitignore-aware, hidden files,
               symlink loop protection, default exclusion rules)
                                 │
                                 ▼
                       File Discovery Pipeline
         ┌────────────────────────────────────────────────────────┐
         │ 1. Ignore Engine Filter                                │
         │    (.gitignore + .sentinel.toml + CLI --ignore)        │
         │                                                        │
         │ 2. Metadata File Size Guard                            │
         │    (Metadata check; skip files > max_file_size (5MB))  │
         │                                                        │
         │ 3. Binary Preflight Filter                             │
         │    (Inspect initial 8KB: null bytes & control ratio)   │
         │                                                        │
         │ 4. Bounded Line-by-Line Streaming                      │
         │    (Capped line reading at 64KB to prevent OOM)        │
         └────────────────────────────────────────────────────────┘
                                 │
                                 ▼
                     Parallel Detector Dispatch
            (Rayon threadpool evaluating Send + Sync Detectors)
         ┌────────────────────────────────────────────────────────┐
         │ • AWS Access Keys & Context-Bound Secrets              │
         │ • GitHub Tokens (Classic, Fine-Grained, OAuth, Apps)   │
         │ • Private Key Headers (RSA, EC, DSA, OpenSSH, PKCS#8)  │
         │ • Database Connection Strings (Postgres, MySQL, etc.)  │
         │ • JWT Structure Validation (3-part base64url ey...)    │
         │ • Bearer Authentication Tokens                         │
         │ • Generic API Keys, Passwords & Credentials            │
         │ • High-Entropy Candidate Engine                        │
         └────────────────────────────────────────────────────────┘
                                 │
                                 ▼
                Context & False-Positive Filter
         (Filters UUIDs, SHA-1/256 hashes, SRI digests,
          package lockfiles, templates, dummy tokens, placeholders)
                                 │
                                 ▼
                    Deduplication & Allowlists
         (Deduplicates overlapping detector matches per line;
          filters SHA-256 fingerprints in .sentinel.toml allowlist)
                                 │
                                 ▼
                       Reporting & Exit Codes
             ┌─────────────────────────┬─────────────────────────┐
             │    Terminal Reporter    │     JSON Reporter       │
             │ (Safe masked fingerprints│ (Versioned schema v1,   │
             │  8a21••••91cf, ANSI/    │  full deterministic     │
             │  NO_COLOR support)      │  SHA-256, machine-safe) │
             └─────────────────────────┴─────────────────────────┘
                                 │
                                 ▼
                      Deterministic Exit Code
           (0 = clean, 1 = findings, 2 = config error, 3 = runtime)
```

---

## Detection Engine

Sentinel employs a layered detection model combining regex patterns, variable assignment context, structural validation, and Shannon entropy analysis:

| Detector ID | Category | Default Severity | Target Signatures & Validation Rules |
|:---|:---|:---|:---|
| `aws_access_key` | Cloud Credentials | `HIGH` | AWS Access Key IDs (`AKIA`, `ABIA`, `ACCA`, `ASIA` [20 chars]) and context-bound secret keys (40-char base64). |
| `github_token` | Source Control | `HIGH` | GitHub Personal Access Tokens (classic `ghp_`, fine-grained `github_pat_`, OAuth `gho_`, user/server tokens `ghu_`/`ghs_`, refresh `ghr_`). |
| `private_key` | Cryptographic Material | `CRITICAL` | PEM header blocks: RSA, DSA, EC, OPENSSH, PGP, ENCRYPTED, and generic PKCS#8 (`BEGIN ... PRIVATE KEY`). |
| `database_connection_string` | Database Credentials | `HIGH` | URIs with embedded passwords for PostgreSQL, MySQL, MongoDB, Redis, AMQP, MSSQL (`scheme://[user]:password@host`). Excludes credential-free URIs. |
| `jwt_token` | Authentication Tokens | `MEDIUM` | Strict three-part dot-separated base64url tokens starting with `ey` in header and payload. Rejects version strings and documentation samples. |
| `bearer_token` | Authentication Tokens | `HIGH` | `Authorization: Bearer <token>` HTTP headers and bearer variable assignments with verified entropy. |
| `generic_api_key` | API Keys | `MEDIUM` | Assignment identifiers (`api_key`, `apikey`, `secret_key`, etc.) with high-entropy token strings. |
| `password_assignment` | Credentials | `MEDIUM` | Explicit password assignments (`password = "..."`, `db_pass = "..."`) excluding templates and placeholders. |
| `generic_credential` | Credentials | `MEDIUM` | Generic credential keys (`client_secret`, `auth_token`, `access_token`) with entropy verification. |
| `high_entropy_candidate` | Entropy Analysis | `LOW` | Unclassified candidate strings exceeding Shannon entropy threshold (default $H \ge 4.0$) inside credential-relevant contexts. |

---

## Security Model

Sentinel operates under strict, transparent security invariants:

1. **Local-First & Offline**: Sentinel never initiates outbound network connections, requires no external API keys, performs no repository uploads, and contains no telemetry or usage tracking.
2. **No Raw Secret Persistence**: Raw detected secret strings are **never** stored in `Finding` structs, never stored in `ScanReport`, never serialized into JSON, never printed in terminal output, and never written to logs or error messages.
3. **Deterministic Cryptographic Fingerprints**: Upon detection, every candidate secret is immediately hashed with SHA-256 (`hex(sha256(secret))`). This full 64-character hash serves as the sole machine-safe identifier for allowlisting and programmatic correlation.
4. **Terminal Redaction**: Terminal reports only display safely masked fingerprints (`8a21••••91cf`), ensuring screen shares, shoulder surfing, and terminal logs never expose sensitive data.
5. **Memory Invariants**: While raw secret substrings temporarily reside in process memory during file line inspection and hashing, they are strictly ephemeral and dropped immediately after hashing and context filtering. They are never retained in persistent data structures.

---

## False Positive Strategy

Security scanners that produce excessive false alarms train developers to ignore warnings. Sentinel implements an aggressive, multi-layered false-positive suppression system:

- **Structural Hashes & Digests**:
  - Standard UUIDs (`[0-9a-f]{8}-[0-9a-f]{4}-...`)
  - Git commit SHA-1 hashes (40-character hex)
  - Standalone SHA-256 hashes (64-character hex)
  - Docker image digests (`sha256:[a-f0-9]{64}`)
  - Subresource Integrity (SRI) and package lockfile hashes (`sha256-...`, `sha384-...`, `sha512-...`)
- **Template Variables & Interpolation**:
  - Shell and template expressions (`${VAR}`, `$VAR`, `<YOUR_KEY>`, `{{API_KEY}}`, `%VAR%`)
  - Environment lookups (`process.env.`, `os.environ[`)
- **Placeholders & Documentation Examples**:
  - Standard documentation placeholders (`YOUR_API_KEY`, `YOUR_KEY_HERE`, `CHANGE_ME`, `REPLACE_ME`, `EXAMPLE_TOKEN`, `dummy_secret`)
  - Trivially fake credentials (`admin/admin`, `test/test`, `password123`, `root/root`, `example/example`)
- **Monotonic & Repetitive Strings**:
  - Repeated character sequences (`AAAA...`, `1111...`, `12345678...`)
  - Low-entropy candidates ($H < 3.0$) are rejected.
- **Line Deduplication**:
  - When multiple detectors match the same secret on the same line (e.g. `generic_credential` and `high_entropy_candidate`), Sentinel deterministically deduplicates findings, keeping only the highest-severity and highest-confidence finding.

---

## Installation

### Prerequisites

Ensure you have a stable Rust toolchain installed (version 1.75+ recommended):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Build and Install from Source

```bash
git clone https://github.com/buildwith-zxid/sentinel.git
cd sentinel
cargo install --path .
```

Verify installation:

```bash
sentinel version
```

### Release Binary Build

To build an optimized standalone native binary without installing to `cargo/bin`:

```bash
cargo build --release
# Executable located at ./target/release/sentinel (or sentinel.exe on Windows)
```

---

## Usage

### Scan Current Directory

```bash
sentinel scan .
```

### Scan Specific Path

```bash
sentinel scan /path/to/repository
```

### Machine-Readable JSON Mode

```bash
sentinel scan . --json
```

### Filter by Minimum Severity

Levels: `low`, `medium`, `high`, `critical`

```bash
sentinel scan . --severity high
```

### Exclude Custom Paths or Patterns

```bash
sentinel scan . --ignore "fixtures/**" --ignore "*.generated.ts"
```

### Plain-Text / CI Terminal Output

Disable ANSI colors via flag or standard environment variable:

```bash
sentinel scan . --no-color
# or
NO_COLOR=1 sentinel scan .
```

### Inspect Active Detector Rules

```bash
sentinel rules
```

---

## Output Examples

### Terminal Output

```text
SENTINEL SECURITY SCAN
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
  Private Key Block
  certs/server.pem:1
  fingerprint: f4e8••••3b12

────────────────────────────────────
✖ 2 potential secret(s) detected
```

### JSON Output (`--json`)

```json
{
  "schema_version": 1,
  "sentinel_version": "0.1.0",
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

Sentinel reads configuration from `.sentinel.toml` located in the scan target directory (or specified via `--config <path>`).

### Configuration Precedence

1. **CLI Flags** (e.g. `--severity`, `--ignore`, `--no-color`)
2. **`.sentinel.toml`** configuration file
3. **Built-in Defaults**

If a `.sentinel.toml` file exists but contains syntax or validation errors, Sentinel exits immediately with exit code `2`.

### Example `.sentinel.toml`

```toml
[scan]
# Maximum file size in bytes to scan (default: 5MB = 5242880)
max_file_size = 5242880

# Follow filesystem symlinks (default: false to prevent loops/escapes)
follow_symlinks = false

# Worker thread count (0 = auto-detect based on logical CPU cores)
workers = 0

[ignore]
# Glob patterns to ignore in addition to .gitignore and built-in rules
patterns = [
    "node_modules/**",
    "target/**",
    "dist/**",
    "**/*.min.js",
    "tests/fixtures/**"
]

[allowlist]
# Full 64-character SHA-256 fingerprints of verified non-secrets
fingerprints = [
    "8a21c43f9a72d3e18502f61e7b99c018a1a3b8d9e2f4c5b6a7d8e9f0123491cf"
]

[entropy]
# Shannon entropy threshold for high-entropy secret candidates (default: 4.0)
minimum = 4.0
```

---

## Exit Codes

Sentinel produces deterministic, standard exit codes:

| Exit Code | Meaning | Description |
|:---:|:---|:---|
| `0` | **Clean** | Scan completed successfully with zero unsuppressed findings. |
| `1` | **Findings Detected** | One or more active secrets were detected. |
| `2` | **Configuration / Argument Error** | Invalid CLI options, unknown flags, or malformed `.sentinel.toml`. |
| `3` | **Runtime / I/O Error** | Nonexistent scan path, permission denied, or fatal traversal failure. |

---

## Performance

Sentinel is engineered for high throughput and bounded memory usage:
- **Filesystem Traversal**: Leverages the multi-threaded, `.gitignore`-aware `ignore` crate.
- **Parallel Scanning**: Uses `rayon` work-stealing parallelism across available CPU cores.
- **Memory Guards**: Skips files exceeding `max_file_size` via metadata before reading contents.
- **Bounded Buffer Inspection**: Lines are read with a 64KB bounded reader to protect against memory exhaustion on minified single-line assets.
- **Binary Preflight**: Content inspection is restricted to the first 8KB.

### Measured Microbenchmarks (Criterion on Rust Stable)

*Measured on x86_64 Windows (AMD Ryzen, 100 samples per test via Criterion):*

| Benchmark Scope | Operation | Latency (Median) | Rate |
|:---|:---|:---:|:---:|
| **Candidate Entropy** | Shannon entropy (20-char candidate) | ~2.39 µs | ~418,000 evaluations / sec / core |
| **Candidate Entropy** | Shannon entropy (60-char candidate) | ~3.34 µs | ~299,000 evaluations / sec / core |
| **Clean Line Inspection** | All 10 modular detectors on clean code line | ~4.34 µs | ~230,000 lines / sec / core |
| **Secret Line Inspection** | Full pipeline on secret match (regex, entropy, context, SHA-256) | ~19.63 µs | ~51,000 lines / sec / core |

*Note: Line evaluation throughput measures raw detector engine speed. Full repository scan throughput also incorporates filesystem I/O, directory traversal, gitignore matching, and OS scheduling.*

---

## Testing

Sentinel includes a comprehensive test matrix spanning unit tests, integration tests, security invariant checks, and regression suites:

```bash
# Run all unit, integration, and security tests
cargo test --all-targets

# Run linters and format check
cargo fmt --check
cargo clippy --all-targets -- -D warnings

# Build benchmarks without running
cargo bench --no-run
```

### Security Tests

The test suite explicitly asserts:
- Raw detected credentials never appear in standard output.
- Raw detected credentials never appear in error streams (stderr).
- Raw detected credentials never appear in JSON serialization.
- Fingerprints are strictly deterministic across runs.
- Deduplication retains highest severity finding when multiple detectors match the same line.

---

## Limitations

- **Pattern-Based Detection**: Pattern matching and Shannon entropy cannot guarantee detection of every novel, custom, or encrypted credential format.
- **Obfuscated Secrets**: Split-string concatenation, base64-nested tokens, or dynamically reconstructed strings at runtime are beyond the scope of static source inspection.
- **Short High-Entropy Strings**: Strings under 16 characters cannot be reliably detected via entropy analysis alone without inducing unacceptable false positive rates.
- **Single-Line Inspection**: Detectors currently operate on individual lines; multi-line secrets that do not use identifiable header/footer blocks (like PEM keys) may not be fully detected.

---

## Roadmap

- [ ] Interactive pre-commit hook installer (`sentinel init-hook`)
- [ ] SARIF (Static Analysis Results Interchange Format) output for GitHub Code Scanning
- [ ] Baseline snapshot file support (`sentinel baseline record / check`)
- [ ] Additional detectors for specialized cloud providers (Stripe, Slack, GitLab, HashiCorp Vault)
- [ ] Custom user-defined regex rules via `.sentinel.toml`

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
├── .sentinel.toml.example
├── Cargo.toml
├── CHANGELOG.md
├── LICENSE
└── README.md
```

---

## License

This project is licensed under the [MIT License](LICENSE).

Copyright (c) 2026 Mohd Zaid.
