# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-14

### Added
- Initial release of LeakGuard, a native Rust secret and credential scanner for source repositories.
- 10 modular detector rules:
  - AWS Access Keys (`AKIA`, `ABIA`, `ACCA`, `ASIA`) and Context-Bound Secret Keys
  - GitHub Personal Access Tokens (classic `ghp_`, fine-grained `github_pat_`, OAuth `gho_`, app and user tokens)
  - Private Keys (RSA, OpenSSH, EC, DSA, generic PKCS#8, encrypted headers, and PGP blocks)
  - Database Connection Strings (PostgreSQL, MySQL, MongoDB, Redis, AMQP, MSSQL)
  - JWT (JSON Web Tokens) with strict 3-part base64url validation
  - Bearer Authentication Tokens
  - Password-like assignments
  - Generic API and secret keys
  - Generic credential-like strings
  - High-entropy secret candidates with contextual analysis
- Rayon-powered parallel repository scanning engine with work-stealing parallelism.
- Gitignore-aware recursive directory traversal via `ignore` crate with loop protection.
- Content-based binary preflight detection using null-byte and non-text byte ratio inspection on the initial 8KB window.
- Safe file size filtering with metadata preflight (default 5MB limit).
- Bounded streaming line reader (64KB buffer guard) preventing memory exhaustion on minified single-line assets.
- SHA-256 deterministic fingerprinting with masked console representation (`8a21••••91cf`).
- Shannon entropy analysis with character distribution metrics.
- Multi-layer false positive suppression (UUIDs, Git SHA-1, SHA-256 hashes, SRI/lockfile digests, Docker digests, template variables, and placeholder credentials).
- Line-based deterministic detector deduplication retaining highest-priority findings.
- TOML configuration file support (`.leakguard.toml` with backward compatibility for `.sentinel.toml`).
- Multiple output formats:
  - Terminal human-readable report with color support and `--no-color` / `NO_COLOR` handling.
  - Strict machine-readable JSON report adhering to versioned schema (`schema_version: 1`, `leakguard_version`).
- Deterministic CLI exit codes (0 = clean, 1 = findings detected, 2 = invalid arguments/config, 3 = scanning/runtime error).
- Rule discovery CLI command (`leakguard rules`).
- Criterion benchmark suite for entropy and detector scanning throughput.
- Comprehensive integration tests and realistic test fixtures.
