# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-14

### Added
- Initial release of Sentinel, a local-first security CLI for secret and credential detection in source code.
- 10 modular detector rules:
  - AWS Access Keys (`AKIA`, `ABIA`, `ACCA`, `ASIA`) and Secret Keys
  - GitHub Personal Access Tokens (classic, fine-grained `github_pat_`, OAuth, and app tokens)
  - Private Keys (RSA, OpenSSH, EC, DSA, generic PKCS#8)
  - Database Connection Strings (PostgreSQL, MySQL, MongoDB, Redis, AMQP, MSSQL)
  - JWT (JSON Web Tokens)
  - Bearer Authentication Tokens
  - Password-like assignments
  - Generic API and secret keys
  - Generic credential-like strings
  - High-entropy secret candidates with contextual analysis
- Rayon-powered parallel repository scanning engine.
- High-performance directory traversal with Gitignore support via `ignore` crate.
- Automatic binary file preflight detection using null-byte and non-text byte ratio inspection.
- Configurable maximum file size filtering (default 5MB).
- SHA-256 deterministic fingerprinting with redacted console representation (`8a21••••91cf`).
- Shannon entropy calculator with character distribution analysis.
- Multi-layer false positive suppression (UUIDs, Git 40-char commit SHAs, common documentation/testing placeholders).
- TOML configuration file support (`.sentinel.toml`).
- Multiple output formats:
  - Terminal human-readable report with color support and `--no-color` flag.
  - Strict machine-readable JSON report adhering to versioned schema (`schema_version: 1`).
- Deterministic CLI exit codes (0 = clean, 1 = findings detected, 2 = invalid arguments, 3 = scanning error).
- Rule discovery CLI command (`sentinel rules`).
- Criterion benchmark suite for entropy and detector scanning throughput.
- Integration tests and comprehensive test fixtures.
