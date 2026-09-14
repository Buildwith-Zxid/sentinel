//! # LeakGuard
//!
//! Native Rust secret and credential scanner for source repositories.

pub mod cli;
pub mod config;
pub mod detector;
pub mod detectors;
pub mod entropy;
pub mod fingerprint;
pub mod ignore;
pub mod models;
pub mod reporter;
pub mod scanner;

pub use config::Config;
pub use detector::{Detector, DetectorRegistry};
pub use models::{Finding, ScanReport, ScanStats, Severity};
pub use scanner::Scanner;
