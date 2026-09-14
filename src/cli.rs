use crate::models::Severity;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "sentinel",
    author = "Mohd Zaid",
    version,
    about = "Local-first security CLI for detecting accidentally exposed secrets and credentials in source code.",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Scan a repository or directory for exposed secrets
    Scan(ScanArgs),

    /// List all built-in detection rules and their severity levels
    Rules(RulesArgs),

    /// Display detailed version information
    Version,
}

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// Path to the repository or directory to scan
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Output findings in strict machine-readable JSON format
    #[arg(long)]
    pub json: bool,

    /// Filter findings by minimum severity (low, medium, high, critical)
    #[arg(short, long)]
    pub severity: Option<Severity>,

    /// Additional ignore patterns (can be specified multiple times)
    #[arg(short, long, value_name = "PATTERN")]
    pub ignore: Vec<String>,

    /// Disable colored terminal output
    #[arg(long)]
    pub no_color: bool,

    /// Explicit path to a .sentinel.toml configuration file
    #[arg(short, long)]
    pub config: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct RulesArgs {
    /// Disable colored terminal output
    #[arg(long)]
    pub no_color: bool,
}
