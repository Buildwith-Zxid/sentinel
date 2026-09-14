use clap::Parser;
use std::process;

use sentinel::cli::{Cli, Commands, RulesArgs, ScanArgs};
use sentinel::config::Config;
use sentinel::detector::DetectorRegistry;
use sentinel::reporter::Reporter;
use sentinel::scanner::Scanner;

// Deterministic exit codes
const EXIT_OK: i32 = 0;
const EXIT_FINDINGS_DETECTED: i32 = 1;
const EXIT_INVALID_CONFIG: i32 = 2;
const EXIT_RUNTIME_ERROR: i32 = 3;

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan(args) => handle_scan(args),
        Commands::Rules(args) => handle_rules(args),
        Commands::Version => handle_version(),
    }
}

fn handle_scan(args: ScanArgs) {
    // 1. Resolve configuration
    let (mut config, _loaded_path) = match &args.config {
        Some(config_path) => match Config::from_file(config_path) {
            Ok(cfg) => (cfg, Some(config_path.clone())),
            Err(err) => {
                eprintln!("Configuration Error: {}", err);
                process::exit(EXIT_INVALID_CONFIG);
            }
        },
        None => match Config::find_or_default(&args.path) {
            Ok(res) => res,
            Err(err) => {
                eprintln!("Configuration Error: {}", err);
                process::exit(EXIT_INVALID_CONFIG);
            }
        },
    };

    // 2. Append CLI ignore patterns
    for pat in args.ignore {
        config.ignore.patterns.push(pat);
    }

    // 3. Instantiate scanner and reporter
    let reporter = Reporter::new(args.no_color);
    let scanner = Scanner::new(config, args.severity);

    // 4. Run scan engine
    let report = match scanner.scan(&args.path) {
        Ok(rep) => rep,
        Err(err) => {
            eprintln!("Scanning Error: {}", err);
            process::exit(EXIT_RUNTIME_ERROR);
        }
    };

    // 5. Output results
    if args.json {
        if let Err(err) = reporter.print_json(&report) {
            eprintln!("Output Error: {}", err);
            process::exit(EXIT_RUNTIME_ERROR);
        }
    } else if let Err(err) = reporter.print_terminal(&report) {
        eprintln!("Output Error: {}", err);
        process::exit(EXIT_RUNTIME_ERROR);
    }

    // 6. Return deterministic exit code
    if !report.findings.is_empty() {
        process::exit(EXIT_FINDINGS_DETECTED);
    } else {
        process::exit(EXIT_OK);
    }
}

fn handle_rules(args: RulesArgs) {
    let registry = DetectorRegistry::default_registry();
    let rules = registry.rules();
    let reporter = Reporter::new(args.no_color);

    if let Err(err) = reporter.print_rules(&rules) {
        eprintln!("Output Error: {}", err);
        process::exit(EXIT_RUNTIME_ERROR);
    }

    process::exit(EXIT_OK);
}

fn handle_version() {
    println!("sentinel {}", env!("CARGO_PKG_VERSION"));
    println!("Local-first security CLI for secrets & credentials detection");
    println!("Engine: 100% Native Rust (Rayon + Ignore + SHA-256)");
    process::exit(EXIT_OK);
}
