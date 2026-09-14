use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sentinel::config::Config;
use sentinel::detector::DetectorRegistry;
use sentinel::entropy::shannon_entropy;
use std::path::Path;

fn benchmark_entropy(c: &mut Criterion) {
    let sample = "AKIA1234567890ABCDEF";
    let high_entropy = "c731f82aa901b4e98f0291cd4a87b65e12f0a9bc8d7e6f5a4b3c2d1e0f";

    c.bench_function("shannon_entropy_sample", |b| {
        b.iter(|| shannon_entropy(black_box(sample)))
    });

    c.bench_function("shannon_entropy_high", |b| {
        b.iter(|| shannon_entropy(black_box(high_entropy)))
    });
}

fn benchmark_detector_line_scan(c: &mut Criterion) {
    let registry = DetectorRegistry::default_registry();
    let config = Config::default();
    let file_path = Path::new("test.rs");

    let clean_line = "let sum = calculate_total(order_items, tax_rate);";
    let secret_line = "let aws_secret = \"AKIA1234567890ABCDEF\";";

    c.bench_function("detector_scan_clean_line", |b| {
        b.iter(|| {
            registry.scan_line(
                black_box(clean_line),
                black_box(42),
                black_box(file_path),
                black_box(&config),
            )
        })
    });

    c.bench_function("detector_scan_secret_line", |b| {
        b.iter(|| {
            registry.scan_line(
                black_box(secret_line),
                black_box(42),
                black_box(file_path),
                black_box(&config),
            )
        })
    });
}

criterion_group!(benches, benchmark_entropy, benchmark_detector_line_scan);
criterion_main!(benches);
