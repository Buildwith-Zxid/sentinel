use std::collections::HashMap;

/// Calculates the Shannon entropy of a string slice in bits per symbol.
///
/// $H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$
///
/// An empty string returns 0.0. A completely repetitive string (e.g. "aaaaa")
/// returns 0.0. High-randomness cryptographic keys typically have entropy > 4.0.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut frequencies: HashMap<char, usize> = HashMap::new();
    let mut total_chars = 0usize;

    for c in s.chars() {
        *frequencies.entry(c).or_insert(0) += 1;
        total_chars += 1;
    }

    let len = total_chars as f64;
    let mut entropy = 0.0;

    for &count in frequencies.values() {
        let p = (count as f64) / len;
        entropy -= p * p.log2();
    }

    entropy
}

/// Helper to detect if a candidate string is an obvious false positive:
/// - UUIDs (e.g., `123e4567-e89b-12d3-a456-426614174000`)
/// - Git commit SHAs (40 hex characters)
/// - Common documentation placeholders (e.g., `YOUR_API_KEY_HERE`, `TODO`, `EXAMPLE`)
/// - Monotonous sequences or repeated characters
pub fn is_likely_false_positive(candidate: &str) -> bool {
    let trimmed = candidate
        .trim()
        .trim_matches(|c| c == '"' || c == '\'' || c == '`');

    if trimmed.len() < 8 {
        return true;
    }

    let lower = trimmed.to_lowercase();

    // Explicit documentation/placeholder tokens
    const EXACT_PLACEHOLDERS: &[&str] = &[
        "password",
        "changeme",
        "supersecret",
        "mysecretkey",
        "default_secret",
        "12345678",
        "123456789",
        "1234567890",
        "abcdef123456",
        "undefined",
        "null",
    ];

    for &ph in EXACT_PLACEHOLDERS {
        if lower == ph {
            return true;
        }
    }

    // Substring placeholder keywords
    const SUBSTRING_PLACEHOLDERS: &[&str] = &[
        "your_key",
        "your_token",
        "your_secret",
        "your_password",
        "your_api_key",
        "your_access_key",
        "change_me",
        "placeholder",
        "example",
        "dummy_key",
        "sample_token",
        "replace_me",
        "test_secret",
        "fake_token",
        "xxxx",
        "00000000",
    ];

    for &ph in SUBSTRING_PLACEHOLDERS {
        if lower.contains(ph) {
            return true;
        }
    }

    // UUID detection: 8-4-4-4-12 hex characters
    if is_uuid(trimmed) {
        return true;
    }

    // Pure 40-character Git commit SHA
    if trimmed.len() == 40 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }

    // Monotonous/repetitive strings
    if is_repetitive(trimmed) {
        return true;
    }

    false
}

fn is_uuid(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let bytes = s.as_bytes();
    if bytes[8] != b'-' || bytes[13] != b'-' || bytes[18] != b'-' || bytes[23] != b'-' {
        return false;
    }
    for (i, &b) in bytes.iter().enumerate() {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            continue;
        }
        if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

fn is_repetitive(s: &str) -> bool {
    let mut chars = s.chars();
    if let Some(first) = chars.next() {
        if chars.all(|c| c == first) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_values() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert_eq!(shannon_entropy("aaaaaaa"), 0.0);
        // "abcdefghijklmnopqrstuvwxyz" should have high entropy
        let alpha = "abcdefghijklmnopqrstuvwxyz";
        assert!(shannon_entropy(alpha) > 4.5);
    }

    #[test]
    fn test_false_positive_uuid() {
        assert!(is_likely_false_positive(
            "123e4567-e89b-12d3-a456-426614174000"
        ));
        assert!(is_likely_false_positive(
            "c56a4180-65aa-42ec-a945-5fd21dec0538"
        ));
    }

    #[test]
    fn test_false_positive_git_sha() {
        assert!(is_likely_false_positive(
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        ));
    }

    #[test]
    fn test_false_positive_placeholders() {
        assert!(is_likely_false_positive("YOUR_API_KEY_HERE"));
        assert!(is_likely_false_positive("CHANGE_ME_NOW"));
        assert!(is_likely_false_positive("test_secret_value_12345"));
        assert!(is_likely_false_positive("xxxxxxxxxxxxxxxxxxxxxxxx"));
    }
}
