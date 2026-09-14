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
/// - Git commit SHA-1 values (40 hex characters)
/// - SHA-256 digests (64 hex characters)
/// - Docker digests (`sha256:[a-f0-9]{64}`)
/// - Package and subresource integrity hashes (`sha256-...`, `sha384-...`, `sha512-...`)
/// - Template syntax (`${...}`, `<...>`, `process.env.`)
/// - Common documentation placeholders (e.g., `YOUR_API_KEY`, `CHANGE_ME`, `test/test`)
/// - Monotonous sequences or repeated characters
pub fn is_likely_false_positive(candidate: &str) -> bool {
    let trimmed = candidate
        .trim()
        .trim_matches(|c| c == '"' || c == '\'' || c == '`');

    // Reject short or empty strings
    if trimmed.len() < 8 {
        return true;
    }

    let lower = trimmed.to_lowercase();

    // Template variables & placeholders
    if (lower.starts_with("${") && lower.ends_with('}'))
        || (lower.starts_with('<') && lower.ends_with('>'))
        || lower.starts_with("process.env.")
        || lower.starts_with("env(")
        || lower.starts_with("os.environ")
    {
        return true;
    }

    // Explicit documentation/placeholder tokens
    const EXACT_PLACEHOLDERS: &[&str] = &[
        "password",
        "changeme",
        "change_me",
        "supersecret",
        "mysecretkey",
        "default_secret",
        "12345678",
        "123456789",
        "1234567890",
        "abcdef123456",
        "undefined",
        "null",
        "test/test",
        "example/example",
        "admin/admin",
        "root/root",
        "user:password",
        "username:password",
        "test_password",
        "dummy_password",
        "your_password",
        "your_api_key",
        "your_key_here",
        "your_token_here",
        "your_secret_here",
        "your_access_key",
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
        "fake_password",
        "dummy_credentials",
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

    // Pure 40-character Git commit SHA-1
    if trimmed.len() == 40 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }

    // Pure 64-character SHA-256 hash / digest
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }

    // Docker image digest: sha256:[64 hex chars]
    if lower.starts_with("sha256:") && lower.len() == 71 {
        let digest_part = &lower[7..];
        if digest_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return true;
        }
    }

    // Package / Subresource Integrity hashes (SRI): sha256-..., sha384-..., sha512-...
    if (lower.starts_with("sha256-")
        || lower.starts_with("sha384-")
        || lower.starts_with("sha512-"))
        && lower.len() >= 48
    {
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
    fn test_false_positive_sha256() {
        assert!(is_likely_false_positive(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
    }

    #[test]
    fn test_false_positive_docker_digest() {
        assert!(is_likely_false_positive(
            "sha256:7173b809ca12ec5dee4506cd86be934c4596dd234ee82c0662eac04a8c2c71dc"
        ));
    }

    #[test]
    fn test_false_positive_sri_hash() {
        assert!(is_likely_false_positive(
            "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
        ));
        assert!(is_likely_false_positive(
            "sha512-v3bT6Y1vWlM1w/1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ=="
        ));
    }

    #[test]
    fn test_false_positive_templates() {
        assert!(is_likely_false_positive("${API_KEY_ENV}"));
        assert!(is_likely_false_positive("<your_secret_token>"));
        assert!(is_likely_false_positive("process.env.SECRET_KEY"));
    }

    #[test]
    fn test_false_positive_placeholders() {
        assert!(is_likely_false_positive("YOUR_API_KEY_HERE"));
        assert!(is_likely_false_positive("CHANGE_ME_NOW"));
        assert!(is_likely_false_positive("test_secret_value_12345"));
        assert!(is_likely_false_positive("xxxxxxxxxxxxxxxxxxxxxxxx"));
    }
}
