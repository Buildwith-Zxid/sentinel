use sha2::{Digest, Sha256};

/// Computes a deterministic SHA-256 fingerprint from the raw secret string.
///
/// The raw secret is immediately hashed and discarded from the finding struct.
/// This allows stable allowlisting and baseline tracking without persisting secrets.
pub fn compute_fingerprint(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.trim().as_bytes());
    let result = hasher.finalize();
    hex_encode(&result)
}

/// Formats a 64-character hex fingerprint into a human-readable redacted string:
/// `8a21••••91cf`
pub fn redact_fingerprint(fingerprint: &str) -> String {
    if fingerprint.len() >= 8 {
        let start = &fingerprint[..4];
        let end = &fingerprint[fingerprint.len() - 4..];
        format!("{}••••{}", start, end)
    } else {
        "••••".to_string()
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_fingerprint_deterministic() {
        let fp1 = compute_fingerprint("AKIAIOSFODNN7EXAMPLE");
        let fp2 = compute_fingerprint("AKIAIOSFODNN7EXAMPLE");
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 64);
    }

    #[test]
    fn test_redact_fingerprint() {
        let fp = "8a21c43f9a72d3e18502f61e7b99c018a1a3b8d9e2f4c5b6a7d8e9f0123491cf";
        assert_eq!(redact_fingerprint(fp), "8a21••••91cf");
    }
}
