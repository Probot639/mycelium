// Guards for values that get joined onto filesystem paths on the coordinator.
// A node (or anyone who can reach the coordinator) controls these strings, so
// they must be checked before they ever reach `Path::join` or `fs::write`,
// otherwise a value like "../../etc/x" escapes the corpus directory.

/// A content hash must be exactly 64 hex chars (a SHA-256 digest). This is what
/// `corpus::hash_bytes` produces, and it rejects any path separators or `..`.
pub fn is_valid_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A campaign name is used as a directory name for the stored harness, so it is
/// restricted to a safe character set and a sane length. No slashes, no dots on
/// their own, nothing that can traverse.
pub fn is_valid_campaign(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes() {
        let good = "a".repeat(64);
        assert!(is_valid_hash(&good));
        assert!(!is_valid_hash("tooshort"));
        assert!(!is_valid_hash(&"a".repeat(63)));
        assert!(!is_valid_hash("../../../../etc/passwd"));
        // right length but not hex
        assert!(!is_valid_hash(&"g".repeat(64)));
    }

    #[test]
    fn campaigns() {
        assert!(is_valid_campaign("fuzz-libpng"));
        assert!(is_valid_campaign("smoke_test.v2"));
        assert!(!is_valid_campaign(""));
        assert!(!is_valid_campaign("."));
        assert!(!is_valid_campaign(".."));
        assert!(!is_valid_campaign("../etc"));
        assert!(!is_valid_campaign("a/b"));
        assert!(!is_valid_campaign("has space"));
        assert!(!is_valid_campaign(&"x".repeat(129)));
    }
}
