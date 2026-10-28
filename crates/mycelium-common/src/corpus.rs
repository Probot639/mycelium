use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Seed {
    pub hash: String,
    pub data: Vec<u8>,
    pub source_node: String,
    pub campaign: String,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub found_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashEntry {
    pub stack_hash: String,
    pub input_hash: String,
    pub data: Vec<u8>,
    pub sanitizer_output: String,
    pub source_node: String,
    pub campaign: String,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub found_at: chrono::DateTime<chrono::Utc>,
}

pub fn hash_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_deterministic() {
        let h1 = hash_bytes(b"hello");
        let h2 = hash_bytes(b"hello");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn hash_differs() {
        let h1 = hash_bytes(b"hello");
        let h2 = hash_bytes(b"world");
        assert_ne!(h1, h2);
    }
}
