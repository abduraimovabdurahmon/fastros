//! Password hashing — FNV-1a 64-bit
//!
//! Linux uses SHA-512/bcrypt/yescrypt in /etc/shadow.
//! We use FNV-1a for simplicity in a no_std kernel (no crypto crates).
//! Adequate for learning; not production-grade.

/// FNV-1a 64-bit hash of a byte slice.
/// Identical algorithm to what GNU libc uses for simple hash tables.
pub const fn hash_password(data: &[u8]) -> u64 {
    let mut h: u64 = 14695981039346656037;
    let mut i = 0;
    while i < data.len() {
        h ^= data[i] as u64;
        h = h.wrapping_mul(1099511628211);
        i += 1;
    }
    h
}

/// Verify plaintext against a stored hash.
pub fn verify_password(plaintext: &[u8], stored_hash: u64) -> bool {
    hash_password(plaintext) == stored_hash
}
