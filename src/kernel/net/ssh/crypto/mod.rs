//! Cryptographic primitives for the SSH transport layer.
//!
//! All implementations are pure Rust, no_std, no external crates.
//!
//!   sha256    — SHA-256 (FIPS 180-4)
//!   sha512    — SHA-512 (FIPS 180-4)
//!   hmac      — HMAC-SHA256 (RFC 2104)
//!   aes       — AES-128 in CBC mode (FIPS 197)
//!   chacha20  — ChaCha20 stream cipher (RFC 8439)
//!   poly1305  — Poly1305 MAC (RFC 8439)
//!   curve25519— X25519 Diffie-Hellman (RFC 7748)
//!   ed25519   — Ed25519 signatures (RFC 8032)

pub mod aes;
pub mod chacha20;
pub mod curve25519;
pub mod ed25519;
pub mod hmac;
pub mod poly1305;
pub mod sha256;
pub mod sha512;

/// Key derivation for SSH (RFC 4253 §7.2).
///
/// Derives key material of `len` bytes using:
///   K = SHA-256(K || H || letter || session_id)
///
/// where K = shared secret, H = exchange hash, letter = 'A'..'F'.
pub fn derive_key(
    shared_secret: &[u8],
    exchange_hash: &[u8; 32],
    letter:        u8,
    session_id:    &[u8; 32],
    out:           &mut [u8],
) {
    let mut h = sha256::Sha256::new();
    h.update(shared_secret);
    h.update(exchange_hash);
    h.update(&[letter]);
    h.update(session_id);
    let k1 = h.finalize();

    let mut pos = 0;
    while pos < out.len() {
        let n = (out.len() - pos).min(32);
        out[pos..pos+n].copy_from_slice(&k1[..n]);
        pos += n;
    }
}
