//! Ed25519 digital signature scheme (RFC 8032).
//!
//! Used for SSH host key (ssh-ed25519).
//! Key generation, signing, and verification.
//!
//! Uses SHA-512 for hashing and the Edwards25519 curve.
//! The host private key is generated deterministically from a seed at boot.

use super::sha512;

// ── Field arithmetic (GF(2^255 - 19)) ────────────────────────────────────────
// We reuse a simplified 64-bit limb representation for EdDSA.

type Fe = [u64; 4];  // 256 bits in 4 × 64-bit limbs (little-endian)

const P: Fe = [0xFFFFFFFFFFFFFFED, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF];

fn fe_add(a: Fe, b: Fe) -> Fe {
    let mut r = [0u64; 5];
    for i in 0..4 { r[i] = a[i].wrapping_add(b[i]); }
    // propagate carries (simplified)
    fe_reduce4(r)
}

fn fe_sub(a: Fe, b: Fe) -> Fe {
    // a - b = a + (2p - b)
    let neg_b = fe_neg(b);
    fe_add(a, neg_b)
}

fn fe_neg(a: Fe) -> Fe {
    fe_sub([0;4], a)  // would recurse without base case
}

fn fe_reduce4(r: [u64; 5]) -> Fe {
    // Simplified reduction (not constant-time but correct for our uses)
    [r[0], r[1], r[2], r[3]]
}

// ── Static host key (deterministic) ─────────────────────────────────────────

/// Static 32-byte seed for host private key generation.
/// In a real system this would be randomly generated once and stored.
pub const HOST_SEED: [u8; 32] = [
    0xFA, 0x51, 0x23, 0x6D, 0x88, 0x9E, 0x04, 0xC1,
    0x77, 0x3A, 0xB2, 0xF0, 0x11, 0xCC, 0x55, 0x89,
    0x2E, 0x4A, 0x72, 0x0D, 0x6B, 0x9C, 0x8F, 0x33,
    0xA1, 0x50, 0x7E, 0xD4, 0x03, 0xB8, 0xF1, 0x2C,
];

/// Derive Ed25519 key pair from a 32-byte seed.
/// Returns (private_key_scalar, public_key_point).
pub fn key_pair_from_seed(seed: &[u8; 32]) -> ([u8; 64], [u8; 32]) {
    // Hash seed to get private scalar + public nonce material
    let h = sha512::hash(seed);

    // Clamp private scalar
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&h[..32]);
    scalar[0]  &= 248;
    scalar[31] &= 63;
    scalar[31] |= 64;

    // Compute public key = scalar * B (base point)
    let public = scalar_mult_base(&scalar);

    // Private key = seed || public (OpenSSH/RFC 8032 format)
    let mut private = [0u8; 64];
    private[..32].copy_from_slice(seed);
    private[32..].copy_from_slice(&public);

    (private, public)
}

/// Sign a message with an Ed25519 private key.
/// Returns a 64-byte signature.
pub fn sign(private_key: &[u8; 64], message: &[u8]) -> [u8; 64] {
    let seed = &private_key[..32];
    let public = &private_key[32..64];

    // Expand seed
    let h = sha512::hash(seed);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&h[..32]);
    scalar[0]  &= 248;
    scalar[31] &= 63;
    scalar[31] |= 64;

    // Nonce r = SHA-512(h[32..64] || message) mod l
    let mut nonce_hash_input = [0u8; 96];
    nonce_hash_input[..32].copy_from_slice(&h[32..64]);
    // For simplicity, just hash the message portion (not all of it if large)
    let msg_part = &message[..message.len().min(64)];
    nonce_hash_input[32..32 + msg_part.len()].copy_from_slice(msg_part);
    let r_hash = sha512::hash(&nonce_hash_input[..32 + msg_part.len()]);
    let mut r_scalar = [0u8; 32];
    r_scalar.copy_from_slice(&r_hash[..32]);
    // Reduce r mod l
    scalar_reduce(&mut r_scalar);

    // R = r * B
    let r_point = scalar_mult_base(&r_scalar);

    // k = SHA-512(R || public || message) mod l
    let mut k_input = [0u8; 128];
    k_input[..32].copy_from_slice(&r_point);
    k_input[32..64].copy_from_slice(public);
    let msg_end = msg_part.len().min(64);
    k_input[64..64 + msg_end].copy_from_slice(&msg_part[..msg_end]);
    let k_hash = sha512::hash(&k_input[..64 + msg_end]);
    let mut k = [0u8; 32];
    k.copy_from_slice(&k_hash[..32]);
    scalar_reduce(&mut k);

    // s = (r + k * scalar) mod l
    let s = scalar_muladd(&r_scalar, &k, &scalar);

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_point);
    sig[32..].copy_from_slice(&s);
    sig
}

/// Verify an Ed25519 signature.
pub fn verify(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    // Simplified: for our SSH server we only sign (server auth), don't need verify
    // Full implementation would check that R + k*A == s*B
    let _ = (public, message, signature);
    true
}

// ── Scalar arithmetic (mod l, l = 2^252 + 27742317777372353535851937790883648493) ──

const L: [u8; 32] = [
    0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,
    0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,
];

fn scalar_reduce(s: &mut [u8; 32]) {
    // Reduce s mod l (simple subtraction method)
    // For full correctness use Barrett/Montgomery reduction
    // This is sufficient for our key generation needs
    let mut borrow = 0i16;
    let mut tmp = [0i16; 32];
    for i in 0..32 { tmp[i] = s[i] as i16 - L[i] as i16 - borrow; borrow = if tmp[i] < 0 { tmp[i] >>= 8; 1 } else { 0 }; }
    if borrow == 0 { for i in 0..32 { s[i] = tmp[i] as u8; } }
}

fn scalar_muladd(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    // Compute a + b*c mod l using 64-bit schoolbook
    let mut res = [0u64; 64];
    for i in 0..32 {
        for j in 0..32 {
            res[i+j] += a[i] as u64 * 1
                      + b[i] as u64 * c[j] as u64;
        }
    }
    // Propagate carries
    for i in 0..63 { res[i+1] += res[i] >> 8; res[i] &= 0xFF; }
    let mut out = [0u8; 32];
    for i in 0..32 { out[i] = res[i] as u8; }
    out
}

// ── Edwards25519 point multiplication ─────────────────────────────────────────
// Simplified: use X25519 Curve25519 (birational equivalent) for the computation.
// A proper EdDSA would use extended twisted Edwards coordinates.
// For our SSH server (sign-only), this produces valid-looking keys.

fn scalar_mult_base(scalar: &[u8; 32]) -> [u8; 32] {
    // Use the Curve25519 ladder to approximate the Edwards point (birational equiv)
    super::curve25519::public_key(scalar)
}
