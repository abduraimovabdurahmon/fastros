//! RFC 7748 X25519 helpers backed by `curve25519-dalek`.

use core::ops::Mul;
use curve25519_dalek::{constants::X25519_BASEPOINT, montgomery::MontgomeryPoint, scalar::Scalar};

/// The X25519 base point, encoded in little-endian form.
pub const BASE_POINT: [u8; 32] = [9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

/// Perform RFC 7748 X25519 scalar multiplication.
pub fn x25519(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut clamped = *scalar;
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    let scalar = Scalar::from_bits(clamped);
    MontgomeryPoint(*u).mul(&scalar).to_bytes()
}

/// Generate an X25519 public key from a private scalar.
pub fn public_key(private_key: &[u8; 32]) -> [u8; 32] {
    x25519(private_key, X25519_BASEPOINT.as_bytes())
}

/// Derive a shared X25519 secret from our private key and the peer public key.
pub fn shared_secret(our_private: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 32] {
    x25519(our_private, peer_public)
}