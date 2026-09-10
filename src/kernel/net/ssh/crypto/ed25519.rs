//! Ed25519 host-key helpers backed by the audited `ed25519-dalek` crate.
//!
//! SSH uses the seed || public-key representation for the host private key.

use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signer, Verifier};

/// Deterministic development host-key seed.
/// Production builds must generate and persist this value securely.
pub const HOST_SEED: [u8; 32] = [
    0xFA,0x51,0x23,0x6D,0x88,0x9E,0x04,0xC1,
    0x77,0x3A,0xB2,0xF0,0x11,0xCC,0x55,0x89,
    0x2E,0x4A,0x72,0x0D,0x6B,0x9C,0x8F,0x33,
    0xA1,0x50,0x7E,0xD4,0x03,0xB8,0xF1,0x2C,
];

fn keypair_from_seed(seed: &[u8; 32]) -> Keypair {
    // A 32-byte value is always a valid Ed25519 secret-key encoding.
    let secret = match SecretKey::from_bytes(seed) {
        Ok(secret) => secret,
        Err(_) => unreachable!(),
    };
    let public = PublicKey::from(&secret);
    Keypair { secret, public }
}

/// Derive the SSH-compatible private-key representation and its public key.
pub fn key_pair_from_seed(seed: &[u8; 32]) -> ([u8; 64], [u8; 32]) {
    let keypair = keypair_from_seed(seed);
    let public = keypair.public.to_bytes();
    let mut private = [0u8; 64];
    private[..32].copy_from_slice(seed);
    private[32..].copy_from_slice(&public);
    (private, public)
}

/// Sign a message using an SSH seed || public-key private key.
pub fn sign(private_key: &[u8; 64], message: &[u8]) -> [u8; 64] {
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&private_key[..32]);
    keypair_from_seed(&seed).sign(message).to_bytes()
}

/// Verify an Ed25519 signature.
pub fn verify(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let public = match PublicKey::from_bytes(public) {
        Ok(public) => public,
        Err(_) => return false,
    };
    let signature = match ed25519_dalek::Signature::from_bytes(signature) {
        Ok(signature) => signature,
        Err(_) => return false,
    };
    public.verify(message, &signature).is_ok()
}