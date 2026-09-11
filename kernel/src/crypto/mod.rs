//! Kernel cryptography: the random number generator plus thin, typed
//! wrappers over the RustCrypto/dalek primitives used by SSH and TLS.

pub mod rng;

use sha2::Digest;

pub fn sha256(data: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(data).into()
}

pub fn sha512(data: &[u8]) -> [u8; 64] {
    sha2::Sha512::digest(data).into()
}

/// Constant-time equality for secrets (MACs, password hashes, tokens).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    core::hint::black_box(diff) == 0
}
