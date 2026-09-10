//! SHA-512 backed by the audited `sha2` crate (no_std, no alloc).
//! Used by the Ed25519 debug path in the SSH server.

use sha2::{Sha512 as Inner, Digest};

pub struct Sha512(Inner);

impl Sha512 {
    pub fn new() -> Self {
        Self(Inner::new())
    }

    pub fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.0, data);
    }

    pub fn finalize(self) -> [u8; 64] {
        let out = self.0.finalize();
        out.as_slice().try_into().unwrap()
    }
}

pub fn hash(data: &[u8]) -> [u8; 64] {
    Inner::digest(data).as_slice().try_into().unwrap()
}

pub fn hash2(a: &[u8], b: &[u8]) -> [u8; 64] {
    let mut h = Inner::new();
    Digest::update(&mut h, a);
    Digest::update(&mut h, b);
    h.finalize().as_slice().try_into().unwrap()
}

pub fn hash3(a: &[u8], b: &[u8], c: &[u8]) -> [u8; 64] {
    let mut h = Inner::new();
    Digest::update(&mut h, a);
    Digest::update(&mut h, b);
    Digest::update(&mut h, c);
    h.finalize().as_slice().try_into().unwrap()
}
