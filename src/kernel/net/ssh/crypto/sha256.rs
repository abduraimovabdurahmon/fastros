//! SHA-256 backed by the audited `sha2` crate (no_std, no alloc).

use sha2::{Sha256 as Inner, Digest};

pub struct Sha256(Inner);

impl Sha256 {
    pub fn new() -> Self {
        Self(Inner::new())
    }

    pub fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.0, data);
    }

    pub fn finalize(self) -> [u8; 32] {
        let out = self.0.finalize();
        out.as_slice().try_into().unwrap()
    }
}

pub fn hash(data: &[u8]) -> [u8; 32] {
    Inner::digest(data).as_slice().try_into().unwrap()
}

pub fn hash2(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = Inner::new();
    Digest::update(&mut h, a);
    Digest::update(&mut h, b);
    h.finalize().as_slice().try_into().unwrap()
}
