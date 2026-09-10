//! AES-128-CTR using the `aes-soft` crate for the AES block primitive.
//!
//! `aes-soft` 0.6 is a pure-Rust lookup-table AES — no SIMD, no cpufeatures,
//! compiles for `x86_64-unknown-none` with soft-float.

use aes_soft::Aes128 as AesBlock;
use aes_soft::cipher::{NewBlockCipher, BlockCipher};
use aes_soft::cipher::generic_array::{typenum::U16, GenericArray};

type Block16 = GenericArray<u8, U16>;

/// AES-128 in CTR mode (RFC 4344 §2.1 — big-endian 128-bit counter).
#[derive(Clone, Copy)]
pub struct Aes128Ctr {
    key: [u8; 16],
    iv:  [u8; 16],
    pos: u64,
}

impl Aes128Ctr {
    pub fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self { key: *key, iv: *iv, pos: 0 }
    }

    pub fn process(&mut self, buf: &mut [u8]) {
        let block_num = self.pos / 16;
        let mut ctr = self.iv;
        let lo = u64::from_be_bytes(ctr[8..16].try_into().unwrap());
        let (new_lo, carry) = lo.overflowing_add(block_num);
        ctr[8..16].copy_from_slice(&new_lo.to_be_bytes());
        if carry {
            let hi = u64::from_be_bytes(ctr[0..8].try_into().unwrap());
            ctr[0..8].copy_from_slice(&hi.wrapping_add(1).to_be_bytes());
        }

        let cipher = AesBlock::new(Block16::from_slice(&self.key));
        let mut i = 0usize;
        while i < buf.len() {
            let mut block: Block16 = *Block16::from_slice(&ctr);
            cipher.encrypt_block(&mut block);

            let n = (buf.len() - i).min(16);
            for j in 0..n { buf[i + j] ^= block[j]; }

            for k in (0..16).rev() {
                ctr[k] = ctr[k].wrapping_add(1);
                if ctr[k] != 0 { break; }
            }
            i += n;
        }
        self.pos += buf.len() as u64;
    }
}
