//! ChaCha20 stream cipher (RFC 8439).
//!
//! Used in chacha20-poly1305@openssh.com AEAD cipher suite.
//! 256-bit key, 96-bit nonce (or 64-bit nonce + 32-bit counter for IETF).

fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]); state[d] ^= state[a]; state[d] = state[d].rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]); state[b] ^= state[c]; state[b] = state[b].rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]); state[d] ^= state[a]; state[d] = state[d].rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]); state[b] ^= state[c]; state[b] = state[b].rotate_left(7);
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    // Constants "expand 32-byte k"
    state[0]  = 0x61707865; state[1] = 0x3320646e;
    state[2]  = 0x79622d32; state[3] = 0x6b206574;
    // Key (little-endian 32-bit words)
    for i in 0..8 { state[4+i] = u32::from_le_bytes(key[i*4..i*4+4].try_into().unwrap()); }
    // Counter
    state[12] = counter;
    // Nonce (little-endian)
    state[13] = u32::from_le_bytes(nonce[0..4].try_into().unwrap());
    state[14] = u32::from_le_bytes(nonce[4..8].try_into().unwrap());
    state[15] = u32::from_le_bytes(nonce[8..12].try_into().unwrap());

    let mut working = state;
    // 20 rounds = 10 column rounds + 10 diagonal rounds
    for _ in 0..10 {
        quarter_round(&mut working, 0,4,8,12);
        quarter_round(&mut working, 1,5,9,13);
        quarter_round(&mut working, 2,6,10,14);
        quarter_round(&mut working, 3,7,11,15);
        quarter_round(&mut working, 0,5,10,15);
        quarter_round(&mut working, 1,6,11,12);
        quarter_round(&mut working, 2,7,8,13);
        quarter_round(&mut working, 3,4,9,14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        let w = working[i].wrapping_add(state[i]);
        out[i*4..i*4+4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

/// Encrypt or decrypt `data` in place (XOR with keystream).
pub fn encrypt(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    let mut pos = 0;
    let mut ctr = counter;
    while pos < data.len() {
        let block = chacha20_block(key, ctr, nonce);
        let n = (data.len() - pos).min(64);
        for i in 0..n { data[pos + i] ^= block[i]; }
        pos += n;
        ctr = ctr.wrapping_add(1);
    }
}

/// Encrypt or decrypt returning new Vec-equivalent into a fixed buffer.
pub fn encrypt_buf(key: &[u8; 32], counter: u32, nonce: &[u8; 12], src: &[u8], dst: &mut [u8]) {
    let n = src.len().min(dst.len());
    dst[..n].copy_from_slice(&src[..n]);
    encrypt(key, counter, nonce, &mut dst[..n]);
}
