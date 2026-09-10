//! SSH Transport Layer Protocol (RFC 4253).
//!
//! Handles:
//!   - Version exchange ("SSH-2.0-FastROS_0.1")
//!   - Binary packet framing (length + padding + payload + MAC)
//!   - Algorithm negotiation (SSH_MSG_KEXINIT)
//!   - Key exchange (curve25519-sha256)
//!   - New keys (SSH_MSG_NEWKEYS)
//!   - Encryption/MAC after key exchange

use super::crypto::{self, sha256, hmac, aes, curve25519};

// ── SSH message type codes ────────────────────────────────────────────────────

pub const SSH_MSG_DISCONNECT:         u8 = 1;
pub const SSH_MSG_IGNORE:             u8 = 2;
pub const SSH_MSG_UNIMPLEMENTED:      u8 = 3;
pub const SSH_MSG_DEBUG:              u8 = 4;
pub const SSH_MSG_SERVICE_REQUEST:    u8 = 5;
pub const SSH_MSG_SERVICE_ACCEPT:     u8 = 6;
pub const SSH_MSG_KEXINIT:            u8 = 20;
pub const SSH_MSG_NEWKEYS:            u8 = 21;
pub const SSH_MSG_KEX_ECDH_INIT:      u8 = 30;  // curve25519 client key
pub const SSH_MSG_KEX_ECDH_REPLY:     u8 = 31;  // curve25519 server reply
pub const SSH_MSG_USERAUTH_REQUEST:   u8 = 50;
pub const SSH_MSG_USERAUTH_FAILURE:   u8 = 51;
pub const SSH_MSG_USERAUTH_SUCCESS:   u8 = 52;
pub const SSH_MSG_USERAUTH_BANNER:    u8 = 53;
pub const SSH_MSG_CHANNEL_OPEN:       u8 = 90;
pub const SSH_MSG_CHANNEL_OPEN_CONFIRM: u8 = 91;
pub const SSH_MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
pub const SSH_MSG_CHANNEL_DATA:       u8 = 94;
pub const SSH_MSG_CHANNEL_EOF:        u8 = 96;
pub const SSH_MSG_CHANNEL_CLOSE:      u8 = 97;
pub const SSH_MSG_CHANNEL_REQUEST:    u8 = 98;
pub const SSH_MSG_CHANNEL_SUCCESS:    u8 = 99;
pub const SSH_MSG_CHANNEL_FAILURE:    u8 = 100;

// ── Disconnect reason codes ───────────────────────────────────────────────────
pub const SSH_DISCONNECT_BY_APPLICATION: u32 = 11;
pub const SSH_DISCONNECT_AUTH_CANCELLED: u32 = 13;

// ── Buffer helpers ────────────────────────────────────────────────────────────

/// Write a big-endian u32.
pub fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off+4].copy_from_slice(&v.to_be_bytes());
}

/// Read a big-endian u32.
pub fn get_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(buf[off..off+4].try_into().unwrap_or([0;4]))
}

/// Write a length-prefixed SSH string.
pub fn put_string(buf: &mut [u8], off: usize, s: &[u8]) -> usize {
    put_u32(buf, off, s.len() as u32);
    buf[off+4..off+4+s.len()].copy_from_slice(s);
    4 + s.len()
}

/// Read a length-prefixed SSH string. Returns (slice, next_offset).
pub fn get_string(buf: &[u8], off: usize) -> (&[u8], usize) {
    if off + 4 > buf.len() { return (&[], off); }
    let len = get_u32(buf, off) as usize;
    let end = (off + 4 + len).min(buf.len());
    (&buf[off+4..end], off + 4 + len)
}

// ── Algorithm lists (what we support) ────────────────────────────────────────

pub const KEX_ALGOS:      &str = "curve25519-sha256";
pub const HOST_KEY_ALGOS: &str = "ssh-ed25519";
pub const CIPHER_ALGOS:   &str = "aes128-cbc";
pub const MAC_ALGOS:      &str = "hmac-sha2-256";
pub const COMP_ALGOS:     &str = "none";
pub const LANGS:          &str = "";

// ── Session crypto state ──────────────────────────────────────────────────────

pub struct SessionKeys {
    pub enc_key_cs:  [u8; 16],   // client→server AES-128 key
    pub enc_key_sc:  [u8; 16],   // server→client AES-128 key
    pub mac_key_cs:  [u8; 32],   // client→server HMAC-SHA256 key
    pub mac_key_sc:  [u8; 32],   // server→client HMAC-SHA256 key
    pub iv_cs:       [u8; 16],   // client→server IV
    pub iv_sc:       [u8; 16],   // server→client IV
}

impl SessionKeys {
    pub const fn zeroed() -> Self {
        Self {
            enc_key_cs: [0;16], enc_key_sc: [0;16],
            mac_key_cs: [0;32], mac_key_sc: [0;32],
            iv_cs: [0;16], iv_sc: [0;16],
        }
    }

    /// Derive session keys from shared_secret and exchange_hash (RFC 4253 §7.2).
    pub fn derive(shared_secret: &[u8; 32], h: &[u8; 32], session_id: &[u8; 32]) -> Self {
        let mut keys = Self::zeroed();
        crypto::derive_key(shared_secret, h, b'A', session_id, &mut keys.iv_cs);
        crypto::derive_key(shared_secret, h, b'B', session_id, &mut keys.iv_sc);
        crypto::derive_key(shared_secret, h, b'C', session_id, &mut keys.enc_key_cs);
        crypto::derive_key(shared_secret, h, b'D', session_id, &mut keys.enc_key_sc);
        crypto::derive_key(shared_secret, h, b'E', session_id, &mut keys.mac_key_cs);
        crypto::derive_key(shared_secret, h, b'F', session_id, &mut keys.mac_key_sc);
        keys
    }
}

// ── Packet framing ────────────────────────────────────────────────────────────

/// Build an SSH binary packet.
/// `payload` is the unencrypted content (starts with message type byte).
/// Returns the total frame length.
pub fn build_packet(buf: &mut [u8], payload: &[u8]) -> usize {
    // Block size for CBC = 16; padding must make (5 + payload.len() + pad_len) % 16 == 0
    let block = 16usize;
    let base = 5 + payload.len();
    let mut pad_len = block - (base % block);
    if pad_len < 4 { pad_len += block; }

    let total = base + pad_len;
    put_u32(buf, 0, (1 + payload.len() + pad_len) as u32);
    buf[4] = pad_len as u8;
    buf[5..5+payload.len()].copy_from_slice(payload);
    // Padding bytes (RFC says "SHOULD be random"; zero is acceptable)
    for i in 0..pad_len { buf[5 + payload.len() + i] = 0; }
    total
}

/// Parse the payload from a received SSH binary packet.
/// Returns (payload slice, total frame length) or ([], 0) on error.
pub fn parse_packet(buf: &[u8]) -> (&[u8], usize) {
    if buf.len() < 5 { return (&[], 0); }
    let packet_len = get_u32(buf, 0) as usize;
    if packet_len < 1 || buf.len() < 4 + packet_len { return (&[], 0); }
    let pad_len = buf[4] as usize;
    let payload_len = packet_len - 1 - pad_len;
    if 5 + payload_len > buf.len() { return (&[], 0); }
    (&buf[5..5+payload_len], 4 + packet_len)
}

// ── KEXINIT packet ────────────────────────────────────────────────────────────

/// Build SSH_MSG_KEXINIT for the server.
/// Returns the payload length.
pub fn build_kexinit(buf: &mut [u8]) -> usize {
    let mut off = 0;
    buf[off] = SSH_MSG_KEXINIT; off += 1;
    // 16 random bytes (cookie) — we use fixed for simplicity
    buf[off..off+16].copy_from_slice(b"fastros-kex-cook"); off += 16;
    // Algorithm lists as SSH strings
    for alg in &[KEX_ALGOS, HOST_KEY_ALGOS, CIPHER_ALGOS, CIPHER_ALGOS,
                 MAC_ALGOS, MAC_ALGOS, COMP_ALGOS, COMP_ALGOS, LANGS, LANGS] {
        off += put_string(buf, off, alg.as_bytes());
    }
    buf[off] = 0; off += 1;   // first_kex_packet_follows = false
    put_u32(buf, off, 0); off += 4; // reserved
    off
}
