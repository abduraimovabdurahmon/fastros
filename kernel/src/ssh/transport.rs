//! SSH transport layer (RFC 4253): version exchange, binary packets,
//! encryption + integrity, curve25519 key exchange and re-keying.
//!
//! Algorithms (in preference order):
//! * kex: `curve25519-sha256` (+ `@libssh.org` alias), with
//!   `kex-strict-s-v00@openssh.com` (Terrapin, CVE-2023-48795, mitigation);
//! * host key: `ssh-ed25519`;
//! * ciphers: `chacha20-poly1305@openssh.com`, `aes256-ctr`, `aes128-ctr`;
//! * MACs (for CTR): `hmac-sha2-256-etm@openssh.com`, `hmac-sha2-256`.
//!
//! Receiving is done by the connection task (`RecvHalf`); sending is shared
//! by every channel writer through `SendHalf` behind a sleeping lock.

use super::wire::{disconnect, msg, Reader, Writer};
use crate::crypto::{ct_eq, rng};
use crate::net::socket::TcpStream;
use crate::sync::{Mutex, WaitQueue};
use aes::{Aes128, Aes256};
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20Legacy;
use ctr::Ctr128BE;
use hmac::{Hmac, Mac};
use poly1305::universal_hash::KeyInit;
use poly1305::Poly1305;
use sha2::{Digest, Sha256};

pub const SERVER_VERSION: &str = "SSH-2.0-FastROS_0.2";
const MAX_PACKET: usize = 256 * 1024;

pub const KEX_ALGS: &str = "curve25519-sha256,curve25519-sha256@libssh.org,ext-info-s,kex-strict-s-v00@openssh.com";
pub const HOSTKEY_ALGS: &str = "ssh-ed25519";
pub const CIPHERS: &str = "chacha20-poly1305@openssh.com,aes256-ctr,aes128-ctr";
pub const MACS: &str = "hmac-sha2-256-etm@openssh.com,hmac-sha2-256";

#[derive(Debug, Clone)]
pub enum SshError {
    Io,
    Closed,
    Protocol(String),
    Mac,
    Disconnected(String),
}

pub type SResult<T> = Result<T, SshError>;

fn proto<T>(m: &str) -> SResult<T> {
    Err(SshError::Protocol(m.to_string()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherAlg {
    ChaChaPoly,
    Aes128Ctr,
    Aes256Ctr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacAlg {
    /// Integrity provided by the AEAD cipher.
    Aead,
    HmacSha256,
    HmacSha256Etm,
}

impl CipherAlg {
    fn from_name(n: &str) -> Option<CipherAlg> {
        match n {
            "chacha20-poly1305@openssh.com" => Some(CipherAlg::ChaChaPoly),
            "aes128-ctr" => Some(CipherAlg::Aes128Ctr),
            "aes256-ctr" => Some(CipherAlg::Aes256Ctr),
            _ => None,
        }
    }
    fn key_len(self) -> usize {
        match self {
            CipherAlg::ChaChaPoly => 64,
            CipherAlg::Aes128Ctr => 16,
            CipherAlg::Aes256Ctr => 32,
        }
    }
    fn iv_len(self) -> usize {
        match self {
            CipherAlg::ChaChaPoly => 0,
            _ => 16,
        }
    }
    fn block(self) -> usize {
        match self {
            CipherAlg::ChaChaPoly => 8,
            _ => 16,
        }
    }
}

enum Cipher {
    Plain,
    ChaCha { main: [u8; 32], hdr: [u8; 32] },
    Aes128(Box<Ctr128BE<Aes128>>),
    Aes256(Box<Ctr128BE<Aes256>>),
}

/// One direction's cryptographic state.
struct Keys {
    cipher: Cipher,
    alg: Option<CipherAlg>,
    mac: MacAlg,
    mac_key: Vec<u8>,
    seq: u32,
}

impl Keys {
    fn plain() -> Keys {
        Keys { cipher: Cipher::Plain, alg: None, mac: MacAlg::Aead, mac_key: Vec::new(), seq: 0 }
    }
    fn new(alg: CipherAlg, mac: MacAlg, key: &[u8], iv: &[u8], mac_key: Vec<u8>, seq: u32) -> Keys {
        let cipher = match alg {
            CipherAlg::ChaChaPoly => {
                let mut main = [0u8; 32];
                let mut hdr = [0u8; 32];
                main.copy_from_slice(&key[..32]);
                hdr.copy_from_slice(&key[32..64]);
                Cipher::ChaCha { main, hdr }
            }
            CipherAlg::Aes128Ctr => Cipher::Aes128(Box::new(Ctr128BE::<Aes128>::new(key[..16].into(), iv[..16].into()))),
            CipherAlg::Aes256Ctr => Cipher::Aes256(Box::new(Ctr128BE::<Aes256>::new(key[..32].into(), iv[..16].into()))),
        };
        Keys { cipher, alg: Some(alg), mac, mac_key, seq }
    }
    fn block(&self) -> usize {
        self.alg.map(|a| a.block()).unwrap_or(8)
    }
    /// Length field and MAC are outside the padded region (AEAD / EtM).
    fn aad_len(&self) -> bool {
        matches!(self.cipher, Cipher::ChaCha { .. }) || self.mac == MacAlg::HmacSha256Etm
    }
    fn mac_len(&self) -> usize {
        match (&self.cipher, self.mac) {
            (Cipher::Plain, _) => 0,
            (Cipher::ChaCha { .. }, _) => 16,
            (_, MacAlg::HmacSha256 | MacAlg::HmacSha256Etm) => 32,
            _ => 0,
        }
    }
    fn ctr_apply(&mut self, data: &mut [u8]) {
        match &mut self.cipher {
            Cipher::Aes128(c) => c.apply_keystream(data),
            Cipher::Aes256(c) => c.apply_keystream(data),
            _ => {}
        }
    }
    fn clone_ctr(&self) -> Option<Cipher> {
        match &self.cipher {
            Cipher::Aes128(c) => Some(Cipher::Aes128(c.clone())),
            Cipher::Aes256(c) => Some(Cipher::Aes256(c.clone())),
            _ => None,
        }
    }
    fn restore_ctr(&mut self, c: Option<Cipher>) {
        if let Some(c) = c {
            self.cipher = c;
        }
    }
    fn hmac(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&self.mac_key).expect("any key length");
        m.update(&self.seq.to_be_bytes());
        for p in parts {
            m.update(p);
        }
        m.finalize().into_bytes().into()
    }
}

fn chacha_poly_key(main: &[u8; 32], seq: u32) -> [u8; 32] {
    let nonce = (seq as u64).to_be_bytes();
    let mut c = ChaCha20Legacy::new(main.into(), &nonce.into());
    let mut k = [0u8; 32];
    c.apply_keystream(&mut k);
    k
}

fn chacha_crypt(key: &[u8; 32], seq: u32, counter_block: u64, data: &mut [u8]) {
    let nonce = (seq as u64).to_be_bytes();
    let mut c = ChaCha20Legacy::new(key.into(), &nonce.into());
    c.seek(counter_block * 64);
    c.apply_keystream(data);
}

/// Sending direction, shared by all writers.
pub struct SendHalf {
    stream: Arc<TcpStream>,
    keys: Keys,
    /// Between our KEXINIT and NEWKEYS only key-exchange messages may flow.
    pub in_kex: bool,
    pub strict: bool,
    closed: bool,
    pub bytes_since_kex: u64,
}

pub struct Sender {
    inner: Mutex<SendHalf>,
    /// Woken when a key exchange finishes (writers wait on it).
    pub kex_done: WaitQueue,
}

impl Sender {
    pub fn new(stream: Arc<TcpStream>) -> Arc<Sender> {
        Arc::new(Sender {
            inner: Mutex::new(SendHalf { stream, keys: Keys::plain(), in_kex: false, strict: false, closed: false, bytes_since_kex: 0 }),
            kex_done: WaitQueue::new(),
        })
    }

    /// Send a connection-layer message (waits out a running key exchange).
    pub fn send(&self, payload: &[u8]) -> SResult<()> {
        loop {
            {
                let mut s = self.inner.lock();
                if s.closed {
                    return Err(SshError::Closed);
                }
                if !s.in_kex {
                    return s.send_packet(payload);
                }
            }
            self.kex_done.wait_until(|| (!self.inner.lock().in_kex).then_some(()));
        }
    }

    /// Send a transport/kex message regardless of key-exchange state.
    pub fn send_kex(&self, payload: &[u8]) -> SResult<()> {
        self.inner.lock().send_packet(payload)
    }

    pub fn lock(&self) -> crate::sync::MutexGuard<'_, SendHalf> {
        self.inner.lock()
    }

    pub fn close(&self) {
        let mut s = self.inner.lock();
        s.closed = true;
        drop(s);
        self.kex_done.wake_all();
    }
}

impl SendHalf {
    pub fn send_packet(&mut self, payload: &[u8]) -> SResult<()> {
        let block = self.keys.block();
        let aad = self.keys.aad_len();
        let covered = 1 + payload.len() + if aad { 0 } else { 4 };
        let mut pad = block - covered % block;
        if pad < 4 {
            pad += block;
        }
        let packet_len = 1 + payload.len() + pad;
        let mut pkt = Vec::with_capacity(4 + packet_len + 32);
        pkt.extend_from_slice(&(packet_len as u32).to_be_bytes());
        pkt.push(pad as u8);
        pkt.extend_from_slice(payload);
        let mut padding = vec![0u8; pad];
        if !matches!(self.keys.cipher, Cipher::Plain) {
            rng::fill(&mut padding);
        }
        pkt.extend_from_slice(&padding);
        let seq = self.keys.seq;
        match &mut self.keys.cipher {
            Cipher::Plain => {}
            Cipher::ChaCha { main, hdr } => {
                chacha_crypt(hdr, seq, 0, &mut pkt[..4]);
                chacha_crypt(main, seq, 1, &mut pkt[4..]);
                let pk = chacha_poly_key(main, seq);
                let tag = Poly1305::new(&pk.into()).compute_unpadded(&pkt);
                pkt.extend_from_slice(&tag);
            }
            Cipher::Aes128(_) | Cipher::Aes256(_) => {
                if self.keys.mac == MacAlg::HmacSha256Etm {
                    let (len, body) = pkt.split_at_mut(4);
                    match &mut self.keys.cipher {
                        Cipher::Aes128(c) => c.apply_keystream(body),
                        Cipher::Aes256(c) => c.apply_keystream(body),
                        _ => {}
                    }
                    let tag = self.keys.hmac(&[len, body]);
                    pkt.extend_from_slice(&tag);
                } else {
                    let tag = self.keys.hmac(&[&pkt]);
                    match &mut self.keys.cipher {
                        Cipher::Aes128(c) => c.apply_keystream(&mut pkt),
                        Cipher::Aes256(c) => c.apply_keystream(&mut pkt),
                        _ => {}
                    }
                    pkt.extend_from_slice(&tag);
                }
            }
        }
        self.keys.seq = self.keys.seq.wrapping_add(1);
        self.bytes_since_kex += pkt.len() as u64;
        self.stream.write_all(&pkt).map_err(|_| SshError::Io)
    }

    fn set_keys(&mut self, k: Keys) {
        self.keys = k;
        if self.strict {
            self.keys.seq = 0;
        }
    }
}

/// Receiving direction (owned by the connection task).
pub struct RecvHalf {
    stream: Arc<TcpStream>,
    buf: Vec<u8>,
    keys: Keys,
    pub strict: bool,
}

impl RecvHalf {
    pub fn new(stream: Arc<TcpStream>) -> RecvHalf {
        RecvHalf { stream, buf: Vec::new(), keys: Keys::plain(), strict: false }
    }

    fn fill(&mut self, n: usize, timeout_ms: Option<u64>) -> SResult<()> {
        let mut tmp = [0u8; 4096];
        while self.buf.len() < n {
            match self.stream.read_timeout(&mut tmp, timeout_ms) {
                Ok(0) => return Err(SshError::Closed),
                Ok(k) => self.buf.extend_from_slice(&tmp[..k]),
                Err(crate::errno::Errno::EINTR) => continue,
                Err(_) => return Err(SshError::Io),
            }
        }
        Ok(())
    }

    /// Read the peer's identification line (skipping any banner lines).
    pub fn read_version(&mut self) -> SResult<String> {
        let mut total = 0;
        loop {
            let pos = loop {
                if let Some(p) = self.buf.iter().position(|&b| b == b'\n') {
                    break p;
                }
                if self.buf.len() > 1024 {
                    return proto("identification line too long");
                }
                let want = self.buf.len() + 1;
                self.fill(want, Some(30_000))?;
            };
            let line: Vec<u8> = self.buf.drain(..=pos).collect();
            total += line.len();
            let s = String::from_utf8_lossy(&line).trim_end_matches(['\r', '\n']).to_string();
            if s.starts_with("SSH-") {
                if !s.starts_with("SSH-2.0-") && !s.starts_with("SSH-1.99-") {
                    return proto("unsupported protocol version");
                }
                return Ok(s);
            }
            if total > 8192 {
                return proto("no identification line");
            }
        }
    }

    /// Next packet payload (decrypted and authenticated).
    pub fn read_packet(&mut self, timeout_ms: Option<u64>) -> SResult<Vec<u8>> {
        let seq = self.keys.seq;
        enum Mode {
            Plain,
            ChaCha([u8; 32], [u8; 32]),
            CtrEtm,
            CtrEam,
        }
        let mode = match &self.keys.cipher {
            Cipher::Plain => Mode::Plain,
            Cipher::ChaCha { main, hdr } => Mode::ChaCha(*main, *hdr),
            _ if self.keys.mac == MacAlg::HmacSha256Etm => Mode::CtrEtm,
            _ => Mode::CtrEam,
        };
        let payload = match mode {
            Mode::Plain => {
                self.fill(4, timeout_ms)?;
                let len = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
                if len < 5 || len > MAX_PACKET {
                    return proto("bad packet length");
                }
                self.fill(4 + len, timeout_ms)?;
                let pkt: Vec<u8> = self.buf.drain(..4 + len).collect();
                unpad(&pkt[4..])?
            }
            Mode::ChaCha(main, hdr) => {
                self.fill(4, timeout_ms)?;
                let mut lenb = [self.buf[0], self.buf[1], self.buf[2], self.buf[3]];
                chacha_crypt(&hdr, seq, 0, &mut lenb);
                let len = u32::from_be_bytes(lenb) as usize;
                if len < 8 || len > MAX_PACKET || len % 8 != 0 {
                    return proto("bad packet length");
                }
                self.fill(4 + len + 16, timeout_ms)?;
                let pk = chacha_poly_key(&main, seq);
                let tag = Poly1305::new(&pk.into()).compute_unpadded(&self.buf[..4 + len]);
                if !ct_eq(&tag, &self.buf[4 + len..4 + len + 16]) {
                    return Err(SshError::Mac);
                }
                let mut body: Vec<u8> = self.buf[4..4 + len].to_vec();
                self.buf.drain(..4 + len + 16);
                chacha_crypt(&main, seq, 1, &mut body);
                unpad(&body)?
            }
            Mode::CtrEtm => {
                self.fill(4, timeout_ms)?;
                let len = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
                if len < 16 || len > MAX_PACKET || len % 16 != 0 {
                    return proto("bad packet length");
                }
                self.fill(4 + len + 32, timeout_ms)?;
                let tag = self.keys.hmac(&[&self.buf[..4 + len]]);
                if !ct_eq(&tag, &self.buf[4 + len..4 + len + 32]) {
                    return Err(SshError::Mac);
                }
                let mut body: Vec<u8> = self.buf[4..4 + len].to_vec();
                self.buf.drain(..4 + len + 32);
                self.keys.ctr_apply(&mut body);
                unpad(&body)?
            }
            Mode::CtrEam => {
                // Encrypt-and-MAC: the length is inside the first encrypted
                // block, and the keystream must advance exactly once.
                self.fill(16, timeout_ms)?;
                let mut first = [0u8; 16];
                first.copy_from_slice(&self.buf[..16]);
                let mut probe = first;
                let len = {
                    // Decrypt a copy of the cipher state to peek at the length.
                    let saved = self.keys.clone_ctr();
                    self.keys.ctr_apply(&mut probe);
                    self.keys.restore_ctr(saved);
                    u32::from_be_bytes([probe[0], probe[1], probe[2], probe[3]]) as usize
                };
                if len < 12 || len > MAX_PACKET || (len + 4) % 16 != 0 {
                    return proto("bad packet length");
                }
                self.fill(4 + len + 32, timeout_ms)?;
                let mut plain: Vec<u8> = self.buf[..4 + len].to_vec();
                self.keys.ctr_apply(&mut plain);
                let tag = self.keys.hmac(&[&plain]);
                if !ct_eq(&tag, &self.buf[4 + len..4 + len + 32]) {
                    return Err(SshError::Mac);
                }
                self.buf.drain(..4 + len + 32);
                unpad(&plain[4..])?
            }
        };
        self.keys.seq = self.keys.seq.wrapping_add(1);
        Ok(payload)
    }

    fn set_keys(&mut self, k: Keys) {
        self.keys = k;
        if self.strict {
            self.keys.seq = 0;
        }
    }
}

fn unpad(body: &[u8]) -> SResult<Vec<u8>> {
    let pad = *body.first().ok_or(SshError::Protocol("empty packet".into()))? as usize;
    if pad < 4 || pad + 1 > body.len() {
        return proto("bad padding");
    }
    let payload = body[1..body.len() - pad].to_vec();
    if payload.is_empty() {
        return proto("empty payload");
    }
    Ok(payload)
}

// ── key exchange ────────────────────────────────────────────────────────────

pub struct HostKey {
    pub signing: ed25519_dalek::SigningKey,
}

impl HostKey {
    pub fn public_blob(&self) -> Vec<u8> {
        let pk = self.signing.verifying_key().to_bytes();
        let mut w = Writer::new();
        w.str("ssh-ed25519").string(&pk);
        w.done()
    }
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let sig = self.signing.sign(data).to_bytes();
        let mut w = Writer::new();
        w.str("ssh-ed25519").string(&sig);
        w.done()
    }
}

/// Negotiated algorithms for both directions.
#[derive(Clone, Copy, Debug)]
pub struct Negotiated {
    pub c2s: (CipherAlg, MacAlg),
    pub s2c: (CipherAlg, MacAlg),
    pub strict: bool,
    pub ext_info: bool,
}

fn pick(client: &[String], server: &str) -> Option<String> {
    client.iter().find(|c| server.split(',').any(|s| s == c.as_str())).cloned()
}

pub fn server_kexinit() -> Vec<u8> {
    let mut w = Writer::msg(msg::KEXINIT);
    w.raw(&rng::array::<16>());
    w.str(KEX_ALGS).str(HOSTKEY_ALGS).str(CIPHERS).str(CIPHERS).str(MACS).str(MACS).str("none").str("none").str("").str("");
    w.bool(false).u32(0);
    w.done()
}

pub fn negotiate(client_kexinit: &[u8]) -> SResult<Negotiated> {
    let mut r = Reader::new(client_kexinit);
    let bad = |_| SshError::Protocol("malformed KEXINIT".into());
    r.u8().map_err(bad)?;
    r.bytes(16).map_err(bad)?;
    let kex = r.name_list().map_err(bad)?;
    let hk = r.name_list().map_err(bad)?;
    let enc_cs = r.name_list().map_err(bad)?;
    let enc_sc = r.name_list().map_err(bad)?;
    let mac_cs = r.name_list().map_err(bad)?;
    let mac_sc = r.name_list().map_err(bad)?;
    let comp_cs = r.name_list().map_err(bad)?;
    let comp_sc = r.name_list().map_err(bad)?;
    if pick(&kex, "curve25519-sha256,curve25519-sha256@libssh.org").is_none() {
        return proto("no common key exchange algorithm");
    }
    if pick(&hk, HOSTKEY_ALGS).is_none() {
        return proto("no common host key algorithm (need ssh-ed25519)");
    }
    if pick(&comp_cs, "none").is_none() || pick(&comp_sc, "none").is_none() {
        return proto("compression required by client");
    }
    let dir = |enc: &[String], mac: &[String]| -> SResult<(CipherAlg, MacAlg)> {
        let c = pick(enc, CIPHERS).and_then(|n| CipherAlg::from_name(&n)).ok_or(SshError::Protocol("no common cipher".into()))?;
        if c == CipherAlg::ChaChaPoly {
            return Ok((c, MacAlg::Aead));
        }
        let m = match pick(mac, MACS).as_deref() {
            Some("hmac-sha2-256-etm@openssh.com") => MacAlg::HmacSha256Etm,
            Some("hmac-sha2-256") => MacAlg::HmacSha256,
            _ => return proto("no common MAC"),
        };
        Ok((c, m))
    };
    Ok(Negotiated {
        c2s: dir(&enc_cs, &mac_cs)?,
        s2c: dir(&enc_sc, &mac_sc)?,
        strict: kex.iter().any(|k| k == "kex-strict-c-v00@openssh.com"),
        ext_info: kex.iter().any(|k| k == "ext-info-c"),
    })
}

fn derive(k_mpint: &[u8], h: &[u8; 32], letter: u8, session_id: &[u8; 32], len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut d = Sha256::new();
    d.update(k_mpint);
    d.update(h);
    d.update([letter]);
    d.update(session_id);
    out.extend_from_slice(&d.finalize());
    while out.len() < len {
        let mut d = Sha256::new();
        d.update(k_mpint);
        d.update(h);
        d.update(&out);
        out.extend_from_slice(&d.finalize());
    }
    out.truncate(len);
    out
}

/// Everything exchanged so far that the exchange hash covers.
pub struct KexContext<'a> {
    pub client_version: &'a str,
    pub client_kexinit: &'a [u8],
    pub server_kexinit: &'a [u8],
}

/// Server side of curve25519-sha256: handle `KEX_ECDH_INIT`, reply, send
/// NEWKEYS, wait for the client's NEWKEYS, switch keys. Returns the
/// exchange hash (the session id on the first exchange).
pub fn server_kex(
    ctx: &KexContext,
    neg: &Negotiated,
    host: &HostKey,
    session_id: Option<[u8; 32]>,
    recv: &mut RecvHalf,
    send: &Sender,
    ecdh_init: &[u8],
) -> SResult<[u8; 32]> {
    let mut r = Reader::new(ecdh_init);
    r.u8().map_err(|_| SshError::Protocol("bad ECDH_INIT".into()))?;
    let q_c = r.string().map_err(|_| SshError::Protocol("bad ECDH_INIT".into()))?;
    if q_c.len() != 32 {
        return proto("bad client ephemeral key");
    }
    let secret = x25519_dalek::StaticSecret::from(rng::array::<32>());
    let q_s = x25519_dalek::PublicKey::from(&secret);
    let mut qc = [0u8; 32];
    qc.copy_from_slice(q_c);
    let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(qc));
    if !shared.was_contributory() {
        return proto("low-order ephemeral key");
    }
    let k_mpint = Writer::new().mpint(shared.as_bytes()).done();
    let ks = host.public_blob();
    let mut hw = Writer::new();
    hw.str(ctx.client_version).str(SERVER_VERSION).string(ctx.client_kexinit).string(ctx.server_kexinit).string(&ks).string(q_c).string(q_s.as_bytes());
    hw.raw(&k_mpint);
    let h: [u8; 32] = Sha256::digest(&hw.b).into();
    let sid = session_id.unwrap_or(h);
    let mut reply = Writer::msg(msg::KEX_ECDH_REPLY);
    reply.string(&ks).string(q_s.as_bytes()).string(&host.sign(&h));
    send.send_kex(&reply.done())?;

    let mk = |letter_iv: u8, letter_key: u8, letter_mac: u8, (alg, mac): (CipherAlg, MacAlg)| -> Keys {
        let iv = derive(&k_mpint, &h, letter_iv, &sid, alg.iv_len().max(1));
        let key = derive(&k_mpint, &h, letter_key, &sid, alg.key_len());
        let mk = if mac == MacAlg::Aead { Vec::new() } else { derive(&k_mpint, &h, letter_mac, &sid, 32) };
        Keys::new(alg, mac, &key, &iv, mk, 0)
    };
    // Our NEWKEYS, then the new outgoing keys — atomically for writers.
    {
        let mut s = send.lock();
        s.strict = neg.strict;
        s.send_packet(&[msg::NEWKEYS])?;
        s.set_keys(mk(b'B', b'D', b'F', neg.s2c));
        s.bytes_since_kex = 0;
    }
    loop {
        let p = recv.read_packet(Some(60_000))?;
        match p[0] {
            msg::NEWKEYS => break,
            msg::IGNORE | msg::DEBUG if !neg.strict => continue,
            msg::DISCONNECT => return Err(SshError::Disconnected("peer disconnected during key exchange".into())),
            _ => return proto("unexpected message during key exchange"),
        }
    }
    recv.strict = neg.strict;
    recv.set_keys(mk(b'A', b'C', b'E', neg.c2s));
    Ok(h)
}

pub fn disconnect_msg(reason: u32, text: &str) -> Vec<u8> {
    let mut w = Writer::msg(msg::DISCONNECT);
    w.u32(reason).str(text).str("");
    w.done()
}

pub use super::wire::disconnect as reasons;
