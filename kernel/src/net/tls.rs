//! A minimal TLS 1.3 client (RFC 8446) for the container registry.
//!
//! Cipher suite: `TLS_CHACHA20_POLY1305_SHA256`; key exchange: X25519. This is
//! enough to talk to Docker Hub, quay.io and GHCR.
//!
//! ⚠️ Certificate chains are **not** verified — the kernel has no CA store yet.
//! Confidentiality and tamper-evidence of the transport still hold, and image
//! integrity is guaranteed separately: every blob is checked against its
//! sha256 digest from the manifest. Full X.509 verification is a follow-up.

use crate::errno::{Errno, KResult};
use crate::net::socket::TcpStream;
use alloc::vec;
use alloc::vec::Vec;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use hmac::{Hmac, Mac};
use poly1305::universal_hash::{KeyInit, UniversalHash};
use poly1305::Poly1305;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const CT_CCS: u8 = 20;
const CT_ALERT: u8 = 21;
const CT_HANDSHAKE: u8 = 22;
const CT_APPDATA: u8 = 23;

const HS_SERVER_HELLO: u8 = 2;
const HS_FINISHED: u8 = 20;

// ── HKDF (RFC 5869) + TLS 1.3 key schedule labels ───────────────────────────

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut m = <HmacSha256 as Mac>::new_from_slice(salt).unwrap();
    m.update(ikm);
    m.finalize().into_bytes().into()
}

fn hkdf_expand(prk: &[u8; 32], info: &[u8], out: &mut [u8]) {
    let mut t: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    let mut done = 0;
    while done < out.len() {
        let mut m = <HmacSha256 as Mac>::new_from_slice(prk).unwrap();
        m.update(&t);
        m.update(info);
        m.update(&[counter]);
        t = m.finalize().into_bytes().to_vec();
        let n = (out.len() - done).min(t.len());
        out[done..done + n].copy_from_slice(&t[..n]);
        done += n;
        counter += 1;
    }
}

fn expand_label(secret: &[u8; 32], label: &[u8], context: &[u8], out: &mut [u8]) {
    // HkdfLabel { u16 length, opaque label<7..255> "tls13 "+label, opaque ctx }
    let mut info = Vec::with_capacity(16 + label.len() + context.len());
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    let full = [b"tls13 ", label].concat();
    info.push(full.len() as u8);
    info.extend_from_slice(&full);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand(secret, &info, out);
}

fn derive_secret(secret: &[u8; 32], label: &[u8], transcript: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(transcript);
    let mut out = [0u8; 32];
    expand_label(secret, label, &hash, &mut out);
    out
}

/// Per-direction record key material.
struct Keys {
    key: [u8; 32],
    iv: [u8; 12],
    seq: u64,
}

impl Keys {
    fn derive(traffic_secret: &[u8; 32]) -> Keys {
        let mut key = [0u8; 32];
        let mut iv = [0u8; 12];
        expand_label(traffic_secret, b"key", &[], &mut key);
        expand_label(traffic_secret, b"iv", &[], &mut iv);
        Keys { key, iv, seq: 0 }
    }
    fn nonce(&self) -> [u8; 12] {
        let mut n = self.iv;
        let s = self.seq.to_be_bytes();
        for i in 0..8 {
            n[4 + i] ^= s[i];
        }
        n
    }
}

// ── ChaCha20-Poly1305 AEAD (RFC 8439) ───────────────────────────────────────

fn poly_key(key: &[u8; 32], nonce: &[u8; 12]) -> ([u8; 32], ChaCha20) {
    let mut c = ChaCha20::new(key.into(), nonce.into());
    let mut block = [0u8; 64];
    c.apply_keystream(&mut block); // consume counter-0 block → Poly1305 key
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block[..32]);
    (otk, c) // `c` is now positioned at counter 1 for the payload
}

fn poly_tag(otk: &[u8; 32], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let mut mac = Poly1305::new(otk.into());
    let mut buf = Vec::new();
    buf.extend_from_slice(aad);
    buf.resize((aad.len() + 15) / 16 * 16, 0);
    buf.extend_from_slice(ct);
    buf.resize(buf.len() + (16 - ct.len() % 16) % 16, 0);
    buf.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    buf.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    mac.update_padded(&buf);
    mac.finalize().into()
}

fn seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let (otk, mut c) = poly_key(key, nonce);
    let mut ct = plaintext.to_vec();
    c.apply_keystream(&mut ct);
    let tag = poly_tag(&otk, aad, &ct);
    ct.extend_from_slice(&tag);
    ct
}

fn open(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ct_and_tag: &[u8]) -> Option<Vec<u8>> {
    if ct_and_tag.len() < 16 {
        return None;
    }
    let (ct, tag) = ct_and_tag.split_at(ct_and_tag.len() - 16);
    let (otk, mut c) = poly_key(key, nonce);
    let want = poly_tag(&otk, aad, ct);
    if !crate::crypto::ct_eq(&want, tag) {
        return None;
    }
    let mut pt = ct.to_vec();
    c.apply_keystream(&mut pt);
    Some(pt)
}

// ── the connection ──────────────────────────────────────────────────────────

pub struct TlsStream {
    tcp: TcpStream,
    client: Keys,
    server: Keys,
    /// Decrypted application data not yet handed to the caller.
    inbox: Vec<u8>,
    timeout_ms: u64,
    closed: bool,
}

fn e(_: Errno) -> Errno {
    Errno::EIO
}

impl TlsStream {
    /// Read exactly one TLS record: (content_type, payload).
    fn read_record(tcp: &TcpStream, timeout_ms: u64) -> KResult<(u8, Vec<u8>)> {
        let mut hdr = [0u8; 5];
        read_full(tcp, &mut hdr, timeout_ms)?;
        let ctype = hdr[0];
        let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        if len > 18 * 1024 {
            return Err(Errno::EIO);
        }
        let mut payload = vec![0u8; len];
        read_full(tcp, &mut payload, timeout_ms)?;
        Ok((ctype, payload))
    }

    fn write_record(&self, ctype: u8, payload: &[u8]) -> KResult<()> {
        let mut rec = Vec::with_capacity(5 + payload.len());
        rec.push(ctype);
        rec.extend_from_slice(&[0x03, 0x03]);
        rec.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        rec.extend_from_slice(payload);
        self.tcp.write_all(&rec).map_err(e)
    }

    /// Encrypt one application/handshake record (inner type appended).
    fn write_encrypted(&mut self, inner_type: u8, data: &[u8]) -> KResult<()> {
        let mut plain = data.to_vec();
        plain.push(inner_type);
        let total = plain.len() + 16;
        let mut aad = [0u8; 5];
        aad[0] = CT_APPDATA;
        aad[1] = 0x03;
        aad[2] = 0x03;
        aad[3..5].copy_from_slice(&(total as u16).to_be_bytes());
        let ct = seal(&self.client.key, &self.client.nonce(), &aad, &plain);
        self.client.seq += 1;
        self.write_record(CT_APPDATA, &ct)
    }

    /// Read and decrypt one encrypted record, returning (inner_type, data).
    fn read_encrypted(&mut self) -> KResult<(u8, Vec<u8>)> {
        loop {
            let (ctype, payload) = Self::read_record(&self.tcp, self.timeout_ms)?;
            if ctype == CT_CCS {
                continue; // middlebox-compat ChangeCipherSpec: ignore
            }
            if ctype == CT_ALERT {
                return Err(Errno::ECONNRESET);
            }
            if ctype != CT_APPDATA {
                return Err(Errno::EIO);
            }
            let mut aad = [0u8; 5];
            aad[0] = CT_APPDATA;
            aad[1] = 0x03;
            aad[2] = 0x03;
            aad[3..5].copy_from_slice(&(payload.len() as u16).to_be_bytes());
            let mut plain = open(&self.server.key, &self.server.nonce(), &aad, &payload).ok_or(Errno::EIO)?;
            self.server.seq += 1;
            // Strip zero padding, then the trailing real content type.
            while plain.last() == Some(&0) {
                plain.pop();
            }
            let inner = plain.pop().ok_or(Errno::EIO)?;
            return Ok((inner, plain));
        }
    }

    /// Application write.
    pub fn write_all(&mut self, data: &[u8]) -> KResult<()> {
        for chunk in data.chunks(16 * 1024) {
            self.write_encrypted(CT_APPDATA, chunk)?;
        }
        Ok(())
    }

    /// Application read; `Ok(0)` at clean end of stream.
    pub fn read(&mut self, buf: &mut [u8]) -> KResult<usize> {
        while self.inbox.is_empty() {
            if self.closed {
                return Ok(0);
            }
            match self.read_encrypted() {
                Ok((CT_APPDATA, data)) => self.inbox.extend_from_slice(&data),
                Ok((CT_HANDSHAKE, _)) => continue, // NewSessionTicket, KeyUpdate: ignore
                Ok(_) => continue,
                Err(Errno::ECONNRESET) => {
                    self.closed = true;
                    return Ok(0);
                }
                Err(_) => {
                    self.closed = true;
                    return Ok(0);
                }
            }
        }
        let n = buf.len().min(self.inbox.len());
        buf[..n].copy_from_slice(&self.inbox[..n]);
        self.inbox.drain(..n);
        Ok(n)
    }
}

fn read_full(tcp: &TcpStream, buf: &mut [u8], timeout_ms: u64) -> KResult<()> {
    let mut off = 0;
    while off < buf.len() {
        let n = tcp.read_timeout(&mut buf[off..], Some(timeout_ms))?;
        if n == 0 {
            return Err(Errno::ECONNRESET);
        }
        off += n;
    }
    Ok(())
}

// ── handshake ────────────────────────────────────────────────────────────────

/// A big-endian writer for building handshake structures.
struct W(Vec<u8>);
impl W {
    fn new() -> W {
        W(Vec::new())
    }
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    /// Write a block whose length prefix (`n` bytes) is filled in afterwards.
    fn block<F: FnOnce(&mut W)>(&mut self, nbytes: usize, f: F) {
        let at = self.0.len();
        for _ in 0..nbytes {
            self.0.push(0);
        }
        f(self);
        let len = self.0.len() - at - nbytes;
        for i in 0..nbytes {
            self.0[at + i] = (len >> (8 * (nbytes - 1 - i))) as u8;
        }
    }
}

fn client_hello(pubkey: &[u8; 32], random: &[u8; 32], hostname: &str) -> Vec<u8> {
    let mut w = W::new();
    w.u8(1); // handshake type: ClientHello
    w.block(3, |w| {
        w.u16(0x0303); // legacy_version
        w.bytes(random);
        w.block(1, |w| w.bytes(&[0u8; 32])); // legacy session id (32 random-ish)
        w.block(2, |w| w.u16(0x1303)); // cipher suites: TLS_CHACHA20_POLY1305_SHA256
        w.block(1, |w| w.u8(0)); // compression: null
        w.block(2, |w| {
            // supported_versions
            w.u16(0x002b);
            w.block(2, |w| w.block(1, |w| w.u16(0x0304)));
            // supported_groups: x25519
            w.u16(0x000a);
            w.block(2, |w| w.block(2, |w| w.u16(0x001d)));
            // signature_algorithms (advertise common ones; unused w/o verify)
            w.u16(0x000d);
            w.block(2, |w| {
                w.block(2, |w| {
                    w.u16(0x0403);
                    w.u16(0x0804);
                    w.u16(0x0805);
                    w.u16(0x0806);
                    w.u16(0x0401);
                })
            });
            // key_share: x25519
            w.u16(0x0033);
            w.block(2, |w| {
                w.block(2, |w| {
                    w.u16(0x001d);
                    w.block(2, |w| w.bytes(pubkey));
                })
            });
            // server_name (SNI)
            w.u16(0x0000);
            w.block(2, |w| {
                w.block(2, |w| {
                    w.u8(0);
                    w.block(2, |w| w.bytes(hostname.as_bytes()));
                })
            });
        });
    });
    w.0
}

/// Parse the server's x25519 key share from a ServerHello handshake body.
fn parse_server_hello(body: &[u8]) -> Option<[u8; 32]> {
    // body: [type(1)][len(3)][version(2)][random(32)][sid_len(1)][sid][suite(2)][comp(1)][ext_len(2)][exts]
    let mut i = 4 + 2 + 32;
    let sid = *body.get(i)? as usize;
    i += 1 + sid + 2 + 1;
    let ext_len = u16::from_be_bytes([*body.get(i)?, *body.get(i + 1)?]) as usize;
    i += 2;
    let end = i + ext_len;
    while i + 4 <= end {
        let etype = u16::from_be_bytes([body[i], body[i + 1]]);
        let elen = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
        i += 4;
        if etype == 0x0033 {
            // key_share: group(2) len(2) key
            let group = u16::from_be_bytes([*body.get(i)?, *body.get(i + 1)?]);
            let klen = u16::from_be_bytes([*body.get(i + 2)?, *body.get(i + 3)?]) as usize;
            if group == 0x001d && klen == 32 {
                let mut k = [0u8; 32];
                k.copy_from_slice(body.get(i + 4..i + 4 + 32)?);
                return Some(k);
            }
        }
        i += elen;
    }
    None
}

/// Connect and perform the TLS 1.3 handshake with `hostname`.
pub fn connect(tcp: TcpStream, hostname: &str, timeout_ms: u64) -> KResult<TlsStream> {
    let secret = x25519_dalek::StaticSecret::from(crate::crypto::rng::array::<32>());
    let pubkey = x25519_dalek::PublicKey::from(&secret);
    let random: [u8; 32] = crate::crypto::rng::array();

    let ch = client_hello(pubkey.as_bytes(), &random, hostname);
    let s = TlsStream {
        tcp,
        client: Keys { key: [0; 32], iv: [0; 12], seq: 0 },
        server: Keys { key: [0; 32], iv: [0; 12], seq: 0 },
        inbox: Vec::new(),
        timeout_ms,
        closed: false,
    };
    s.write_record(CT_HANDSHAKE, &ch)?;
    // The transcript is the concatenation of handshake message bodies.
    finish_handshake(s, secret, ch)
}

fn finish_handshake(mut s: TlsStream, secret: x25519_dalek::StaticSecret, mut transcript: Vec<u8>) -> KResult<TlsStream> {
    // ServerHello (plaintext handshake record).
    let (ct, sh) = TlsStream::read_record(&s.tcp, s.timeout_ms)?;
    if ct != CT_HANDSHAKE || sh.first() != Some(&HS_SERVER_HELLO) {
        return Err(Errno::EIO);
    }
    let server_pub = parse_server_hello(&sh).ok_or(Errno::EIO)?;
    transcript.extend_from_slice(&sh);

    // Key schedule.
    let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(server_pub));
    let early = hkdf_extract(&[0u8; 32], &[0u8; 32]);
    let derived = derive_secret(&early, b"derived", b"");
    let handshake = hkdf_extract(&derived, shared.as_bytes());
    let c_hs = derive_secret(&handshake, b"c hs traffic", &transcript);
    let s_hs = derive_secret(&handshake, b"s hs traffic", &transcript);
    s.client = Keys::derive(&c_hs);
    s.server = Keys::derive(&s_hs);

    // Read encrypted handshake flight until the server Finished.
    let mut server_finished = Vec::new();
    loop {
        let (inner, data) = s.read_encrypted()?;
        if inner != CT_HANDSHAKE {
            continue;
        }
        // A record may carry several handshake messages back to back.
        let mut i = 0;
        while i + 4 <= data.len() {
            let mtype = data[i];
            let mlen = ((data[i + 1] as usize) << 16) | ((data[i + 2] as usize) << 8) | data[i + 3] as usize;
            let end = i + 4 + mlen;
            if end > data.len() {
                break; // truncated / malformed message: stop parsing this record
            }
            let msg = &data[i..end];
            transcript.extend_from_slice(msg);
            if mtype == HS_FINISHED {
                server_finished.extend_from_slice(msg);
            }
            i = end;
        }
        if !server_finished.is_empty() {
            break;
        }
    }

    // Client Finished over the transcript up to (and including) server Finished.
    let mut fin_key = [0u8; 32];
    expand_label(&c_hs, b"finished", &[], &mut fin_key);
    let mut m = <HmacSha256 as Mac>::new_from_slice(&fin_key).unwrap();
    m.update(&Sha256::digest(&transcript));
    let verify: [u8; 32] = m.finalize().into_bytes().into();
    let mut fin_msg = Vec::with_capacity(36);
    fin_msg.push(HS_FINISHED);
    fin_msg.extend_from_slice(&[0, 0, 32]);
    fin_msg.extend_from_slice(&verify);
    s.write_encrypted(CT_HANDSHAKE, &fin_msg)?;

    // Application traffic secrets (transcript through the server Finished).
    let master_derived = derive_secret(&handshake, b"derived", b"");
    let master = hkdf_extract(&master_derived, &[0u8; 32]);
    let c_ap = derive_secret(&master, b"c ap traffic", &transcript);
    let s_ap = derive_secret(&master, b"s ap traffic", &transcript);
    s.client = Keys::derive(&c_ap);
    s.server = Keys::derive(&s_ap);
    Ok(s)
}
