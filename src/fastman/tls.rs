//! TLS 1.3 client (RFC 8446) — minimal, no certificate verification.
//!
//! Cipher suite : TLS_CHACHA20_POLY1305_SHA256 (0x1303)
//! Key exchange  : X25519 (RFC 7748)
//! Transcript    : SHA-256
//!
//! Certificate verification is intentionally SKIPPED.
//! The kernel has no CA store; it accepts any server certificate.
//! WARNING: susceptible to MITM on untrusted networks.
//!
//! Usage:
//!   let fd = net::tcp_connect(ip, 443)?;
//!   // ... wait for Established ...
//!   let mut conn = tls::handshake(fd, b"registry-1.docker.io")?;
//!   tls::send(fd, &mut conn, b"GET / HTTP/1.1\r\n...\r\n\r\n");
//!   let n = tls::recv(fd, &mut conn, &mut buf);

use crate::kernel::net::{self, tcp};
use crate::kernel::net::ssh::crypto::{chacha20, poly1305, hmac, sha256, curve25519};

// ── Public state ──────────────────────────────────────────────────────────────

pub struct TlsConn {
    server_key: [u8; 32],
    server_iv:  [u8; 12],
    client_key: [u8; 32],
    client_iv:  [u8; 12],
    server_seq: u64,
    client_seq: u64,
}

// ── Static buffers (single-threaded) ─────────────────────────────────────────

static mut TX_BUF:  [u8; 4096]  = [0; 4096];
static mut RX_BUF:  [u8; 20000] = [0; 20000];  // raw TCP accumulation
static mut PT_BUF:  [u8; 16640] = [0; 16640];  // decrypted record payload
static mut MAC_BUF: [u8; 20100] = [0; 20100];  // poly1305 input construction
static mut TR_BUF:  [u8; 8192]  = [0; 8192];   // handshake transcript bytes
static mut TR_LEN:  usize       = 0;

// SHA-256("") — used for Derive-Secret with empty message set
const EMPTY_HASH: [u8; 32] = [
    0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,
    0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
    0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,
    0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55,
];

// ── Public API ────────────────────────────────────────────────────────────────

/// Perform TLS 1.3 handshake on an ESTABLISHED TCP socket.
/// Returns None if the handshake fails.
pub fn handshake(fd: usize, hostname: &[u8]) -> Option<TlsConn> {
    // Reset transcript
    unsafe { TR_LEN = 0; }

    // Generate ephemeral X25519 key pair
    let private_key = pseudo_random32();
    let public_key  = curve25519::public_key(&private_key);

    // Build and send ClientHello
    let ch_len = unsafe { build_client_hello(&mut TX_BUF, &pseudo_random32(), &public_key, hostname) };
    // Add handshake body (skip 5-byte TLS record header) to transcript
    transcript_add(unsafe { &TX_BUF[5..ch_len] });
    if !net::tcp_send(fd, unsafe { &TX_BUF[..ch_len] }) { return None; }

    // ── Read ServerHello (unencrypted) ────────────────────────────────────────
    let sh_data = read_plain_record(fd, 0x16)?;   // 0x16 = Handshake
    let server_pub = parse_server_hello(sh_data)?;
    transcript_add(sh_data);

    // ── Key schedule phase 1: Handshake keys ─────────────────────────────────
    let dhe = curve25519::shared_secret(&private_key, &server_pub);

    let early_secret = hkdf_extract(&[0u8; 32], &[0u8; 32]);
    let es_derived   = derive_secret(&early_secret, b"derived", &EMPTY_HASH);
    let hs           = hkdf_extract(&es_derived, &dhe);

    let ch_sh_hash = transcript_hash();
    let srv_hs_ts  = derive_secret(&hs, b"s hs traffic", &ch_sh_hash);
    let cli_hs_ts  = derive_secret(&hs, b"c hs traffic", &ch_sh_hash);

    let mut srv_hs_key = [0u8; 32]; let mut srv_hs_iv = [0u8; 12];
    let mut cli_hs_key = [0u8; 32]; let mut cli_hs_iv = [0u8; 12];
    traffic_keys(&srv_hs_ts, &mut srv_hs_key, &mut srv_hs_iv);
    traffic_keys(&cli_hs_ts, &mut cli_hs_key, &mut cli_hs_iv);

    // ── Read and buffer server handshake messages (encrypted) ─────────────────
    // In TLS 1.3 the server sends EncryptedExtensions + Certificate +
    // CertificateVerify + Finished — often coalesced into one or two records.
    let mut srv_seq = 0u64;

    loop {
        let pt = decrypt_record(fd, &srv_hs_key, &srv_hs_iv, &mut srv_seq)?;
        if pt.is_empty() { break; }

        // Parse handshake messages within this plaintext.
        // The last byte is the content type (22 = Handshake).
        let content = inner_content(pt);
        if content.is_empty() { continue; }

        let mut done = false;
        let mut pos = 0usize;
        while pos + 4 <= content.len() {
            let msg_type = content[pos];
            let msg_len  = u24_be(&content[pos + 1..]) as usize;
            let msg_end  = pos + 4 + msg_len;
            if msg_end > content.len() { break; }

            // Add entire handshake message (type + len + body) to transcript
            transcript_add(&content[pos..msg_end]);

            if msg_type == 20 { done = true; } // Finished — stop reading
            pos = msg_end;
        }
        if done { break; }
    }

    // ── Key schedule phase 2: Master / Application keys ──────────────────────
    let full_hash   = transcript_hash();
    let hs_derived  = derive_secret(&hs, b"derived", &EMPTY_HASH);
    let ms          = hkdf_extract(&hs_derived, &[0u8; 32]);
    let srv_app_ts  = derive_secret(&ms, b"s ap traffic", &full_hash);
    let cli_app_ts  = derive_secret(&ms, b"c ap traffic", &full_hash);

    let mut srv_app_key = [0u8; 32]; let mut srv_app_iv = [0u8; 12];
    let mut cli_app_key = [0u8; 32]; let mut cli_app_iv = [0u8; 12];
    traffic_keys(&srv_app_ts, &mut srv_app_key, &mut srv_app_iv);
    traffic_keys(&cli_app_ts, &mut cli_app_key, &mut cli_app_iv);

    // ── Send ClientFinished ───────────────────────────────────────────────────
    // finished_key = HKDF-Expand-Label(cli_hs_ts, "finished", "", 32)
    let mut fin_key = [0u8; 32];
    hkdf_expand_label(&cli_hs_ts, b"finished", &[], &mut fin_key);
    // verify_data = HMAC-SHA256(fin_key, transcript_hash_at_this_point)
    let transcript_before_client_fin = transcript_hash();
    let verify_data = hmac::mac(&fin_key, &transcript_before_client_fin);

    // Build Finished handshake message: [type=20][len=32][verify_data]
    let mut fin_msg = [0u8; 36];
    fin_msg[0] = 20;
    fin_msg[1..4].copy_from_slice(&(32u32).to_be_bytes()[1..]);  // 3-byte length = 32
    fin_msg[4..36].copy_from_slice(&verify_data);

    // Encrypt and send ClientFinished as a Handshake record (type 22)
    let mut cli_hs_seq = 0u64;
    let enc_len = unsafe {
        seal_record(&cli_hs_key, &cli_hs_iv, &mut cli_hs_seq, 22, &fin_msg, &mut TX_BUF)
    };
    if enc_len == 0 || !net::tcp_send(fd, unsafe { &TX_BUF[..enc_len] }) {
        return None;
    }

    Some(TlsConn {
        server_key: srv_app_key, server_iv: srv_app_iv,
        client_key: cli_app_key, client_iv: cli_app_iv,
        server_seq: 0, client_seq: 0,
    })
}

/// Send application data (HTTP request) encrypted with TLS.
pub fn send(fd: usize, conn: &mut TlsConn, data: &[u8]) -> bool {
    // Split into chunks ≤ 4060 bytes (leaving room for TLS overhead)
    let mut pos = 0usize;
    while pos < data.len() {
        let chunk_end = (pos + 4060).min(data.len());
        let chunk = &data[pos..chunk_end];
        let enc_len = unsafe {
            seal_record(&conn.client_key, &conn.client_iv, &mut conn.client_seq, 23, chunk, &mut TX_BUF)
        };
        if enc_len == 0 || !net::tcp_send(fd, unsafe { &TX_BUF[..enc_len] }) {
            return false;
        }
        pos = chunk_end;
    }
    true
}

/// Receive and decrypt application data. Returns bytes written to buf.
pub fn recv(fd: usize, conn: &mut TlsConn, buf: &mut [u8]) -> usize {
    let mut total = 0usize;
    // Poll for up to ~10 seconds
    for _ in 0..10_000_000u64 {
        net::poll_drivers();

        match net::tcp_state_of(fd) {
            tcp::TcpState::CloseWait | tcp::TcpState::Closed => {
                if net::tcp_rx_available(fd) == 0 { break; }
            }
            _ => {}
        }

        if net::tcp_rx_available(fd) < 5 { continue; }

        // Try to read a record
        if let Some(pt) = decrypt_record(fd, &conn.server_key, &conn.server_iv, &mut conn.server_seq) {
            let content = inner_content(pt);
            let n = content.len().min(buf.len() - total);
            buf[total..total + n].copy_from_slice(&content[..n]);
            total += n;
            if total >= buf.len() { break; }
        }
    }
    total
}

// ── HKDF (RFC 5869) ──────────────────────────────────────────────────────────

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac::mac(salt, ikm)
}

fn hkdf_expand(prk: &[u8; 32], info: &[u8], out: &mut [u8]) {
    let mut t = [0u8; 32];
    let mut t_len = 0usize;
    let mut pos = 0usize;
    let mut ctr = 1u8;
    while pos < out.len() {
        let mut h = hmac::HmacSha256::new(prk);
        h.update(&t[..t_len]);
        h.update(info);
        h.update(&[ctr]);
        t = h.finalize();
        t_len = 32;
        let n = (out.len() - pos).min(32);
        out[pos..pos + n].copy_from_slice(&t[..n]);
        pos += n;
        ctr += 1;
    }
}

/// HKDF-Expand-Label as per RFC 8446 §7.1.
fn hkdf_expand_label(secret: &[u8; 32], label: &[u8], context: &[u8], out: &mut [u8]) {
    let prefix = b"tls13 ";
    let full_len = prefix.len() + label.len();
    let mut info = [0u8; 256];
    let len_u16 = out.len() as u16;
    info[0..2].copy_from_slice(&len_u16.to_be_bytes());
    info[2] = full_len as u8;
    info[3..3 + prefix.len()].copy_from_slice(prefix);
    info[3 + prefix.len()..3 + full_len].copy_from_slice(label);
    let mut p = 3 + full_len;
    info[p] = context.len() as u8;
    p += 1;
    if !context.is_empty() {
        info[p..p + context.len()].copy_from_slice(context);
        p += context.len();
    }
    hkdf_expand(secret, &info[..p], out);
}

/// Derive-Secret(S, label, transcript_hash).
fn derive_secret(secret: &[u8; 32], label: &[u8], hash: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    hkdf_expand_label(secret, label, hash, &mut out);
    out
}

/// Derive traffic key (32 bytes) and IV (12 bytes) from a traffic secret.
fn traffic_keys(ts: &[u8; 32], key: &mut [u8; 32], iv: &mut [u8; 12]) {
    hkdf_expand_label(ts, b"key", &[], key);
    hkdf_expand_label(ts, b"iv",  &[], iv);
}

// ── ChaCha20-Poly1305 AEAD (RFC 8439) ────────────────────────────────────────

/// Compute nonce = IV XOR (seq as big-endian u64, zero-padded to 12 bytes).
fn make_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut n = *iv;
    let seq_bytes = seq.to_be_bytes();
    for i in 0..8 { n[4 + i] ^= seq_bytes[i]; }
    n
}

/// Build Poly1305 MAC input: pad16(aad) || pad16(ct) || aad_len_le64 || ct_len_le64.
fn build_mac_input(aad: &[u8], ct: &[u8]) -> usize {
    let buf = unsafe { &mut MAC_BUF };
    let mut pos = 0usize;

    // pad16(aad)
    let apad = (16 - aad.len() % 16) % 16;
    buf[pos..pos + aad.len()].copy_from_slice(aad);
    pos += aad.len();
    buf[pos..pos + apad].fill(0);
    pos += apad;

    // pad16(ciphertext)
    let ctpad = (16 - ct.len() % 16) % 16;
    buf[pos..pos + ct.len()].copy_from_slice(ct);
    pos += ct.len();
    buf[pos..pos + ctpad].fill(0);
    pos += ctpad;

    // lengths
    buf[pos..pos + 8].copy_from_slice(&(aad.len() as u64).to_le_bytes()); pos += 8;
    buf[pos..pos + 8].copy_from_slice(&(ct.len()  as u64).to_le_bytes()); pos += 8;
    pos
}

/// Seal: encrypt plaintext + content_type into TLS record ciphertext.
/// Returns the length of the encrypted TLS record (written to out).
unsafe fn seal_record(
    key:     &[u8; 32],
    iv:      &[u8; 12],
    seq:     &mut u64,
    ct_type: u8,       // actual content type appended to plaintext
    payload: &[u8],
    out:     &mut [u8; 4096],
) -> usize {
    // Inner plaintext = payload || ct_type
    let pt_len = payload.len() + 1;
    if pt_len + 5 + 16 > 4096 { return 0; }

    // TLS record header: type=23, version=0x0303, length=pt_len+16
    out[0] = 23; // opaque_type = application_data (always in TLS 1.3)
    out[1] = 0x03; out[2] = 0x03;
    let enc_len = (pt_len + 16) as u16;
    out[3..5].copy_from_slice(&enc_len.to_be_bytes());

    // Copy the 5-byte record header to a local array so we can mutate `out` below.
    let mut aad = [0u8; 5];
    aad.copy_from_slice(&out[0..5]);
    let nonce = make_nonce(iv, *seq);
    *seq += 1;

    // Generate Poly1305 one-time key from counter=0 keystream
    let mut otk = [0u8; 32];
    chacha20::encrypt_buf(key, 0, &nonce, &[0u8; 32], &mut otk);

    // Encrypt: ChaCha20 counter=1
    // plaintext = payload || ct_type
    let ct_start = 5usize;
    out[ct_start..ct_start + payload.len()].copy_from_slice(payload);
    out[ct_start + payload.len()] = ct_type;
    let ct_slice = &mut out[ct_start..ct_start + pt_len];
    chacha20::encrypt(key, 1, &nonce, ct_slice);

    // Build MAC input and compute tag
    let mac_len = build_mac_input(&aad, &out[ct_start..ct_start + pt_len]);
    let tag = poly1305::mac(&otk, &MAC_BUF[..mac_len]);
    out[ct_start + pt_len..ct_start + pt_len + 16].copy_from_slice(&tag);

    5 + pt_len + 16
}

/// Open: verify and decrypt an encrypted TLS record.
/// `ct` is the raw TLS record (header + ciphertext + tag).
/// On success, writes decrypted plaintext (including trailing content-type byte) into PT_BUF.
/// Returns the slice of PT_BUF, or None on authentication failure.
unsafe fn open_record<'a>(
    key: &[u8; 32],
    iv:  &[u8; 12],
    seq: &mut u64,
    ct:  &[u8],     // full TLS record including 5-byte header
) -> Option<&'static [u8]> {
    if ct.len() < 5 + 16 { return None; }
    let aad      = &ct[..5];
    let enc_data = &ct[5..];
    let ct_body  = &enc_data[..enc_data.len() - 16];
    let tag_recv = &enc_data[enc_data.len() - 16..];

    let nonce = make_nonce(iv, *seq);
    *seq += 1;

    // Poly1305 OTK
    let mut otk = [0u8; 32];
    chacha20::encrypt_buf(key, 0, &nonce, &[0u8; 32], &mut otk);

    // Verify tag
    let mac_len = build_mac_input(aad, ct_body);
    let tag_calc = poly1305::mac(&otk, &MAC_BUF[..mac_len]);
    if tag_calc != tag_recv { return None; }  // compare as arrays

    // Decrypt
    let n = ct_body.len();
    PT_BUF[..n].copy_from_slice(ct_body);
    chacha20::encrypt(key, 1, &nonce, &mut PT_BUF[..n]);

    Some(&PT_BUF[..n])
}

// ── TLS record I/O ────────────────────────────────────────────────────────────

/// Strip trailing zeros and return content without the trailing content-type byte.
fn inner_content(pt: &[u8]) -> &[u8] {
    // The last non-zero byte is the content type; everything before it is the payload.
    let mut end = pt.len();
    while end > 0 && pt[end - 1] == 0 { end -= 1; }
    if end == 0 { return &[]; }
    &pt[..end - 1]  // strip content type byte
}

/// Read bytes from the TCP socket until we have `need` bytes in RX_BUF[offset..].
/// Returns false on timeout.
fn tcp_read_at_least(fd: usize, rx: &mut [u8], have: &mut usize, need: usize) -> bool {
    let deadline = 5_000_000u64;
    let mut loops = 0u64;
    while *have < need && loops < deadline {
        net::poll_drivers();
        let n = net::tcp_recv(fd, &mut rx[*have..]);
        *have += n;
        if n == 0 { loops += 1; }
    }
    *have >= need
}

/// Read one plain (unencrypted) TLS Handshake record and return its payload.
fn read_plain_record(fd: usize, expected_type: u8) -> Option<&'static [u8]> {
    let rx = unsafe { &mut RX_BUF };
    let mut have = 0usize;

    // Read 5-byte header
    if !tcp_read_at_least(fd, rx, &mut have, 5) { return None; }
    if rx[0] != expected_type { return None; }

    let rec_len = u16::from_be_bytes([rx[3], rx[4]]) as usize;
    if rec_len > 18000 { return None; }

    // Read record payload
    if !tcp_read_at_least(fd, rx, &mut have, 5 + rec_len) { return None; }

    // Move remaining bytes to front (in case have > 5 + rec_len)
    // For simplicity, assume the record is exactly the data we have.
    let payload = unsafe { &PT_BUF[..rec_len] };
    unsafe { PT_BUF[..rec_len].copy_from_slice(&rx[5..5 + rec_len]); }

    // Shift remaining TCP data (if any)
    let remaining = have - (5 + rec_len);
    unsafe {
        for i in 0..remaining { RX_BUF[i] = RX_BUF[5 + rec_len + i]; }
    }

    Some(unsafe { &PT_BUF[..rec_len] })
}

/// Read one encrypted TLS record, decrypt it, and return the inner plaintext.
fn decrypt_record<'a>(
    fd:  usize,
    key: &[u8; 32],
    iv:  &[u8; 12],
    seq: &mut u64,
) -> Option<&'static [u8]> {
    let rx = unsafe { &mut RX_BUF };
    let mut have = 0usize;

    if !tcp_read_at_least(fd, rx, &mut have, 5) { return None; }

    let rec_len = u16::from_be_bytes([rx[3], rx[4]]) as usize;
    if rec_len < 17 || rec_len > 16640 { return None; }

    if !tcp_read_at_least(fd, rx, &mut have, 5 + rec_len) { return None; }

    let full_record = unsafe { &RX_BUF[..5 + rec_len] };
    let pt = unsafe { open_record(key, iv, seq, full_record)? };

    // Shift remaining
    let remaining = have - (5 + rec_len);
    unsafe {
        for i in 0..remaining { RX_BUF[i] = RX_BUF[5 + rec_len + i]; }
    }

    Some(pt)
}

// ── ClientHello builder ───────────────────────────────────────────────────────

fn build_client_hello(buf: &mut [u8; 4096], random: &[u8; 32], pub_key: &[u8; 32], sni: &[u8]) -> usize {
    let mut w = Writer::new(buf);

    // TLS record header (type=0x16 Handshake, legacy version=0x0301)
    let rec_hdr_pos = w.pos;
    w.u8(0x16); w.u16be(0x0301);
    let rec_len_pos = w.pos; w.u16be(0); // fill later

    // Handshake message header
    let hs_start = w.pos;
    w.u8(1); // ClientHello
    let hs_len_pos = w.pos; w.u24be(0); // fill later
    let body_start = w.pos;

    // ClientHello body
    w.u16be(0x0303);    // legacy version TLS 1.2
    w.bytes(random);    // 32-byte random
    w.u8(0);            // legacy session ID length = 0
    w.u16be(2);         // cipher suites length
    w.u16be(0x1303);    // TLS_CHACHA20_POLY1305_SHA256
    w.u8(1); w.u8(0);  // compression methods: [null]

    // Extensions
    let ext_len_pos = w.pos; w.u16be(0);
    let ext_start = w.pos;

    // supported_versions: TLS 1.3
    w.u16be(0x002b); w.u16be(3); w.u8(2); w.u16be(0x0304);

    // server_name (SNI)
    let sni_host_len = sni.len() as u16;
    let sni_list_len = 3 + sni_host_len;
    let sni_ext_len  = 2 + sni_list_len;
    w.u16be(0x0000);
    w.u16be(sni_ext_len);
    w.u16be(sni_list_len);
    w.u8(0);  // name_type: host_name
    w.u16be(sni_host_len);
    w.bytes(sni);

    // key_share: x25519
    w.u16be(0x0033); w.u16be(38);
    w.u16be(36);        // client_shares length
    w.u16be(0x001d);    // group: x25519
    w.u16be(32);        // key_exchange length
    w.bytes(pub_key);

    // supported_groups
    w.u16be(0x000a); w.u16be(4);
    w.u16be(2); w.u16be(0x001d); // x25519

    // signature_algorithms
    w.u16be(0x000d); w.u16be(8);
    w.u16be(6);
    w.u16be(0x0403); // ecdsa_secp256r1_sha256
    w.u16be(0x0804); // rsa_pss_rsae_sha256
    w.u16be(0x0805); // rsa_pss_pss_sha256

    // Patch extension length
    let ext_len = (w.pos - ext_start) as u16;
    w.patch16(ext_len_pos, ext_len);

    // Patch Handshake message length (3 bytes)
    let hs_body_len = (w.pos - body_start) as u32;
    w.patch24(hs_len_pos, hs_body_len);

    // Patch TLS record length
    let rec_payload_len = (w.pos - hs_start) as u16;
    w.patch16(rec_len_pos, rec_payload_len);

    w.pos
}

// ── ServerHello parser ────────────────────────────────────────────────────────

/// Parse a ServerHello handshake message and return the server's X25519 public key.
fn parse_server_hello(data: &[u8]) -> Option<[u8; 32]> {
    if data.len() < 4 || data[0] != 2 { return None; } // not ServerHello
    let body_len = u24_be(&data[1..]) as usize;
    if data.len() < 4 + body_len { return None; }
    let body = &data[4..4 + body_len];

    // Skip: legacy_version(2) + random(32) = 34 bytes
    if body.len() < 35 { return None; }
    let sid_len = body[34] as usize;
    let pos = 35 + sid_len; // after session_id
    if body.len() < pos + 5 { return None; }
    // cipher_suite(2) + compression(1) + ext_len(2) = 5 bytes
    let ext_len = u16_be(&body[pos + 3..]) as usize;
    let exts = &body[pos + 5..pos + 5 + ext_len.min(body.len() - pos - 5)];

    let mut ep = 0usize;
    while ep + 4 <= exts.len() {
        let ext_type = u16_be(&exts[ep..]);
        let el       = u16_be(&exts[ep + 2..]) as usize;
        ep += 4;
        if ep + el > exts.len() { break; }

        if ext_type == 0x0033 {  // key_share
            let ks = &exts[ep..ep + el];
            // ServerHello key_share: NamedGroup(2) + key_len(2) + key(key_len)
            if ks.len() >= 36 && u16_be(ks) == 0x001d {  // x25519
                let kl = u16_be(&ks[2..]) as usize;
                if kl == 32 && ks.len() >= 4 + kl {
                    let mut k = [0u8; 32];
                    k.copy_from_slice(&ks[4..36]);
                    return Some(k);
                }
            }
        }
        ep += el;
    }
    None
}

// ── Transcript hash ───────────────────────────────────────────────────────────

fn transcript_add(msg: &[u8]) {
    let buf = unsafe { &mut TR_BUF };
    let len = unsafe { TR_LEN };
    let n = msg.len().min(8192 - len);
    buf[len..len + n].copy_from_slice(&msg[..n]);
    unsafe { TR_LEN += n; }
}

fn transcript_hash() -> [u8; 32] {
    sha256::hash(unsafe { &TR_BUF[..TR_LEN] })
}

// ── Pseudo-random bytes (seeded from RDTSC) ───────────────────────────────────

fn pseudo_random32() -> [u8; 32] {
    let mut r = [0u8; 32];
    for i in 0..4usize {
        let tsc: u64;
        unsafe { core::arch::asm!("rdtsc; shl rdx, 32; or rax, rdx", out("rax") tsc, out("rdx") _, options(nostack, nomem)); }
        let v = tsc.wrapping_mul(0x6c62272e07bb0142u64).wrapping_add(i as u64);
        r[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes());
    }
    r
}

// ── Byte helpers ──────────────────────────────────────────────────────────────

fn u16_be(b: &[u8]) -> u16 { u16::from_be_bytes([b[0], b[1]]) }
fn u24_be(b: &[u8]) -> u32 { u32::from_be_bytes([0, b[0], b[1], b[2]]) }

// ── Writer helper ─────────────────────────────────────────────────────────────

struct Writer<'a> { buf: &'a mut [u8; 4096], pos: usize }

impl<'a> Writer<'a> {
    fn new(buf: &'a mut [u8; 4096]) -> Self { Self { buf, pos: 0 } }
    fn u8(&mut self, v: u8)  { if self.pos < 4096 { self.buf[self.pos] = v; self.pos += 1; } }
    fn u16be(&mut self, v: u16)  { self.u8((v >> 8) as u8); self.u8(v as u8); }
    fn u24be(&mut self, v: u32)  { self.u8((v >> 16) as u8); self.u8((v >> 8) as u8); self.u8(v as u8); }
    fn bytes(&mut self, d: &[u8]) { for &b in d { self.u8(b); } }
    fn patch16(&mut self, at: usize, v: u16) {
        if at + 1 < 4096 { self.buf[at] = (v >> 8) as u8; self.buf[at + 1] = v as u8; }
    }
    fn patch24(&mut self, at: usize, v: u32) {
        if at + 2 < 4096 {
            self.buf[at]     = (v >> 16) as u8;
            self.buf[at + 1] = (v >> 8)  as u8;
            self.buf[at + 2] =  v        as u8;
        }
    }
}
