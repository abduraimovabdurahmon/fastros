//! SSH-2 server (RFC 4253 / RFC 4254).
//!
//! Single-connection SSH server on TCP port 22.
//! Supports:
//!   - Cipher:      aes128-cbc
//!   - MAC:         hmac-sha2-256
//!   - KEX:         curve25519-sha256
//!   - Host key:    ssh-ed25519
//!   - Auth method: password
//!   - Channel:     session (shell)
//!
//! State machine:
//!   Idle → VersionExchange → KexInit → KexDh → NewKeys
//!        → ServiceRequest → UserAuth → Authenticated
//!        → ChannelOpen → ShellActive → Closed

use super::{
    crypto::{self, sha256, hmac, aes::{self, Aes128Ctr}, curve25519, ed25519},
    transport::{self, *, SSH_MSG_CHANNEL_WINDOW_ADJUST},
};
use crate::kernel::net::{socket, tcp::TcpState};
use crate::kernel::users;

// ── Server state machine ──────────────────────────────────────────────────────

#[derive(Copy, Clone, PartialEq)]
pub enum SshState {
    Idle,
    VersionSent,
    KexInit,
    KexDh,
    NewKeys,
    ServiceRequest,
    UserAuth,
    Authenticated,
    ChannelOpen,
    ShellActive,
    Closed,
}

// ── Per-connection session ────────────────────────────────────────────────────

const BUF_SIZE: usize = 8192;
pub const MAX_SESSIONS: usize = 4;

// Per-session input ring buffer size
const SESSION_INPUT_SIZE: usize = 256;

pub struct SshSession {
    pub state:    SshState,
    pub tcp_fd:   usize,

    // TX buffer
    tx_buf: [u8; BUF_SIZE],
    tx_len: usize,

    // RX accumulation buffer (undecrypted frames)
    rx_buf: [u8; BUF_SIZE],
    rx_len: usize,

    // Crypto state
    encrypted:    bool,
    enc_cs:       Option<Aes128Ctr>,  // client → server decryption
    enc_sc:       Option<Aes128Ctr>,  // server → client encryption
    mac_key_cs:   [u8; 32],
    mac_key_sc:   [u8; 32],

    // Sequence numbers (for MAC)
    seq_send:     u32,
    seq_recv:     u32,

    // Key exchange material
    server_privkey: [u8; 32],
    session_id:     [u8; 32],

    // Exchange hash input material (RFC 4253 §8)
    client_version:     [u8; 256],
    client_version_len: usize,
    client_kexinit:     [u8; 4096],  // Large enough for any client KEXINIT
    client_kexinit_len: usize,
    server_kexinit:     [u8; 512],
    server_kexinit_len: usize,

    // Authenticated user
    pub username: [u8; 32],
    pub uname_len: usize,

    // Channel
    pub channel_id_client: u32,
    pub channel_id_server: u32,

    // Terminal size from pty-req
    pub term_cols: u32,
    pub term_rows: u32,

    // Per-session input ring buffer (shell reads from here)
    input_buf:  [u8; SESSION_INPUT_SIZE],
    input_head: usize,
    input_tail: usize,
}

impl SshSession {
    pub fn new(tcp_fd: usize) -> Self {
        let (privkey, _pubkey) = ed25519::key_pair_from_seed(&ed25519::HOST_SEED);
        let mut server_privkey = [0u8; 32];
        server_privkey.copy_from_slice(&privkey[..32]);

        Self {
            state: SshState::Idle,
            tcp_fd,
            tx_buf: [0; BUF_SIZE], tx_len: 0,
            rx_buf: [0; BUF_SIZE], rx_len: 0,
            encrypted: false,
            enc_cs: None, enc_sc: None,
            mac_key_cs: [0; 32], mac_key_sc: [0; 32],
            seq_send: 0, seq_recv: 0,
            server_privkey,
            session_id: [0; 32],
            client_version: [0; 256], client_version_len: 0,
            client_kexinit: [0; 4096], client_kexinit_len: 0,
            server_kexinit: [0; 512],  server_kexinit_len: 0,
            username: [0; 32], uname_len: 0,
            channel_id_client: 0, channel_id_server: 0,
            term_cols: 80, term_rows: 24,
            input_buf: [0; SESSION_INPUT_SIZE], input_head: 0, input_tail: 0,
        }
    }

    // ── Frame output ──────────────────────────────────────────────────────────

    /// Queue a raw payload as an SSH packet (encrypting if keys are active).
    pub fn send_packet(&mut self, payload: &[u8]) {
        if self.tx_len + BUF_SIZE / 2 > BUF_SIZE { return; } // overflow guard

        let mut pkt = [0u8; 1600];
        let pkt_len = build_packet(&mut pkt, payload);

        if self.encrypted {
            // Compute MAC over (seq_be || cleartext_packet)
            let mut mac_input = [0u8; 1604];
            mac_input[0..4].copy_from_slice(&self.seq_send.to_be_bytes());
            mac_input[4..4+pkt_len].copy_from_slice(&pkt[..pkt_len]);
            let tag = hmac::mac(&self.mac_key_sc, &mac_input[..4+pkt_len]);

            // Encrypt packet (but not MAC)
            if let Some(ref mut enc) = self.enc_sc {
                enc.process(&mut pkt[..pkt_len]);
            }

            // Copy encrypted + MAC into TX buffer
            let total = pkt_len + 32;
            if self.tx_len + total <= BUF_SIZE {
                self.tx_buf[self.tx_len..self.tx_len+pkt_len].copy_from_slice(&pkt[..pkt_len]);
                self.tx_buf[self.tx_len+pkt_len..self.tx_len+total].copy_from_slice(&tag);
                self.tx_len += total;
            }
        } else {
            if self.tx_len + pkt_len <= BUF_SIZE {
                self.tx_buf[self.tx_len..self.tx_len+pkt_len].copy_from_slice(&pkt[..pkt_len]);
                self.tx_len += pkt_len;
            }
        }
        self.seq_send = self.seq_send.wrapping_add(1);
    }

    /// Flush TX buffer to TCP socket.
    pub fn flush(&mut self) {
        if self.tx_len == 0 { return; }
        // Write to TCP RX buffer (we push into the peer's socket)
        // In our TCP impl, the socket is a data store; the actual send happens
        // when the TCP stack processes outgoing data.
        // For simplicity, we write directly using the kernel TCP send helper.
        let _ = tcp_write(self.tcp_fd, &self.tx_buf[..self.tx_len]);
        self.tx_len = 0;
    }

    // ── Protocol handlers ─────────────────────────────────────────────────────

    /// Send the server SSH version banner.
    pub fn send_version(&mut self) {
        let banner = b"SSH-2.0-FastROS_0.1\r\n";
        let _ = tcp_write(self.tcp_fd, banner);
        self.state = SshState::VersionSent;
    }

    /// Send our SSH_MSG_KEXINIT (called proactively after version exchange).
    pub fn handle_kexinit(&mut self) {
        crate::drivers::char::serial::write(b"  ssh: sending our KEXINIT\n");
        let mut payload = [0u8; 512];
        let len = build_kexinit(&mut payload);
        // Save our KEXINIT payload for exchange hash
        let n = len.min(512);
        self.server_kexinit[..n].copy_from_slice(&payload[..n]);
        self.server_kexinit_len = n;
        self.send_packet(&payload[..len]);
        self.flush();
        self.state = SshState::KexInit;  // Wait for client's KEXINIT
    }

    /// Process SSH_MSG_KEX_ECDH_INIT — client sends its Curve25519 public key.
    /// We generate our ephemeral key pair, compute shared secret, send ECDH reply.
    pub fn handle_kex_ecdh_init(&mut self, payload: &[u8]) {
        if payload.len() < 5 { return; }

        // Parse client's ephemeral public key (32 bytes)
        let (client_pubkey_bytes, _) = get_string(payload, 1);
        if client_pubkey_bytes.len() != 32 { return; }
        let mut client_pub = [0u8; 32];
        client_pub.copy_from_slice(client_pubkey_bytes);

        // Generate server ephemeral key pair (deterministic from counter)
        static mut KEX_COUNTER: u8 = 0;
        let mut server_eph_priv = [0u8; 32];
        unsafe {
            server_eph_priv[0] = 0xAB ^ KEX_COUNTER;
            KEX_COUNTER = KEX_COUNTER.wrapping_add(1);
        }
        for i in 1..32 { server_eph_priv[i] = (i as u8).wrapping_mul(0x7) ^ 0x5A; }
        server_eph_priv[0]  &= 248;
        server_eph_priv[31] &= 127;
        server_eph_priv[31] |= 64;

        let server_eph_pub = curve25519::public_key(&server_eph_priv);
        let shared_secret  = curve25519::shared_secret(&server_eph_priv, &client_pub);

        // RFC 8731 §3: the X25519 result is treated as a big-endian unsigned
        // integer (same convention as OpenSSH/PuTTY) and encoded as SSH mpint.
        // The 32 bytes from X25519 are used AS-IS (no reversal); byte 0 is
        // the most significant byte for mpint padding purposes.
        let mut k_mpint = [0u8; 37];
        let needs_pad = shared_secret[0] & 0x80 != 0;
        let k_data_len = 32 + if needs_pad { 1 } else { 0 };
        k_mpint[..4].copy_from_slice(&(k_data_len as u32).to_be_bytes());
        let k_data_off = 4 + if needs_pad { k_mpint[4] = 0; 1 } else { 0 };
        k_mpint[k_data_off..k_data_off + 32].copy_from_slice(&shared_secret);
        let k_mpint_len = 4 + k_data_len;

        // Compute host key (Ed25519 public key)
        let (_host_priv, host_pub) = ed25519::key_pair_from_seed(&ed25519::HOST_SEED);

        // Build host key blob: string("ssh-ed25519") || string(pubkey)
        let mut host_key_blob = [0u8; 64];
        let mut hkb_off = 0usize;
        hkb_off += put_string(&mut host_key_blob, hkb_off, b"ssh-ed25519");
        hkb_off += put_string(&mut host_key_blob, hkb_off, &host_pub);

        // ── RFC 4253 §8 / RFC 8731 exchange hash ──────────────────────────────
        // H = SHA-256(string(V_C) || string(V_S) || string(I_C) || string(I_S) ||
        //             string(K_S) || string(Q_C) || string(Q_S) || mpint(K))
        // Use static to avoid large stack allocation (OpenSSH KEXINIT ~1500 bytes)
        static mut H_BUF: [u8; 4096] = [0u8; 4096];
        let mut h_off = 0usize;
        unsafe {
            h_off += put_string(&mut H_BUF, h_off, &self.client_version[..self.client_version_len]);
            h_off += put_string(&mut H_BUF, h_off, b"SSH-2.0-FastROS_0.1");
            h_off += put_string(&mut H_BUF, h_off, &self.client_kexinit[..self.client_kexinit_len]);
            h_off += put_string(&mut H_BUF, h_off, &self.server_kexinit[..self.server_kexinit_len]);
            h_off += put_string(&mut H_BUF, h_off, &host_key_blob[..hkb_off]);
            h_off += put_string(&mut H_BUF, h_off, &client_pub);
            h_off += put_string(&mut H_BUF, h_off, &server_eph_pub);
            H_BUF[h_off..h_off + k_mpint_len].copy_from_slice(&k_mpint[..k_mpint_len]);
            h_off += k_mpint_len;
        }
        if h_off == 0 || h_off > 4096 {
            crate::drivers::char::serial::write(b"  ssh: exchange hash buf overflow!\n");
            return;
        }
        crate::drivers::char::serial::write(b"  ssh: computing exchange hash\n");

        let exchange_hash = unsafe { sha256::hash(&H_BUF[..h_off]) };

        if self.session_id == [0u8; 32] {
            self.session_id = exchange_hash;
        }

        // Sign H with host key (Ed25519)
        let mut host_priv_full = [0u8; 64];
        host_priv_full[..32].copy_from_slice(&ed25519::HOST_SEED);
        host_priv_full[32..].copy_from_slice(&host_pub);
        let signature = ed25519::sign(&host_priv_full, &exchange_hash);

        // Build SSH_MSG_KEX_ECDH_REPLY
        let mut reply = [0u8; 512];
        let mut off = 0;
        reply[off] = SSH_MSG_KEX_ECDH_REPLY; off += 1;
        off += put_string(&mut reply, off, &host_key_blob[..hkb_off]);
        off += put_string(&mut reply, off, &server_eph_pub);

        // Signature blob (needs 4+11 + 4+64 = 83 bytes → use 96)
        let mut sig_blob = [0u8; 96];
        let mut sb_off = 0;
        sb_off += put_string(&mut sig_blob, sb_off, b"ssh-ed25519");
        sb_off += put_string(&mut sig_blob, sb_off, &signature);
        off += put_string(&mut reply, off, &sig_blob[..sb_off]);

        self.send_packet(&reply[..off]);
        self.send_packet(&[SSH_MSG_NEWKEYS]);
        self.flush();

        // Derive session keys
        let keys = SessionKeys::derive(&k_mpint[..k_mpint_len], &exchange_hash, &self.session_id);
        self.enc_cs = Some(Aes128Ctr::new(&keys.enc_key_cs, &keys.iv_cs));
        self.enc_sc = Some(Aes128Ctr::new(&keys.enc_key_sc, &keys.iv_sc));
        self.mac_key_cs.copy_from_slice(&keys.mac_key_cs);
        self.mac_key_sc.copy_from_slice(&keys.mac_key_sc);
        // encrypted stays false until client's NEWKEYS received (RFC 4253 §7.3)
        self.state = SshState::NewKeys;
        crate::drivers::char::serial::write(b"  ssh: kex done, keys derived (enc pending NEWKEYS)\n");
    }

    /// Handle SSH_MSG_NEWKEYS from client — NOW activate encryption both directions.
    pub fn handle_newkeys(&mut self) {
        self.encrypted = true;
        self.state = SshState::ServiceRequest;
        crate::drivers::char::serial::write(b"  ssh: NEWKEYS received, encryption ON\n");
    }

    /// Handle SSH_MSG_SERVICE_REQUEST ("ssh-userauth").
    pub fn handle_service_request(&mut self, payload: &[u8]) {
        let (service, _) = get_string(payload, 1);
        if service == b"ssh-userauth" {
            let mut ack = [0u8; 32];
            ack[0] = SSH_MSG_SERVICE_ACCEPT;
            let n = 1 + put_string(&mut ack, 1, b"ssh-userauth");
            self.send_packet(&ack[..n]);
            self.flush();
            self.state = SshState::UserAuth;
        } else {
            self.send_disconnect(SSH_DISCONNECT_BY_APPLICATION, b"unknown service");
        }
    }

    /// Handle SSH_MSG_USERAUTH_REQUEST.
    /// Supports "password" method matching kernel user database.
    pub fn handle_userauth(&mut self, payload: &[u8]) {
        let mut off = 1;
        let (username, next) = get_string(payload, off); off = next;
        let (_service, next) = get_string(payload, off); off = next;
        let (method,   next) = get_string(payload, off); off = next;

        let ulen = username.len().min(32);
        self.username[..ulen].copy_from_slice(&username[..ulen]);
        self.uname_len = ulen;

        let authed = if method == b"password" {
            off += 1; // boolean "change"
            let (password, _) = get_string(payload, off);
            users::verify(&self.username[..self.uname_len], password)
        } else {
            false
        };

        if authed {
            crate::drivers::char::serial::write(b"  ssh: userauth SUCCESS\n");
            self.send_packet(&[SSH_MSG_USERAUTH_SUCCESS]);
            self.flush();
            self.state = SshState::Authenticated;
        } else {
            crate::drivers::char::serial::write(b"  ssh: userauth FAILED\n");
            let mut fail = [0u8; 64];
            fail[0] = SSH_MSG_USERAUTH_FAILURE;
            let n = 1 + put_string(&mut fail, 1, b"password") + 1; // partial = false
            self.send_packet(&fail[..n]);
            self.flush();
        }
    }

    /// Handle SSH_MSG_CHANNEL_OPEN.
    pub fn handle_channel_open(&mut self, payload: &[u8]) {
        let (chan_type, next)  = get_string(payload, 1);
        let sender_chan        = get_u32(payload, next);
        let initial_window    = get_u32(payload, next + 4);
        let max_packet        = get_u32(payload, next + 8);

        self.channel_id_client = sender_chan;
        self.channel_id_server = 0;

        if chan_type == b"session" {
            let mut confirm = [0u8; 32];
            confirm[0] = SSH_MSG_CHANNEL_OPEN_CONFIRM;
            put_u32(&mut confirm, 1, sender_chan);
            put_u32(&mut confirm, 5, self.channel_id_server);
            put_u32(&mut confirm, 9,  0x00100000); // initial window
            put_u32(&mut confirm, 13, 0x00004000); // max packet
            self.send_packet(&confirm[..17]);
            self.flush();
            self.state = SshState::ChannelOpen;
        } else {
            let mut fail = [0u8; 20];
            fail[0] = SSH_MSG_CHANNEL_OPEN_FAILURE;
            put_u32(&mut fail, 1, sender_chan);
            put_u32(&mut fail, 5, 3); // SSH_OPEN_UNKNOWN_CHANNEL_TYPE
            self.send_packet(&fail[..9]);
            self.flush();
        }
        let _ = (initial_window, max_packet);
    }

    /// Handle SSH_MSG_CHANNEL_REQUEST ("shell", "pty-req", etc.).
    pub fn handle_channel_request(&mut self, payload: &[u8]) {
        let _channel = get_u32(payload, 1);
        let (req_type, next) = get_string(payload, 5);
        if next >= payload.len() { return; }
        let want_reply = payload[next] != 0;

        let success = match req_type {
            b"shell" => {
                self.state = SshState::ShellActive;
                // Greeting is sent by the shell loop in src/shell/mod.rs
                true
            }
            b"exec" => {
                // Parse the command string (next byte after want_reply)
                let (cmd, _) = get_string(payload, next + 1);
                self.state = SshState::ShellActive;
                // Echo the command back and send EOF
                self.send_data(b"exec: ");
                self.send_data(cmd);
                self.send_data(b"\r\n");
                // Send exit-status(0), EOF, CLOSE
                // Format: type(1) + chan(4) + str(4+11) + want_reply(1) + code(4) = 25 bytes
                let mut es = [0u8; 32];
                es[0] = SSH_MSG_CHANNEL_REQUEST;
                put_u32(&mut es, 1, self.channel_id_client);
                let n = 5 + put_string(&mut es, 5, b"exit-status");
                es[n] = 0; // want_reply = false
                put_u32(&mut es, n + 1, 0); // exit code 0
                self.send_packet(&es[..n + 5]);
                let mut eof = [0u8; 8];
                eof[0] = SSH_MSG_CHANNEL_EOF;
                put_u32(&mut eof, 1, self.channel_id_client);
                self.send_packet(&eof[..5]);
                let mut cls = [0u8; 8];
                cls[0] = SSH_MSG_CHANNEL_CLOSE;
                put_u32(&mut cls, 1, self.channel_id_client);
                self.send_packet(&cls[..5]);
                self.flush();
                self.state = SshState::Closed;
                true
            }
            b"pty-req" => {
                // Parse: string(term) uint32(cols) uint32(rows) uint32(px_w) uint32(px_h) string(modes)
                let (_term, after_term) = get_string(payload, next + 1);
                if after_term + 8 <= payload.len() {
                    self.term_cols = get_u32(payload, after_term);
                    self.term_rows = get_u32(payload, after_term + 4);
                }
                true
            }
            b"env"     => true,   // accept environment variables silently
            _          => false,
        };

        if want_reply {
            let mut resp = [0u8; 8];
            resp[0] = if success { SSH_MSG_CHANNEL_SUCCESS } else { SSH_MSG_CHANNEL_FAILURE };
            put_u32(&mut resp, 1, self.channel_id_client);
            self.send_packet(&resp[..5]);
            self.flush();
        }
    }

    /// Handle SSH_MSG_CHANNEL_DATA — data from client.
    /// Returns the payload (shell input).
    pub fn handle_channel_data<'a>(&mut self, payload: &'a [u8]) -> &'a [u8] {
        let _channel = get_u32(payload, 1);
        let (data, _) = get_string(payload, 5);
        data
    }

    /// Send data to client on the active channel.
    pub fn send_data(&mut self, data: &[u8]) {
        let mut buf = [0u8; 1600];
        buf[0] = SSH_MSG_CHANNEL_DATA;
        put_u32(&mut buf, 1, self.channel_id_client);
        let n = 5 + put_string(&mut buf, 5, data);
        self.send_packet(&buf[..n]);
        self.flush();
    }

    /// Send SSH_MSG_DISCONNECT and mark session closed.
    pub fn send_disconnect(&mut self, reason: u32, description: &[u8]) {
        let mut buf = [0u8; 256];
        buf[0] = SSH_MSG_DISCONNECT;
        put_u32(&mut buf, 1, reason);
        let n = 5 + put_string(&mut buf, 5, description);
        self.send_packet(&buf[..n]);
        self.flush();
        self.state = SshState::Closed;
    }

    // ── Inbound packet processing ─────────────────────────────────────────────

    /// Feed received bytes into the session. Call this when TCP data arrives.
    /// Returns a slice of shell input data if in ShellActive state, else empty.
    pub fn process_received<'a>(&'a mut self, data: &[u8]) -> ShellInput<'a> {
        // Accumulate into RX buffer
        let take = data.len().min(BUF_SIZE - self.rx_len);
        self.rx_buf[self.rx_len..self.rx_len + take].copy_from_slice(&data[..take]);
        self.rx_len += take;

        // Handle version exchange (text line before binary protocol).
        // RFC 4253 §4.2: server sends its version first (done in poll()),
        // then waits for the client's version string (a text line ending with \n).
        if self.state == SshState::Idle || self.state == SshState::VersionSent {
            if let Some(pos) = find_byte(&self.rx_buf[..self.rx_len], b'\n') {
                // Save client version string (strip \r\n per RFC 4253)
                let vend = if pos > 0 && self.rx_buf[pos-1] == b'\r' { pos-1 } else { pos };
                let vlen = vend.min(256);
                self.client_version[..vlen].copy_from_slice(&self.rx_buf[..vlen]);
                self.client_version_len = vlen;
                // Consume the version line and send our KEXINIT
                let consumed = pos + 1;
                self.rx_buf.copy_within(consumed..self.rx_len, 0);
                self.rx_len -= consumed;
                self.handle_kexinit();
            }
            return ShellInput::None;
        }

        // Binary packet processing
        loop {
            if self.rx_len < 5 { break; }

            let mut payload_copy = [0u8; 4096];
            let plen;
            let total_consumed;

            if self.encrypted {
                // Need at least one AES block to read packet_length
                if self.rx_len < 16 { break; }

                // Peek-decrypt first block to read packet_length without consuming IV state
                let peek_dec = match &self.enc_cs {
                    Some(c) => {
                        let mut tmp = c.clone();
                        let mut blk = [0u8; 16];
                        blk.copy_from_slice(&self.rx_buf[..16]);
                        tmp.process(&mut blk);
                        blk
                    }
                    None => break,
                };
                let packet_length = get_u32(&peek_dec, 0) as usize;

                // Sanity: valid SSH packet lengths. Total must align to 8 (CTR mode).
                if packet_length == 0 || packet_length > 32768
                    || (4 + packet_length) % 8 != 0
                {
                    // Discard garbage (mismatched keys / wrong IV)
                    crate::drivers::char::serial::write(b"  ssh: enc packet garbage, discarding\n");
                    self.rx_len = 0;
                    break;
                }

                let total_enc = 4 + packet_length;
                let mac_size  = 32usize; // HMAC-SHA256
                if self.rx_len < total_enc + mac_size { break; } // wait for full packet

                // Decrypt all blocks in-place
                if let Some(ref mut dec) = self.enc_cs {
                    dec.process(&mut self.rx_buf[..total_enc]);
                }

                // Parse the now-decrypted packet
                let (payload, consumed) = parse_packet(&self.rx_buf[..total_enc]);
                if consumed == 0 {
                    self.rx_len = 0;
                    break;
                }
                plen = payload.len().min(4096);
                payload_copy[..plen].copy_from_slice(&payload[..plen]);
                total_consumed = (total_enc + mac_size).min(self.rx_len);
            } else {
                let (payload, consumed) = parse_packet(&self.rx_buf[..self.rx_len]);
                if consumed == 0 { break; }
                plen = payload.len().min(4096);
                payload_copy[..plen].copy_from_slice(&payload[..plen]);
                total_consumed = consumed;
            }

            self.rx_buf.copy_within(total_consumed..self.rx_len, 0);
            self.rx_len -= total_consumed;
            self.seq_recv = self.seq_recv.wrapping_add(1);

            if plen == 0 { continue; }
            let msg_type = payload_copy[0];

            match (self.state, msg_type) {
                (SshState::KexInit, SSH_MSG_KEXINIT) |
                (SshState::KexDh,   SSH_MSG_KEXINIT) => {
                    // Save client's KEXINIT for RFC 4253 §8 exchange hash
                    let n = plen.min(4096);
                    self.client_kexinit[..n].copy_from_slice(&payload_copy[..n]);
                    self.client_kexinit_len = n;
                    if self.state == SshState::KexInit {
                        self.state = SshState::KexDh;
                        crate::drivers::char::serial::write(b"  ssh: client KEXINIT saved, waiting for ECDH_INIT\n");
                    }
                }
                (SshState::KexDh,      SSH_MSG_KEX_ECDH_INIT) => {
                    let mut p = [0u8; 64];
                    p[..plen.min(64)].copy_from_slice(&payload_copy[..plen.min(64)]);
                    self.handle_kex_ecdh_init(&p[..plen.min(64)]);
                }
                (SshState::NewKeys,    SSH_MSG_NEWKEYS) => {
                    self.handle_newkeys();
                }
                (SshState::ServiceRequest, SSH_MSG_SERVICE_REQUEST) => {
                    self.handle_service_request(&payload_copy[..plen]);
                }
                (SshState::UserAuth, SSH_MSG_USERAUTH_REQUEST) => {
                    self.handle_userauth(&payload_copy[..plen]);
                }
                (SshState::Authenticated, SSH_MSG_CHANNEL_OPEN) |
                (SshState::ChannelOpen,   SSH_MSG_CHANNEL_OPEN) => {
                    self.handle_channel_open(&payload_copy[..plen]);
                }
                (SshState::ChannelOpen,  SSH_MSG_CHANNEL_REQUEST) |
                (SshState::Authenticated, SSH_MSG_CHANNEL_REQUEST) => {
                    self.handle_channel_request(&payload_copy[..plen]);
                }
                (SshState::ShellActive, SSH_MSG_CHANNEL_DATA) => {
                    let (data, _) = get_string(&payload_copy[..plen], 5);
                    for &b in data {
                        self.push_input(b);
                    }
                    // still return Data for legacy poll() callers
                    static mut SHELL_INPUT: [u8; 256] = [0; 256];
                    let n = data.len().min(256);
                    unsafe {
                        SHELL_INPUT[..n].copy_from_slice(&data[..n]);
                        return ShellInput::Data(&SHELL_INPUT[..n]);
                    }
                }
                (SshState::ShellActive, SSH_MSG_CHANNEL_EOF) |
                (SshState::ShellActive, SSH_MSG_CHANNEL_CLOSE) => {
                    self.send_disconnect(SSH_DISCONNECT_BY_APPLICATION, b"client closed");
                }
                // window-adjust: silently accept in any state (flow control)
                (_, SSH_MSG_CHANNEL_WINDOW_ADJUST) => {}
                // channel-request in ShellActive (window-change, signal, etc.)
                (SshState::ShellActive, SSH_MSG_CHANNEL_REQUEST) => {
                    let (req_type, next) = get_string(&payload_copy[..plen], 5);
                    if req_type == b"window-change" && next + 9 <= plen {
                        // uint32(cols) uint32(rows) uint32(px_w) uint32(px_h) — no want_reply
                        self.term_cols = get_u32(&payload_copy, next + 1);
                        self.term_rows = get_u32(&payload_copy, next + 5);
                    } else if next < plen {
                        let want_reply = payload_copy[next] != 0;
                        if want_reply {
                            let mut resp = [0u8; 8];
                            resp[0] = SSH_MSG_CHANNEL_SUCCESS;
                            put_u32(&mut resp, 1, self.channel_id_client);
                            self.send_packet(&resp[..5]);
                            self.flush();
                        }
                    }
                    let _ = req_type;
                }
                (_, SSH_MSG_DISCONNECT) => { self.state = SshState::Closed; }
                (_, SSH_MSG_IGNORE)     => {}
                _ => {
                    // Unimplemented: send SSH_MSG_UNIMPLEMENTED
                    let mut pkt = [0u8; 8];
                    pkt[0] = SSH_MSG_UNIMPLEMENTED;
                    put_u32(&mut pkt, 1, self.seq_recv.wrapping_sub(1));
                    self.send_packet(&pkt[..5]);
                    self.flush();
                }
            }
        }
        ShellInput::None
    }

    pub fn push_input(&mut self, b: u8) {
        let next = (self.input_tail + 1) % SESSION_INPUT_SIZE;
        if next != self.input_head {
            self.input_buf[self.input_tail] = b;
            self.input_tail = next;
        }
    }

    pub fn pop_input(&mut self) -> Option<u8> {
        if self.input_head == self.input_tail { return None; }
        let b = self.input_buf[self.input_head];
        self.input_head = (self.input_head + 1) % SESSION_INPUT_SIZE;
        Some(b)
    }

    pub fn has_input(&self) -> bool {
        self.input_head != self.input_tail
    }
}

pub enum ShellInput<'a> {
    None,
    Data(&'a [u8]),
}

// ── TCP write helper ──────────────────────────────────────────────────────────

fn tcp_write(fd: usize, data: &[u8]) -> usize {
    if crate::kernel::net::tcp_send(fd, data) { data.len() } else { 0 }
}

fn find_byte(haystack: &[u8], needle: u8) -> Option<usize> {
    haystack.iter().position(|&b| b == needle)
}

// ── Global server state (N concurrent sessions) ───────────────────────────────

static mut SESSIONS: [Option<SshSession>; MAX_SESSIONS] = [const { None }; MAX_SESSIONS];
static mut LISTEN_FD: usize = usize::MAX;

/// Initialize the SSH server: open TCP listen socket on port 22.
pub fn init() {
    let fd = match socket::socket(socket::AF_INET, socket::SOCK_STREAM, socket::IPPROTO_TCP) {
        Some(f) => f,
        None    => return,
    };
    if let Some(s) = socket::get_mut(fd) {
        s.local_ip   = crate::kernel::net::primary_ip();
        s.local_port = 22;
        s.tcp_state  = TcpState::Listen;
    }
    unsafe { LISTEN_FD = fd; }
}

/// Poll all SSH sessions and accept new connections. Call from the main loop.
pub fn poll() -> Option<&'static [u8]> {
    unsafe {
        // 1. Clean up dead sessions
        for slot in SESSIONS.iter_mut() {
            if let Some(ref s) = *slot {
                let tcp_alive = socket::get(s.tcp_fd)
                    .map(|t| matches!(t.tcp_state, TcpState::Established | TcpState::SynRcvd))
                    .unwrap_or(false);
                if s.state == SshState::Closed || !tcp_alive {
                    crate::drivers::char::serial::write(b"  ssh: session closed\n");
                    *slot = None;
                }
            }
        }

        // 2. Accept new connections into free slots (up to MAX_SESSIONS).
        //    Build a list of already-tracked fds so find_tcp_established_not_in
        //    skips them — otherwise it always returns the first established fd
        //    (the existing session) and new connections are never accepted.
        let free_slots = SESSIONS.iter().filter(|s| s.is_none()).count();
        if free_slots > 0 {
            let mut tracked = [usize::MAX; MAX_SESSIONS];
            for (i, slot) in SESSIONS.iter().enumerate() {
                if let Some(ref s) = *slot { tracked[i] = s.tcp_fd; }
            }
            if let Some(fd) = socket::find_tcp_established_not_in(22, &tracked) {
                if let Some(slot) = SESSIONS.iter_mut().find(|s| s.is_none()) {
                    crate::drivers::char::serial::write(b"  ssh: new connection accepted\n");
                    let mut session = SshSession::new(fd);
                    session.send_version();
                    crate::drivers::char::serial::write(b"  ssh: version banner sent\n");
                    *slot = Some(session);
                }
            }
        }

        // 3. Drive all active sessions
        for slot in SESSIONS.iter_mut() {
            if let Some(ref mut session) = *slot {
                if let Some(s) = socket::get_mut(session.tcp_fd) {
                    if s.rx_available() > 0 {
                        let mut buf = [0u8; 1024];
                        let n = s.rx_pop(&mut buf);
                        if n > 0 {
                            session.process_received(&buf[..n]);
                        }
                    }
                }
            }
        }
    }
    None
}

/// Send data to a specific SSH session by index.
pub fn send_to_session(idx: usize, data: &[u8]) {
    unsafe {
        if idx < MAX_SESSIONS {
            if let Some(ref mut s) = SESSIONS[idx] {
                if s.state == SshState::ShellActive {
                    s.send_data(data);
                }
            }
        }
    }
}

/// Legacy: send to the first active shell session.
pub fn send_to_client(data: &[u8]) {
    unsafe {
        for slot in SESSIONS.iter_mut() {
            if let Some(ref mut s) = *slot {
                if s.state == SshState::ShellActive {
                    s.send_data(data);
                    return;
                }
            }
        }
    }
}

/// Pop one input byte from a specific session. Returns None if no input.
pub fn pop_input_from(idx: usize) -> Option<u8> {
    unsafe {
        if idx < MAX_SESSIONS {
            if let Some(ref mut s) = SESSIONS[idx] {
                return s.pop_input();
            }
        }
        None
    }
}

/// Legacy: pop input byte from the first ShellActive session.
pub fn pop_input_byte() -> Option<u8> {
    unsafe {
        for slot in SESSIONS.iter_mut() {
            if let Some(ref mut s) = *slot {
                if s.state == SshState::ShellActive {
                    if let Some(b) = s.pop_input() { return Some(b); }
                }
            }
        }
        None
    }
}

/// Returns the index of the first ShellActive session, or None.
pub fn first_active_session() -> Option<usize> {
    unsafe {
        for (i, slot) in SESSIONS.iter().enumerate() {
            if let Some(ref s) = *slot {
                if s.state == SshState::ShellActive { return Some(i); }
            }
        }
        None
    }
}

/// Returns true if ANY session is in ShellActive state.
pub fn has_active_client() -> bool {
    first_active_session().is_some()
}

/// Returns true if session `idx` is ShellActive.
pub fn session_is_active(idx: usize) -> bool {
    unsafe {
        idx < MAX_SESSIONS &&
        SESSIONS[idx].as_ref().map(|s| s.state == SshState::ShellActive).unwrap_or(false)
    }
}

/// Returns true if session `idx` has buffered input.
pub fn session_has_input(idx: usize) -> bool {
    unsafe {
        idx < MAX_SESSIONS &&
        SESSIONS[idx].as_ref().map(|s| s.has_input()).unwrap_or(false)
    }
}

/// Get negotiated terminal width for session `idx`.
pub fn get_term_cols_for(idx: usize) -> u32 {
    unsafe {
        if idx < MAX_SESSIONS {
            SESSIONS[idx].as_ref().map(|s| s.term_cols).unwrap_or(80)
        } else { 80 }
    }
}

/// Get negotiated terminal rows for session `idx`.
pub fn get_term_rows_for(idx: usize) -> u32 {
    unsafe {
        if idx < MAX_SESSIONS {
            SESSIONS[idx].as_ref().map(|s| s.term_rows).unwrap_or(24)
        } else { 24 }
    }
}

/// Legacy getters (use first active session).
pub fn get_term_cols() -> u32 {
    first_active_session().map(get_term_cols_for).unwrap_or(80)
}
pub fn get_term_rows() -> u32 {
    first_active_session().map(get_term_rows_for).unwrap_or(24)
}
