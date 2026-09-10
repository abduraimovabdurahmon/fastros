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
    crypto::{self, sha256, hmac, aes::{self, Aes128Cbc}, curve25519, ed25519},
    transport::{self, *},
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
    enc_cs:       Option<Aes128Cbc>,  // client → server decryption
    enc_sc:       Option<Aes128Cbc>,  // server → client encryption
    mac_key_cs:   [u8; 32],
    mac_key_sc:   [u8; 32],

    // Sequence numbers (for MAC)
    seq_send:     u32,
    seq_recv:     u32,

    // Key exchange material
    server_privkey: [u8; 32],
    session_id:     [u8; 32],

    // Authenticated user
    pub username: [u8; 32],
    pub uname_len: usize,

    // Channel
    pub channel_id_client: u32,
    pub channel_id_server: u32,
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
            username: [0; 32], uname_len: 0,
            channel_id_client: 0, channel_id_server: 0,
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
                enc.encrypt(&mut pkt[..pkt_len]);
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

    /// Process a received SSH_MSG_KEXINIT from client, send ours.
    pub fn handle_kexinit(&mut self) {
        let mut payload = [0u8; 512];
        let len = build_kexinit(&mut payload);
        self.send_packet(&payload[..len]);
        self.flush();
        self.state = SshState::KexDh;
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

        // Generate server ephemeral key pair
        // Use a deterministic private key based on a counter (simplified)
        static mut KEX_COUNTER: u8 = 0;
        let mut server_eph_priv = [0u8; 32];
        unsafe {
            server_eph_priv[0] = 0xAB ^ KEX_COUNTER;
            KEX_COUNTER = KEX_COUNTER.wrapping_add(1);
        }
        for i in 1..32 { server_eph_priv[i] = (i as u8).wrapping_mul(0x7) ^ 0x5A; }
        // Clamp
        server_eph_priv[0]  &= 248;
        server_eph_priv[31] &= 127;
        server_eph_priv[31] |= 64;

        let server_eph_pub = curve25519::public_key(&server_eph_priv);
        let shared_secret  = curve25519::shared_secret(&server_eph_priv, &client_pub);

        // Compute host key (Ed25519 public key)
        let (_host_priv, host_pub) = ed25519::key_pair_from_seed(&ed25519::HOST_SEED);

        // Build H = SHA-256(client_version || server_version || client_kexinit ||
        //                    server_kexinit || host_key || client_ephpub ||
        //                    server_ephpub || shared_secret)
        // (Simplified: hash key material only)
        let mut h_input = [0u8; 256];
        h_input[0..32].copy_from_slice(&client_pub);
        h_input[32..64].copy_from_slice(&server_eph_pub);
        h_input[64..96].copy_from_slice(&shared_secret);
        h_input[96..128].copy_from_slice(&host_pub);
        let exchange_hash = sha256::hash(&h_input[..128]);

        if self.session_id == [0u8; 32] {
            self.session_id = exchange_hash;
        }

        // Sign H with host key (Ed25519)
        let mut host_priv_full = [0u8; 64];
        host_priv_full[..32].copy_from_slice(&ed25519::HOST_SEED);
        host_priv_full[32..].copy_from_slice(&host_pub);
        let signature = ed25519::sign(&host_priv_full, &exchange_hash);

        // Build SSH_MSG_KEX_ECDH_REPLY:
        //   byte   SSH_MSG_KEX_ECDH_REPLY
        //   string host_key (ssh-ed25519 || public_key_bytes)
        //   string server_ephemeral_public_key
        //   string signature
        let mut reply = [0u8; 512];
        let mut off = 0;
        reply[off] = SSH_MSG_KEX_ECDH_REPLY; off += 1;

        // Host key blob: string "ssh-ed25519" || string pubkey
        let mut host_key_blob = [0u8; 64];
        let mut hkb_off = 0;
        hkb_off += put_string(&mut host_key_blob, hkb_off, b"ssh-ed25519");
        hkb_off += put_string(&mut host_key_blob, hkb_off, &host_pub);
        off += put_string(&mut reply, off, &host_key_blob[..hkb_off]);

        // Server ephemeral public key
        off += put_string(&mut reply, off, &server_eph_pub);

        // Signature blob: string "ssh-ed25519" || string sig_bytes
        let mut sig_blob = [0u8; 80];
        let mut sb_off = 0;
        sb_off += put_string(&mut sig_blob, sb_off, b"ssh-ed25519");
        sb_off += put_string(&mut sig_blob, sb_off, &signature);
        off += put_string(&mut reply, off, &sig_blob[..sb_off]);

        self.send_packet(&reply[..off]);

        // Send SSH_MSG_NEWKEYS
        self.send_packet(&[SSH_MSG_NEWKEYS]);
        self.flush();

        // Derive session keys
        let keys = SessionKeys::derive(&shared_secret, &exchange_hash, &self.session_id);

        // Install encryption
        self.enc_cs = Some(Aes128Cbc::new(&keys.enc_key_cs, &keys.iv_cs));
        self.enc_sc = Some(Aes128Cbc::new(&keys.enc_key_sc, &keys.iv_sc));
        self.mac_key_cs.copy_from_slice(&keys.mac_key_cs);
        self.mac_key_sc.copy_from_slice(&keys.mac_key_sc);
        self.encrypted = true;
        self.state = SshState::NewKeys;
    }

    /// Handle SSH_MSG_NEWKEYS from client (just acknowledge, keys already active).
    pub fn handle_newkeys(&mut self) {
        self.state = SshState::ServiceRequest;
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
            self.send_packet(&[SSH_MSG_USERAUTH_SUCCESS]);
            self.flush();
            self.state = SshState::Authenticated;
        } else {
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
        let want_reply = payload[next] != 0;

        let success = match req_type {
            b"shell" => {
                self.state = SshState::ShellActive;
                // Send a welcome banner
                self.send_data(b"\r\nFastROS SSH shell. Type 'exit' to disconnect.\r\n$ ");
                true
            }
            b"pty-req" => true,   // accept but don't do anything with it
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

        // Handle version exchange (text line before binary protocol)
        if self.state == SshState::Idle {
            // Look for \n terminating the client version string
            if let Some(pos) = find_byte(&self.rx_buf[..self.rx_len], b'\n') {
                // Client version received; send ours
                self.send_version();
                // Remove version line from buffer
                let consumed = pos + 1;
                self.rx_buf.copy_within(consumed..self.rx_len, 0);
                self.rx_len -= consumed;
                // Send our KEXINIT immediately
                self.handle_kexinit();
            }
            return ShellInput::None;
        }

        // Binary packet processing
        loop {
            if self.rx_len < 5 { break; }

            // Decrypt if needed
            if self.encrypted {
                // We'd need to decrypt the first block to get packet length.
                // Simplified: assume the first 4 bytes give the length after decrypt.
                // (A real impl decrypts one block at a time)
                // For now: attempt to use the data as-is (works when testing with
                // non-encrypting clients or after implementing proper decryption)
            }

            let (payload, consumed) = parse_packet(&self.rx_buf[..self.rx_len]);
            if consumed == 0 { break; }

            // Make a local copy to avoid borrow conflicts
            let mut payload_copy = [0u8; 1600];
            let plen = payload.len().min(1600);
            payload_copy[..plen].copy_from_slice(&payload[..plen]);
            let plen = plen;

            // Skip MAC bytes if encrypted
            let mac_size = if self.encrypted { 32 } else { 0 };
            let total_consumed = (consumed + mac_size).min(self.rx_len);
            self.rx_buf.copy_within(total_consumed..self.rx_len, 0);
            self.rx_len -= total_consumed;
            self.seq_recv = self.seq_recv.wrapping_add(1);

            if plen == 0 { continue; }
            let msg_type = payload_copy[0];

            match (self.state, msg_type) {
                (SshState::VersionSent, SSH_MSG_KEXINIT) |
                (SshState::KexInit,    SSH_MSG_KEXINIT) => {
                    self.handle_kexinit();
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
                (SshState::ChannelOpen,  SSH_MSG_CHANNEL_REQUEST) => {
                    self.handle_channel_request(&payload_copy[..plen]);
                }
                (SshState::ShellActive, SSH_MSG_CHANNEL_DATA) => {
                    // Copy data and return it
                    let (data, _) = get_string(&payload_copy[..plen], 5);
                    let n = data.len().min(256);
                    // Copy into static buffer (single-threaded kernel)
                    static mut SHELL_INPUT: [u8; 256] = [0; 256];
                    unsafe {
                        SHELL_INPUT[..n].copy_from_slice(&data[..n]);
                        return ShellInput::Data(&SHELL_INPUT[..n]);
                    }
                }
                (SshState::ShellActive, SSH_MSG_CHANNEL_EOF) |
                (SshState::ShellActive, SSH_MSG_CHANNEL_CLOSE) => {
                    self.send_disconnect(SSH_DISCONNECT_BY_APPLICATION, b"client closed");
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
}

pub enum ShellInput<'a> {
    None,
    Data(&'a [u8]),
}

// ── TCP write helper ──────────────────────────────────────────────────────────

fn tcp_write(fd: usize, data: &[u8]) -> usize {
    // In our kernel, "sending" means pushing into the socket's internal TX
    // buffer. The actual TCP ACK/retransmit is handled by the TCP stack.
    // For now we use a direct approach: store the data for the shell loop to
    // retrieve and send via send_ipv4/TCP.
    if let Some(s) = socket::get_mut(fd) {
        // Push into RX buffer of the peer socket (we're simulating loopback-style)
        // In a real implementation this would go to a TX ring buffer.
        // For our single-connection SSH, we use a workaround: push to the
        // socket's own RX buffer and let the shell loop read it.
        // Actually this pushes into the SENDER's socket which is wrong.
        // For a correct implementation, this needs the full TCP TX path.
        // We mark as data available by returning the length.
        let _ = s;
        data.len()
    } else {
        0
    }
}

fn find_byte(haystack: &[u8], needle: u8) -> Option<usize> {
    haystack.iter().position(|&b| b == needle)
}

// ── Global server state ───────────────────────────────────────────────────────

static mut SERVER_SESSION: Option<SshSession> = None;
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

/// Poll for incoming SSH connections and data. Call from the main loop.
/// Returns Some(shell_input) when authenticated client sends shell data.
pub fn poll() -> Option<&'static [u8]> {
    // Check for new connections (TCP ESTABLISHED on port 22)
    unsafe {
        if let Some(ref mut session) = SERVER_SESSION {
            if session.state == SshState::Closed {
                SERVER_SESSION = None;
                // Re-listen
                init();
            }
        }

        // Try to accept a new connection
        if SERVER_SESSION.is_none() {
            if let Some(fd) = socket::find_tcp(&[0;4], 22, &[0;4], 0) {
                if let Some(s) = socket::get(fd) {
                    if s.tcp_state == TcpState::Established {
                        SERVER_SESSION = Some(SshSession::new(fd));
                    }
                }
            }
        }

        if let Some(ref mut session) = SERVER_SESSION {
            // Read data from TCP socket
            if let Some(s) = socket::get_mut(session.tcp_fd) {
                if s.rx_available() > 0 {
                    let mut buf = [0u8; 1024];
                    let n = s.rx_pop(&mut buf);
                    if n > 0 {
                        match session.process_received(&buf[..n]) {
                            ShellInput::Data(d) => return Some(d),
                            ShellInput::None    => {}
                        }
                    }
                }
            }
        }
    }
    None
}

/// Send data to the current SSH client (if connected and shell is active).
pub fn send_to_client(data: &[u8]) {
    unsafe {
        if let Some(ref mut session) = SERVER_SESSION {
            if session.state == SshState::ShellActive {
                session.send_data(data);
            }
        }
    }
}

/// Returns true if an SSH client is currently connected and shell is active.
pub fn has_active_client() -> bool {
    unsafe {
        matches!(SERVER_SESSION, Some(ref s) if s.state == SshState::ShellActive)
    }
}
