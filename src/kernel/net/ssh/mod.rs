//! SSH-2 subsystem for FastROS.
//!
//! Implements a full SSH-2 server allowing remote shell access.
//! Protocol compliance: RFC 4251, RFC 4252, RFC 4253, RFC 4254.
//!
//! Cipher suite: aes128-cbc + hmac-sha2-256
//! KEX:          curve25519-sha256
//! Host key:     ssh-ed25519
//! Auth:         password
//! Channel:      session (shell)
//!
//! Architecture: kernel/net/ssh/ is pure kernel code.
//!   crypto/    — SHA-256/512, HMAC, AES-128-CBC, ChaCha20, Poly1305, Curve25519, Ed25519
//!   transport  — SSH binary packet framing, algorithm negotiation
//!   server     — SSH state machine + TCP integration

pub mod crypto;
pub mod server;
pub mod transport;

/// Initialise the SSH server (call from kernel_main after net::init).
pub fn init() {
    server::init();
    crate::drivers::char::serial::write(b"  sshd: listening on 0.0.0.0:22\n");
}

/// Poll for incoming SSH connections and data.
/// Returns Some(shell_input_bytes) when an authenticated client sends data.
pub fn poll() -> Option<&'static [u8]> {
    server::poll()
}

/// Send data (shell output) to the connected SSH client.
pub fn send_to_client(data: &[u8]) {
    server::send_to_client(data);
}

/// Returns true if an SSH shell session is currently active.
pub fn has_client() -> bool {
    server::has_active_client()
}

/// Return the next byte of SSH shell input, or None if none buffered.
/// Drives the SSH handshake as a side effect via poll().
pub fn poll_byte() -> Option<u8> {
    poll(); // drive the state machine
    server::pop_input_byte()
}

/// Return the terminal width (columns) negotiated during pty-req.
pub fn term_cols() -> u32 { server::get_term_cols() }
pub fn term_rows() -> u32 { server::get_term_rows() }

pub use server::MAX_SESSIONS;

/// Returns the index of the first active shell session, if any.
pub fn first_active_session() -> Option<usize> { server::first_active_session() }
pub fn session_is_active(idx: usize) -> bool    { server::session_is_active(idx) }
pub fn session_has_input(idx: usize) -> bool    { server::session_has_input(idx) }
pub fn pop_input_from(idx: usize) -> Option<u8> { server::pop_input_from(idx) }
pub fn send_to_session(idx: usize, data: &[u8]) { server::send_to_session(idx, data) }
pub fn term_cols_for(idx: usize) -> u32         { server::get_term_cols_for(idx) }
pub fn term_rows_for(idx: usize) -> u32         { server::get_term_rows_for(idx) }
