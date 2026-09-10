//! sshd — SSH daemon status.
//!
//! Usage:
//!   sshd          — show SSH server status
//!   sshd -q       — quiet (exit code only: 0=client connected, 1=idle)
//!
//! The SSH server starts automatically at boot on port 22.
//! Connect with: ssh root@10.0.2.15  (password: root)

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;
use crate::kernel::net::ssh;

pub struct SshdCommand;
pub static SSHD: SshdCommand = SshdCommand;

impl Command for SshdCommand {
    fn name(&self) -> &'static str { "sshd" }
    fn description(&self) -> &'static str { "Show SSH daemon status" }

    fn execute(&self, args: &[&[u8]], _env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        let quiet = args.iter().any(|a| *a == b"-q");
        let connected = ssh::has_client();

        if !quiet {
            io.write_bytes(b"SSH daemon status:\n");
            io.write_bytes(b"  Protocol:  SSH-2.0\n");
            io.write_bytes(b"  Listen:    0.0.0.0:22\n");
            io.write_bytes(b"  Cipher:    aes128-cbc\n");
            io.write_bytes(b"  MAC:       hmac-sha2-256\n");
            io.write_bytes(b"  KEX:       curve25519-sha256\n");
            io.write_bytes(b"  Host key:  ssh-ed25519\n");
            io.write_bytes(b"  Auth:      password\n");
            io.write_bytes(b"  Client:    ");
            io.write_bytes(if connected { b"connected (shell active)\n" } else { b"none (waiting)\n" });
            io.write_bytes(b"\nConnect with: ssh root@10.0.2.15\n");
        }

        if connected { 0 } else { 1 }
    }
}
