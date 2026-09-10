//! `su` — switch user identity.
//!
//! Usage:
//!   su           — switch to root (asks root password)
//!   su username  — switch to username (asks that user's password)
//!   su -         — switch to root and reset environment (cd to home)
//!
//! Mirrors Linux su(1) from shadow-utils.

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;
use crate::kernel::users;

pub struct SuCommand;
pub static SU: SuCommand = SuCommand;

impl Command for SuCommand {
    fn name(&self) -> &'static str { "su" }
    fn description(&self) -> &'static str { "Switch user identity" }

    fn execute(&self, args: &[&[u8]], env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        // Parse arguments
        let mut target: &[u8] = b"root";
        for &arg in args {
            if arg == b"-" || arg == b"-l" || arg == b"--login" { continue; }
            if !arg.starts_with(b"-") { target = arg; break; }
        }

        // root switching to any user doesn't need a password (Linux behaviour)
        if env.euid() != 0 {
            io.write_bytes(b"Password: ");
            let mut pw = [0u8; 64];
            let pwlen = read_secret(io, &mut pw);

            if !users::verify(target, &pw[..pwlen]) {
                io.write_bytes(b"su: Authentication failure\n");
                return 1;
            }
        }

        // Look up target user
        match users::lookup_user(target) {
            None => {
                io.write_bytes(b"su: user '");
                io.write_bytes(target);
                io.write_bytes(b"' does not exist\n");
                return 1;
            }
            Some((uid, gid, home, hlen)) => {
                env.set_session(uid, gid, &home[..hlen], target);
                // Print new session info (like real su)
                io.write_bytes(b"\n");
            }
        }
        0
    }
}

/// Read a password without echoing characters. Returns length.
pub fn read_secret(io: &mut dyn ShellIo, buf: &mut [u8; 64]) -> usize {
    let mut n = 0;
    loop {
        let b = io.read_byte_blocking();
        match b {
            b'\n' | b'\r' => { io.newline(); break; }
            0x08 | 0x7F   => { if n > 0 { n -= 1; } }          // backspace
            c if c >= 0x20 && n < 64 => { buf[n] = c; n += 1; } // no echo
            _ => {}
        }
    }
    n
}
