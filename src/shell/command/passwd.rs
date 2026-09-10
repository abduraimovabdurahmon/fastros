//! `passwd` — change user password.
//!
//! Usage:
//!   passwd            — change your own password
//!   passwd username   — change another user's password (root only)

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;
use crate::kernel::users;
use super::su::read_secret;

pub struct PasswdCommand;
pub static PASSWD: PasswdCommand = PasswdCommand;

impl Command for PasswdCommand {
    fn name(&self) -> &'static str { "passwd" }
    fn description(&self) -> &'static str { "Change user password" }

    fn execute(&self, args: &[&[u8]], env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        // Determine target user
        let target: &[u8] = match args.first() {
            Some(&t) => t,
            None     => env.username(),
        };

        // Only root can change other users' passwords
        if target != env.username() && !env.is_root() {
            io.write_bytes(b"passwd: Permission denied\n");
            return 1;
        }

        // Verify current password (unless root changing someone else's)
        if !env.is_root() || target == env.username() {
            io.write_bytes(b"Current password: ");
            let mut cur = [0u8; 64];
            let cl = read_secret(io, &mut cur);

            let mut uname_buf = [0u8; 32];
            let un = {
                let u = env.username();
                let n = u.len().min(32);
                uname_buf[..n].copy_from_slice(&u[..n]);
                n
            };

            if !users::verify(&uname_buf[..un], &cur[..cl]) {
                io.write_bytes(b"passwd: Authentication failure\n");
                return 1;
            }
        }

        // Read new password twice
        io.write_bytes(b"New password: ");
        let mut pw1 = [0u8; 64];
        let l1 = read_secret(io, &mut pw1);

        if l1 < 5 {
            io.write_bytes(b"passwd: password too short (minimum 5 characters)\n");
            return 1;
        }

        io.write_bytes(b"Retype new password: ");
        let mut pw2 = [0u8; 64];
        let l2 = read_secret(io, &mut pw2);

        if l1 != l2 || pw1[..l1] != pw2[..l2] {
            io.write_bytes(b"passwd: passwords do not match\n");
            return 1;
        }

        let changed = users::with_users_mut(|db| db.set_password(target, &pw1[..l1]));
        if changed {
            io.write_bytes(b"passwd: password updated successfully\n");
            0
        } else {
            io.write_bytes(b"passwd: user not found\n");
            1
        }
    }
}
