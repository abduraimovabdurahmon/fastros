//! `userdel` — delete a user account.
//!
//! Usage:
//!   userdel username       — remove user (keep home directory)
//!   userdel -r username    — remove user AND home directory

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;
use crate::kernel::users;
use crate::shell::memdir;
use crate::shell::memfs;

pub struct UserdelCommand;
pub static USERDEL: UserdelCommand = UserdelCommand;

impl Command for UserdelCommand {
    fn name(&self) -> &'static str { "userdel" }
    fn description(&self) -> &'static str { "Delete a user account" }

    fn execute(&self, args: &[&[u8]], env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        if !env.is_root() {
            io.write_bytes(b"userdel: Permission denied (must be root)\n");
            return 1;
        }

        let mut remove_home = false;
        let mut username: &[u8] = b"";
        for &arg in args {
            if arg == b"-r" || arg == b"--remove" { remove_home = true; }
            else if !arg.starts_with(b"-") { username = arg; }
        }

        if username.is_empty() {
            io.write_bytes(b"Usage: userdel [-r] <username>\n");
            return 1;
        }
        if username == b"root" {
            io.write_bytes(b"userdel: cannot delete root\n");
            return 1;
        }

        // Get home path before deletion
        let mut home_buf = [0u8; 64];
        let home_len = match users::lookup_user(username) {
            None => {
                io.write_bytes(b"userdel: user '");
                io.write_bytes(username);
                io.write_bytes(b"' does not exist\n");
                return 1;
            }
            Some((uid, _, home, hl)) => {
                home_buf[..hl].copy_from_slice(&home[..hl]);
                // Remove from all groups
                users::with_groups_mut(|db| db.remove_member(uid));
                hl
            }
        };

        // Remove from user table
        users::with_users_mut(|db| db.remove(username));

        // Remove home if -r
        if remove_home && home_len > 0 {
            let home = &home_buf[..home_len];
            memdir::remove_recursive(home);
            // Also remove memfs files under home
            let mut paths = [b"" as &[u8]; 16];
            let n = memfs::list(&mut paths);
            for i in 0..n {
                if paths[i].starts_with(home) {
                    memfs::remove(paths[i]);
                }
            }
            io.write_bytes(b"userdel: removed home directory ");
            io.write_bytes(home);
            io.newline();
        }

        io.write_bytes(b"userdel: user '");
        io.write_bytes(username);
        io.write_bytes(b"' deleted\n");
        0
    }
}
