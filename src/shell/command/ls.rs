//! `ls` — list directory contents.
//!
//! Flags:
//!   -a   show all entries including hidden (dot-files)
//!   -l   long listing (currently shows name only, no stat)
//!
//! By default, entries whose names begin with '.' are hidden.

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;

pub struct LsCommand;
pub static LS: LsCommand = LsCommand;

impl Command for LsCommand {
    fn name(&self) -> &'static str { "ls" }
    fn description(&self) -> &'static str { "List directory contents (-a show hidden)" }

    fn execute(&self, args: &[&[u8]], env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        let mut show_all = false;
        let mut target: &[u8] = env.cwd();

        // Parse flags and path
        for &arg in args {
            if arg.starts_with(b"-") {
                if arg.contains(&b'a') { show_all = true; }
                // -l flag accepted but output is the same (no inode info yet)
            } else {
                target = arg;
            }
        }

        match super::virt_fs::lookup(target) {
            None => {
                io.write_bytes(b"ls: ");
                io.write_bytes(target);
                io.write_bytes(b": No such directory\n");
                1
            }
            Some(children) => {
                let visible: &[&[u8]] = children;
                let mut count = 0;

                for &name in visible {
                    if !show_all && name.first() == Some(&b'.') {
                        continue; // skip hidden
                    }
                    io.write_bytes(name);
                    io.write_bytes(b"  ");
                    count += 1;
                }

                if count > 0 {
                    io.newline();
                } else if show_all {
                    io.write_bytes(b"(empty)\n");
                }
                // Without -a, an all-hidden dir shows nothing (like real ls)
                0
            }
        }
    }
}
