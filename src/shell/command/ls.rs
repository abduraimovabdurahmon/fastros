//! `ls` — list directory contents.
//!
//! Backed by the static virtual FS table in `virt_fs`.

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;

pub struct LsCommand;
pub static LS: LsCommand = LsCommand;

impl Command for LsCommand {
    fn name(&self) -> &'static str { "ls" }
    fn description(&self) -> &'static str { "List directory contents" }

    fn execute(&self, args: &[&[u8]], env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        let target: &[u8] = if args.is_empty() { env.cwd() } else { args[0] };

        match super::virt_fs::lookup(target) {
            Some(children) if children.is_empty() => {
                io.write_bytes(b"(empty)\n");
                0
            }
            Some(children) => {
                for name in children.iter() {
                    io.write_bytes(name);
                    io.write_bytes(b"  ");
                }
                io.newline();
                0
            }
            None => {
                io.write_bytes(b"ls: ");
                io.write_bytes(target);
                io.write_bytes(b": No such directory\n");
                1
            }
        }
    }
}
