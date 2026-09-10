//! `uname` — print kernel identification.

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;

pub struct UnameCommand;
pub static UNAME: UnameCommand = UnameCommand;

impl Command for UnameCommand {
    fn name(&self) -> &'static str { "uname" }
    fn description(&self) -> &'static str { "Print kernel/OS identification" }

    fn execute(&self, args: &[&[u8]], _env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        // `uname -a` prints everything; no flags → just the OS name
        let all = args.iter().any(|a| *a == b"-a");

        if all {
            io.write_bytes(b"FastROS  fastros  0.1.0  ");
            io.write_bytes(b"#1 SMP x86_64  2026-09-10  ");
            io.write_bytes(b"fastros/x86_64\n");
        } else {
            io.write_bytes(b"FastROS\n");
        }
        0
    }
}
