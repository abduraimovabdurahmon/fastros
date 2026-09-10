//! `echo` — print arguments separated by spaces.

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;

pub struct EchoCommand;
pub static ECHO: EchoCommand = EchoCommand;

impl Command for EchoCommand {
    fn name(&self) -> &'static str { "echo" }
    fn description(&self) -> &'static str { "Print arguments to the screen" }

    fn execute(&self, args: &[&[u8]], _env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        for (i, arg) in args.iter().enumerate() {
            if i > 0 { io.write_byte(b' '); }
            io.write_bytes(arg);
        }
        io.newline();
        0
    }
}
