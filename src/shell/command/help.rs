//! `help` — list all available commands with their descriptions.

use super::{Command, CommandRegistry};
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;

pub struct HelpCommand;
pub static HELP: HelpCommand = HelpCommand;

impl Command for HelpCommand {
    fn name(&self) -> &'static str { "help" }
    fn description(&self) -> &'static str { "List available commands" }

    fn execute(&self, _args: &[&[u8]], _env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        io.write_bytes(b"Available commands:\n");
        io.write_bytes(b"  (use <command> --help for details)\n\n");

        // Re-build the registry to iterate — avoids a circular static dependency
        let reg = CommandRegistry::init();
        for cmd in reg.iter() {
            io.write_bytes(b"  ");
            io.write_bytes(cmd.name().as_bytes());
            // Pad to column 12
            let pad = 12usize.saturating_sub(cmd.name().len());
            for _ in 0..pad { io.write_byte(b' '); }
            io.write_bytes(cmd.description().as_bytes());
            io.newline();
        }
        0
    }
}
