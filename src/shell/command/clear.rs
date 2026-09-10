//! `clear` — clear the terminal screen.

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;

pub struct ClearCommand;
pub static CLEAR: ClearCommand = ClearCommand;

impl Command for ClearCommand {
    fn name(&self) -> &'static str { "clear" }
    fn description(&self) -> &'static str { "Clear the screen" }

    fn execute(&self, _args: &[&[u8]], _env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        io.clear_screen();
        0
    }
}
