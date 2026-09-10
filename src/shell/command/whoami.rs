//! `whoami` — print the current effective username.

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;

pub struct WhoamiCommand;
pub static WHOAMI: WhoamiCommand = WhoamiCommand;

impl Command for WhoamiCommand {
    fn name(&self) -> &'static str { "whoami" }
    fn description(&self) -> &'static str { "Print effective username" }

    fn execute(&self, _args: &[&[u8]], env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        let mut name = [0u8; 32];
        let n = crate::kernel::users::uid_to_name(env.euid(), &mut name);
        io.write_bytes(&name[..n]);
        io.newline();
        0
    }
}
