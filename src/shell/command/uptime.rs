//! `uptime` — show elapsed time since boot.
//!
//! Uses the PIT tick counter (100 Hz) from `arch::x86_64::cpu::timer`.
//! Converts ticks → hours : minutes : seconds.

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;

pub struct UptimeCommand;
pub static UPTIME: UptimeCommand = UptimeCommand;

impl Command for UptimeCommand {
    fn name(&self) -> &'static str { "uptime" }
    fn description(&self) -> &'static str { "Show time elapsed since boot" }

    fn execute(&self, _args: &[&[u8]], _env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        let ticks = crate::arch::x86_64::cpu::timer::ticks();
        let secs  = ticks / 100;
        let mins  = secs  / 60;
        let hours = mins  / 60;

        io.write_bytes(b"Uptime: ");
        io.write_u64(hours);
        io.write_byte(b'h');
        io.write_u64(mins % 60);
        io.write_byte(b'm');
        io.write_u64(secs % 60);
        io.write_bytes(b"s  (");
        io.write_u64(ticks);
        io.write_bytes(b" ticks @ 100 Hz)\n");
        0
    }
}
