//! `ps` — list active kernel processes.

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;
use crate::kernel::process::{PROCESS_TABLE, PROCESS_USED, MAX_PROCESSES};
use crate::kernel::process::process::ProcessState;

pub struct PsCommand;
pub static PS: PsCommand = PsCommand;

impl Command for PsCommand {
    fn name(&self) -> &'static str { "ps" }
    fn description(&self) -> &'static str { "List kernel processes" }

    fn execute(&self, _args: &[&[u8]], _env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        io.write_bytes(b"  PID  STATE    \n");
        io.write_bytes(b"  ---  -------  \n");

        unsafe {
            let mut found = false;
            for i in 0..MAX_PROCESSES {
                if !PROCESS_USED[i] { continue; }
                found = true;
                let proc = PROCESS_TABLE[i].assume_init_ref();
                io.write_bytes(b"  ");
                io.write_u64(proc.pid.0 as u64);
                io.write_bytes(b"    ");
                let state = match proc.state {
                    ProcessState::Created  => b"created ".as_ref(),
                    ProcessState::Ready    => b"ready   ".as_ref(),
                    ProcessState::Running  => b"running ".as_ref(),
                    ProcessState::Blocked  => b"blocked ".as_ref(),
                    ProcessState::Zombie   => b"zombie  ".as_ref(),
                };
                io.write_bytes(state);
                io.newline();
            }
            if !found {
                io.write_bytes(b"  (no processes)\n");
            }
        }
        0
    }
}
