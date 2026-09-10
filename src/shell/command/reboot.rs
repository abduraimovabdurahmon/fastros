//! `reboot` — reset the machine.
//!
//! Uses the PS/2 keyboard controller to pulse the reset line (port 0x64, cmd 0xFE).
//! This is the standard BIOS-compatible reset method, works in QEMU.

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;

pub struct RebootCommand;
pub static REBOOT: RebootCommand = RebootCommand;

impl Command for RebootCommand {
    fn name(&self) -> &'static str { "reboot" }
    fn description(&self) -> &'static str { "Reboot the system" }

    fn execute(&self, _args: &[&[u8]], _env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        io.write_bytes(b"System rebooting...\n");
        // Pulse reset via keyboard controller (universally supported)
        unsafe {
            // Wait for keyboard controller input buffer to be empty
            loop {
                let status: u8;
                core::arch::asm!("in al, 0x64", out("al") status, options(nomem, nostack));
                if (status & 0x02) == 0 { break; }
            }
            // Send "pulse output port" command — bit 0 = reset line
            core::arch::asm!("out 0x64, al", in("al") 0xFEu8, options(nomem, nostack));
        }
        // Should never reach here
        loop { unsafe { core::arch::asm!("hlt", options(nomem, nostack)); } }
    }
}
