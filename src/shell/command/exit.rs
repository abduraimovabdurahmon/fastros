//! `exit` — shut down the machine (ACPI power-off).
//!
//! Writes the ACPI S5 (soft-off) value to QEMU's ACPI PM control port.
//! No extra QEMU flags needed — the PIIX4 ACPI port 0x604 is present by default.

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;

pub struct ExitCommand;
pub static EXIT: ExitCommand = ExitCommand;

impl Command for ExitCommand {
    fn name(&self) -> &'static str { "exit" }
    fn description(&self) -> &'static str { "Power off the machine (shuts down QEMU)" }

    fn execute(&self, _args: &[&[u8]], _env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        io.write_bytes(b"System powering off...\n");
        unsafe {
            // ACPI S5 (soft power-off) via QEMU's PIIX4 PM control register.
            // Port 0x604, value 0x2000 = SLP_EN | SLP_TYP(5) = S5 state.
            core::arch::asm!(
                "out dx, ax",
                in("dx") 0x604u16,
                in("ax") 0x2000u16,
                options(nomem, nostack)
            );
        }
        // Should never reach here; halt as a fallback.
        loop {
            unsafe { core::arch::asm!("hlt", options(nomem, nostack)); }
        }
    }
}
