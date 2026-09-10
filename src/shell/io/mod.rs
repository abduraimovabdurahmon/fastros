//! Shell I/O abstraction layer
//!
//! `ShellIo` is the ONLY interface through which shell commands interact
//! with the outside world.  This decouples:
//!   - Commands from VGA/keyboard specifics
//!   - Readline from concrete I/O devices
//!   - The shell from any future TTY / serial / network backend
//!
//! Concrete implementation: `shell::VgaKeyboardIo` in `shell/mod.rs`.

/// Output + input contract for the shell.
///
/// All methods are `&mut self` so implementations can track cursor state.
pub trait ShellIo {
    // ── Output ────────────────────────────────────────────────────────────────

    /// Write a single byte to the output.
    fn write_byte(&mut self, b: u8);

    /// Write a byte slice to the output.
    fn write_bytes(&mut self, s: &[u8]);

    /// Write a decimal integer.
    fn write_u64(&mut self, n: u64) {
        let mut buf = [0u8; 20];
        let s = crate::libs::fmt::u64_to_dec(n, &mut buf);
        self.write_bytes(s);
    }

    /// Write a hex integer with "0x" prefix.
    fn write_hex(&mut self, n: u64) {
        let mut buf = [0u8; 18];
        let s = crate::libs::fmt::u64_to_hex(n, &mut buf);
        self.write_bytes(s);
    }

    /// Write a newline.
    fn newline(&mut self) { self.write_byte(b'\n'); }

    // ── Input ─────────────────────────────────────────────────────────────────

    /// Non-blocking read.  Returns `None` if no key is pending.
    fn read_byte(&mut self) -> Option<u8>;

    /// Blocking read.  Halts the CPU between polls (energy-efficient spin).
    fn read_byte_blocking(&mut self) -> u8 {
        loop {
            if let Some(b) = self.read_byte() { return b; }
            // Yield CPU until the next interrupt (keyboard IRQ will wake us)
            unsafe { core::arch::asm!("hlt", options(nomem, nostack)); }
        }
    }

    // ── Screen control ────────────────────────────────────────────────────────

    /// Clear the entire screen and reset cursor to top-left.
    fn clear_screen(&mut self);
}
