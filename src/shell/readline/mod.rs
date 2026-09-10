//! Shell line editor (readline)
//!
//! Reads one line of input from `ShellIo`, with:
//!   - Character echo
//!   - Backspace / delete
//!   - Enter to submit
//!
//! Does NOT know about VGA or keyboard — uses `ShellIo` exclusively.
//! Future extensions: history, tab completion (implement here, not in mod.rs).

use crate::shell::io::ShellIo;

/// Maximum line length (bytes).
pub const LINE_MAX: usize = 256;

/// Line editor — reused across prompts (zero-alloc).
pub struct LineEditor {
    buf: [u8; LINE_MAX],
    len: usize,
}

impl LineEditor {
    pub const fn new() -> Self {
        Self { buf: [0; LINE_MAX], len: 0 }
    }

    /// Block until the user presses Enter.
    /// Returns the line content (without the trailing newline).
    pub fn read_line<'a>(&'a mut self, io: &mut dyn ShellIo) -> &'a [u8] {
        self.len = 0;
        loop {
            let byte = io.read_byte_blocking();
            match byte {
                // Enter — submit the line
                b'\n' | b'\r' => {
                    io.newline();
                    break;
                }
                // Backspace (ASCII 0x08) or DEL (0x7F)
                0x08 | 0x7F => {
                    if self.len > 0 {
                        self.len -= 1;
                        // Erase the character on screen: BS + space + BS
                        io.write_byte(0x08);
                        io.write_byte(b' ');
                        io.write_byte(0x08);
                    }
                }
                // Printable ASCII
                0x20..=0x7E => {
                    if self.len < LINE_MAX - 1 {
                        self.buf[self.len] = byte;
                        self.len += 1;
                        io.write_byte(byte); // echo
                    }
                }
                // Ignore all other control characters
                _ => {}
            }
        }
        &self.buf[..self.len]
    }
}
