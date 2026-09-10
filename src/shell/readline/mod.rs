//! Shell line editor (readline)
//!
//! Reads one line of input from `ShellIo`, with:
//!   - Character echo
//!   - Backspace / delete
//!   - Enter to submit
//!   - Up/Down arrows — navigate command history
//!   - Left/Right arrows — move cursor within the line
//!   - Home/End — jump to start/end of line
//!
//! Does NOT know about VGA or keyboard — uses `ShellIo` exclusively.

use crate::shell::io::ShellIo;
use crate::shell::history;
use crate::drivers::char::keyboard::{
    KEY_UP, KEY_DOWN, KEY_LEFT, KEY_RIGHT, KEY_HOME, KEY_END, KEY_DEL,
};

/// Maximum line length (bytes).
pub const LINE_MAX: usize = 256;

/// Line editor — reused across prompts (zero-alloc).
pub struct LineEditor {
    buf:      [u8; LINE_MAX],
    len:      usize,
    cursor:   usize,   // insertion point within buf (0..=len)
    hist_age: Option<usize>, // None = not browsing history; Some(n) = showing entry n
    hist_buf: [u8; LINE_MAX], // saved draft while browsing history
    hist_buf_len: usize,
}

impl LineEditor {
    pub const fn new() -> Self {
        Self {
            buf:          [0u8; LINE_MAX],
            len:          0,
            cursor:       0,
            hist_age:     None,
            hist_buf:     [0u8; LINE_MAX],
            hist_buf_len: 0,
        }
    }

    /// Block until the user presses Enter.
    /// Returns the line content (without the trailing newline).
    pub fn read_line<'a>(&'a mut self, io: &mut dyn ShellIo) -> &'a [u8] {
        self.len    = 0;
        self.cursor = 0;
        self.hist_age = None;

        loop {
            let byte = io.read_byte_blocking();
            match byte {
                // ── Submit ─────────────────────────────────────────────────
                b'\n' | b'\r' => {
                    io.newline();
                    break;
                }

                // ── Backspace ──────────────────────────────────────────────
                0x08 | 0x7F => {
                    if self.cursor > 0 {
                        self.cursor -= 1;
                        // Shift left from cursor
                        for i in self.cursor..self.len - 1 {
                            self.buf[i] = self.buf[i + 1];
                        }
                        self.len -= 1;
                        self.redraw(io);
                    }
                }

                // ── Delete (forward) ───────────────────────────────────────
                KEY_DEL => {
                    if self.cursor < self.len {
                        for i in self.cursor..self.len - 1 {
                            self.buf[i] = self.buf[i + 1];
                        }
                        self.len -= 1;
                        self.redraw(io);
                    }
                }

                // ── Left arrow ─────────────────────────────────────────────
                KEY_LEFT => {
                    if self.cursor > 0 {
                        self.cursor -= 1;
                        // Move terminal cursor left (BS)
                        io.write_byte(0x08);
                    }
                }

                // ── Right arrow ────────────────────────────────────────────
                KEY_RIGHT => {
                    if self.cursor < self.len {
                        io.write_byte(self.buf[self.cursor]);
                        self.cursor += 1;
                    }
                }

                // ── Home ───────────────────────────────────────────────────
                KEY_HOME => {
                    while self.cursor > 0 {
                        io.write_byte(0x08);
                        self.cursor -= 1;
                    }
                }

                // ── End ────────────────────────────────────────────────────
                KEY_END => {
                    while self.cursor < self.len {
                        io.write_byte(self.buf[self.cursor]);
                        self.cursor += 1;
                    }
                }

                // ── Up arrow — older history ───────────────────────────────
                KEY_UP => {
                    let next_age = match self.hist_age {
                        None => {
                            // Save current draft before browsing
                            self.hist_buf_len = self.len;
                            self.hist_buf[..self.len].copy_from_slice(&self.buf[..self.len]);
                            0
                        }
                        Some(age) => age + 1,
                    };
                    let mut tmp = [0u8; LINE_MAX];
                    if let Some(n) = history::get(next_age, &mut tmp) {
                        self.hist_age = Some(next_age);
                        self.set_line(&tmp[..n], io);
                    }
                    // If no older entry, stay at current
                }

                // ── Down arrow — newer history / return to draft ───────────
                KEY_DOWN => {
                    match self.hist_age {
                        None => {} // already at draft, nothing to do
                        Some(0) => {
                            // Return to saved draft
                            self.hist_age = None;
                            let draft_len = self.hist_buf_len;
                            let mut tmp = [0u8; LINE_MAX];
                            tmp[..draft_len].copy_from_slice(&self.hist_buf[..draft_len]);
                            self.set_line(&tmp[..draft_len], io);
                        }
                        Some(age) => {
                            let next_age = age - 1;
                            let mut tmp = [0u8; LINE_MAX];
                            if let Some(n) = history::get(next_age, &mut tmp) {
                                self.hist_age = Some(next_age);
                                self.set_line(&tmp[..n], io);
                            }
                        }
                    }
                }

                // ── Ctrl+C — cancel current line ───────────────────────────
                0x03 => {
                    io.write_bytes(b"^C\n");
                    self.len    = 0;
                    self.cursor = 0;
                    break;
                }

                // ── Printable ASCII ────────────────────────────────────────
                0x20..=0x7E => {
                    if self.len < LINE_MAX - 1 {
                        // Reset history browsing when typing
                        self.hist_age = None;
                        // Insert at cursor
                        for i in (self.cursor..self.len).rev() {
                            self.buf[i + 1] = self.buf[i];
                        }
                        self.buf[self.cursor] = byte;
                        self.len    += 1;
                        self.cursor += 1;
                        if self.cursor == self.len {
                            // Cursor at end: just echo
                            io.write_byte(byte);
                        } else {
                            self.redraw(io);
                        }
                    }
                }

                // Ignore all other control characters
                _ => {}
            }
        }

        &self.buf[..self.len]
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Replace buffer contents with `line` and redraw.
    fn set_line(&mut self, line: &[u8], io: &mut dyn ShellIo) {
        let n = line.len().min(LINE_MAX - 1);
        self.buf[..n].copy_from_slice(&line[..n]);
        self.len    = n;
        self.cursor = n;
        self.redraw(io);
    }

    /// Redraw the input line in place:
    ///   1. Move to column 0 of the input (by sending BS for each char before cursor).
    ///      But we don't know how many BS we need if cursor is in the middle, so we
    ///      go to the very start first then reprint everything.
    ///
    /// We use a simple trick: send `\r` to go to start of line, then reprint the
    /// prompt-less content.  Since we don't track the prompt width here, we erase
    /// by overwriting then padding with spaces.
    fn redraw(&mut self, io: &mut dyn ShellIo) {
        // Move terminal cursor back to start of input region:
        // send BS for each character currently to the left of cursor, then
        // go all the way to the left using additional BSes up to `len`.
        // Simpler: just go to line start by sending old_cursor BSes, then
        // reprint and erase tail.
        //
        // We track cursor position: first move back to position 0 of the buffer.
        let back = self.cursor;
        for _ in 0..back {
            io.write_byte(0x08);
        }
        // Print entire buffer
        io.write_bytes(&self.buf[..self.len]);
        // Erase any trailing characters from previous longer content
        // (write spaces then go back)
        // We don't know previous len, so we write a few extra spaces safely
        for _ in 0..8 {
            io.write_byte(b' ');
        }
        // Move cursor back from end: (len - cursor) + 8 spaces
        let back2 = (self.len - self.cursor) + 8;
        for _ in 0..back2 {
            io.write_byte(0x08);
        }
    }
}
