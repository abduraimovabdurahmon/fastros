//! Shell line editor (readline)
//!
//! Reads one line from `ShellIo`, supporting:
//!   • Typing at end-of-line (simple echo, no full redraw)
//!   • Backspace at end-of-line (BS + space + BS, no full redraw)
//!   • Mid-line insert / delete (full redraw via \r + prompt + buffer)
//!   • Left / Right arrows  — cursor movement
//!   • Home / End           — jump to line start / end
//!   • Up / Down arrows     — history navigation
//!   • Delete key           — forward delete
//!   • Ctrl+C               — cancel current line
//!
//! redraw() uses \r to return to column 0, reprints prompt + buffer,
//! then moves the hardware cursor to the insertion point.
//! This is correct regardless of prior terminal state.

use crate::shell::io::ShellIo;
use crate::shell::history;
use crate::drivers::char::keyboard::{
    KEY_UP, KEY_DOWN, KEY_LEFT, KEY_RIGHT, KEY_HOME, KEY_END, KEY_DEL,
};

pub const LINE_MAX: usize = 256;

pub struct LineEditor {
    buf:          [u8; LINE_MAX],
    len:          usize,
    cursor:       usize,
    prev_len:     usize,   // buffer length as last displayed (for erase)
    hist_age:     Option<usize>,
    hist_draft:   [u8; LINE_MAX],
    hist_draft_len: usize,
}

impl LineEditor {
    pub const fn new() -> Self {
        Self {
            buf:            [0u8; LINE_MAX],
            len:            0,
            cursor:         0,
            prev_len:       0,
            hist_age:       None,
            hist_draft:     [0u8; LINE_MAX],
            hist_draft_len: 0,
        }
    }

    /// Block until Enter is pressed. Returns the entered line.
    /// `prompt` must match what was printed before calling this function,
    /// because redraw uses \r then re-prints the prompt.
    pub fn read_line<'a>(&'a mut self, io: &mut dyn ShellIo, prompt: &[u8]) -> &'a [u8] {
        self.len      = 0;
        self.cursor   = 0;
        self.prev_len = 0;
        self.hist_age = None;

        loop {
            let key = io.read_byte_blocking();
            match key {

                // ── Submit ─────────────────────────────────────────────────
                b'\n' | b'\r' => {
                    io.newline();
                    break;
                }

                // ── Ctrl+C — cancel ────────────────────────────────────────
                0x03 => {
                    io.write_bytes(b"^C\n");
                    self.len    = 0;
                    self.cursor = 0;
                    break;
                }

                // ── Backspace ──────────────────────────────────────────────
                0x08 | 0x7F => {
                    if self.cursor == 0 { continue; }
                    if self.cursor == self.len {
                        // At end of line — fast path (no full redraw)
                        self.cursor   -= 1;
                        self.len      -= 1;
                        self.prev_len  = self.prev_len.saturating_sub(1);
                        io.write_byte(0x08);
                        io.write_byte(b' ');
                        io.write_byte(0x08);
                    } else {
                        // Mid-line — shift buffer then full redraw
                        self.cursor -= 1;
                        for i in self.cursor..self.len - 1 {
                            self.buf[i] = self.buf[i + 1];
                        }
                        self.len -= 1;
                        self.redraw(io, prompt);
                    }
                }

                // ── Delete (forward) ───────────────────────────────────────
                KEY_DEL => {
                    if self.cursor < self.len {
                        for i in self.cursor..self.len - 1 {
                            self.buf[i] = self.buf[i + 1];
                        }
                        self.len -= 1;
                        self.redraw(io, prompt);
                    }
                }

                // ── Left / Right ───────────────────────────────────────────
                KEY_LEFT => {
                    if self.cursor > 0 {
                        self.cursor -= 1;
                        io.write_byte(0x08);
                    }
                }
                KEY_RIGHT => {
                    if self.cursor < self.len {
                        io.write_byte(self.buf[self.cursor]);
                        self.cursor += 1;
                    }
                }

                // ── Home / End ─────────────────────────────────────────────
                KEY_HOME => {
                    // Send BSes to go back to start of buffer
                    for _ in 0..self.cursor {
                        io.write_byte(0x08);
                    }
                    self.cursor = 0;
                }
                KEY_END => {
                    // Echo remaining characters to advance cursor
                    while self.cursor < self.len {
                        io.write_byte(self.buf[self.cursor]);
                        self.cursor += 1;
                    }
                }

                // ── Up — older history ─────────────────────────────────────
                KEY_UP => {
                    let next_age = match self.hist_age {
                        None => {
                            // Save current draft
                            self.hist_draft_len = self.len;
                            self.hist_draft[..self.len]
                                .copy_from_slice(&self.buf[..self.len]);
                            0
                        }
                        Some(a) => a + 1,
                    };
                    let mut tmp = [0u8; LINE_MAX];
                    if let Some(n) = history::get(next_age, &mut tmp) {
                        self.hist_age = Some(next_age);
                        self.load_line(&tmp[..n]);
                        self.redraw(io, prompt);
                    }
                }

                // ── Down — newer history / back to draft ───────────────────
                KEY_DOWN => {
                    match self.hist_age {
                        None => {}
                        Some(0) => {
                            self.hist_age = None;
                            let n = self.hist_draft_len;
                            let mut tmp = [0u8; LINE_MAX];
                            tmp[..n].copy_from_slice(&self.hist_draft[..n]);
                            self.load_line(&tmp[..n]);
                            self.redraw(io, prompt);
                        }
                        Some(a) => {
                            let next_age = a - 1;
                            let mut tmp = [0u8; LINE_MAX];
                            if let Some(n) = history::get(next_age, &mut tmp) {
                                self.hist_age = Some(next_age);
                                self.load_line(&tmp[..n]);
                                self.redraw(io, prompt);
                            }
                        }
                    }
                }

                // ── Printable ASCII ────────────────────────────────────────
                0x20..=0x7E => {
                    // Typing resets history navigation
                    self.hist_age = None;
                    if self.len >= LINE_MAX - 1 { continue; }

                    if self.cursor == self.len {
                        // Append at end — fast path
                        self.buf[self.len] = key;
                        self.len      += 1;
                        self.cursor   += 1;
                        self.prev_len += 1;
                        io.write_byte(key);
                    } else {
                        // Mid-line insert — shift right then full redraw
                        let mut i = self.len;
                        while i > self.cursor {
                            self.buf[i] = self.buf[i - 1];
                            i -= 1;
                        }
                        self.buf[self.cursor] = key;
                        self.len    += 1;
                        self.cursor += 1;
                        self.redraw(io, prompt);
                    }
                }

                _ => {} // ignore all other keys
            }
        }

        &self.buf[..self.len]
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn load_line(&mut self, src: &[u8]) {
        let n = src.len().min(LINE_MAX - 1);
        self.buf[..n].copy_from_slice(&src[..n]);
        self.len    = n;
        self.cursor = n;
    }

    /// Full redraw: \r, prompt, buffer, erase tail, position cursor.
    fn redraw(&mut self, io: &mut dyn ShellIo, prompt: &[u8]) {
        // Return to column 0 (VGA handles \r as carriage return)
        io.write_byte(b'\r');
        // Reprint prompt
        io.write_bytes(prompt);
        // Print current buffer
        io.write_bytes(&self.buf[..self.len]);
        // Erase characters left from a previously longer display
        let erase = self.prev_len.saturating_sub(self.len);
        for _ in 0..erase { io.write_byte(b' '); }
        self.prev_len = self.len;
        // Move cursor back to insertion point
        let back = (self.len - self.cursor) + erase;
        for _ in 0..back { io.write_byte(0x08); }
    }
}
