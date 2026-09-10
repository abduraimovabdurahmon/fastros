//! Shell line editor (readline)
//!
//! Supports:
//!   • Typing / backspace at end of line (fast path, no full redraw)
//!   • Mid-line insert / delete  (full redraw via \r + prompt + buffer)
//!   • Left / Right / Home / End (cursor movement)
//!   • Up / Down arrows          (history navigation)
//!   • Delete key                (forward delete)
//!   • Tab                       (completion: cycle through matches)
//!   • Ctrl+C                    (cancel line)
//!
//! redraw() uses \r to return to col 0, reprints prompt + buffer, erases
//! old tail, and repositions the cursor.  This is always correct regardless
//! of prior terminal state.

use crate::shell::io::ShellIo;
use crate::shell::history;
use crate::shell::completion::{self, CompletionList};
use crate::drivers::char::keyboard::{
    KEY_UP, KEY_DOWN, KEY_LEFT, KEY_RIGHT, KEY_HOME, KEY_END, KEY_DEL,
};

pub const LINE_MAX: usize = 256;

pub struct LineEditor {
    buf:            [u8; LINE_MAX],
    len:            usize,
    cursor:         usize,
    prev_len:       usize,
    // History navigation
    hist_age:       Option<usize>,
    hist_draft:     [u8; LINE_MAX],
    hist_draft_len: usize,
    // Tab completion state
    tab_list:       CompletionList,
    tab_idx:        usize,   // next index to use in tab_list
    tab_word_start: usize,   // buf index where the completed word starts
    tab_active:     bool,    // true = we are mid-completion cycle
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
            tab_list:       CompletionList::empty(),
            tab_idx:        0,
            tab_word_start: 0,
            tab_active:     false,
        }
    }

    /// Block until Enter is pressed. Returns the entered line.
    /// `prompt` must match what was printed just before this call.
    /// `cwd` is needed for path completion.
    pub fn read_line<'a>(
        &'a mut self,
        io:     &mut dyn ShellIo,
        prompt: &[u8],
        cwd:    &[u8],
    ) -> &'a [u8] {
        self.len            = 0;
        self.cursor         = 0;
        self.prev_len       = 0;
        self.hist_age       = None;
        self.tab_active     = false;

        loop {
            let key = io.read_byte_blocking();

            // Any key other than Tab resets completion cycle
            if key != b'\t' { self.tab_active = false; }

            match key {
                // ── Submit ─────────────────────────────────────────────────
                b'\n' | b'\r' => {
                    io.newline();
                    break;
                }

                // ── Ctrl+C ─────────────────────────────────────────────────
                0x03 => {
                    io.write_bytes(b"^C\n");
                    self.len    = 0;
                    self.cursor = 0;
                    break;
                }

                // ── Tab — completion ───────────────────────────────────────
                b'\t' => {
                    self.handle_tab(io, prompt, cwd);
                }

                // ── Backspace ──────────────────────────────────────────────
                0x08 | 0x7F => {
                    if self.cursor == 0 { continue; }
                    if self.cursor == self.len {
                        // Fast path: at end of line
                        self.cursor   -= 1;
                        self.len      -= 1;
                        self.prev_len  = self.prev_len.saturating_sub(1);
                        io.write_byte(0x08);
                        io.write_byte(b' ');
                        io.write_byte(0x08);
                    } else {
                        // Mid-line: shift and redraw
                        self.cursor -= 1;
                        for i in self.cursor..self.len - 1 {
                            self.buf[i] = self.buf[i + 1];
                        }
                        self.len -= 1;
                        self.redraw(io, prompt);
                    }
                }

                // ── Delete ─────────────────────────────────────────────────
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
                    for _ in 0..self.cursor { io.write_byte(0x08); }
                    self.cursor = 0;
                }
                KEY_END => {
                    while self.cursor < self.len {
                        io.write_byte(self.buf[self.cursor]);
                        self.cursor += 1;
                    }
                }

                // ── Up — older history ─────────────────────────────────────
                KEY_UP => {
                    let next_age = match self.hist_age {
                        None => {
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

                // ── Down — newer / draft ───────────────────────────────────
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
                            let next = a - 1;
                            let mut tmp = [0u8; LINE_MAX];
                            if let Some(n) = history::get(next, &mut tmp) {
                                self.hist_age = Some(next);
                                self.load_line(&tmp[..n]);
                                self.redraw(io, prompt);
                            }
                        }
                    }
                }

                // ── Printable ASCII ────────────────────────────────────────
                0x20..=0x7E => {
                    self.hist_age = None;
                    if self.len >= LINE_MAX - 1 { continue; }
                    if self.cursor == self.len {
                        // Fast path: append
                        self.buf[self.len] = key;
                        self.len      += 1;
                        self.cursor   += 1;
                        self.prev_len += 1;
                        io.write_byte(key);
                    } else {
                        // Mid-line insert
                        let mut i = self.len;
                        while i > self.cursor { self.buf[i] = self.buf[i - 1]; i -= 1; }
                        self.buf[self.cursor] = key;
                        self.len    += 1;
                        self.cursor += 1;
                        self.redraw(io, prompt);
                    }
                }

                _ => {}
            }
        }

        &self.buf[..self.len]
    }

    // ── Tab completion ────────────────────────────────────────────────────────

    fn handle_tab(&mut self, io: &mut dyn ShellIo, prompt: &[u8], cwd: &[u8]) {
        if !self.tab_active {
            // First Tab: build completion list
            let (word_start, partial, is_cmd) = self.find_partial();
            let list = completion::complete(partial, is_cmd, cwd);

            if list.count == 0 {
                return; // no completions — do nothing
            }

            if list.count == 1 {
                // Single match: insert it directly
                self.apply_completion(word_start, list.get(0), io, prompt);
                // Append a space if completing a command or non-directory
                if self.len < LINE_MAX - 1 {
                    self.buf[self.len] = b' ';
                    self.len      += 1;
                    self.cursor   += 1;
                    self.prev_len += 1;
                    io.write_byte(b' ');
                }
                return;
            }

            // Multiple matches: show list below current line, start cycling
            io.newline();
            let mut col = 0usize;
            for i in 0..list.count {
                let name = list.get(i);
                io.write_bytes(name);
                io.write_bytes(b"  ");
                col += name.len() + 2;
                if col >= 76 { io.newline(); col = 0; }
            }
            if col > 0 { io.newline(); }

            // Reprint prompt + buffer so user can continue
            io.write_bytes(prompt);
            io.write_bytes(&self.buf[..self.len]);
            self.prev_len = self.len;

            // Begin cycling through completions
            self.tab_list       = list;
            self.tab_idx        = 0;
            self.tab_word_start = word_start;
            self.tab_active     = true;

        } else {
            // Subsequent Tab: cycle to next completion
            let idx = self.tab_idx % self.tab_list.count;
            // Copy completion into a local buffer to release the immutable borrow
            let mut tmp = [0u8; 128];
            let tmp_len = {
                let s = self.tab_list.get(idx);
                let n = s.len().min(128);
                tmp[..n].copy_from_slice(&s[..n]);
                n
            };
            self.tab_idx += 1;
            let word_start = self.tab_word_start;
            self.apply_completion(word_start, &tmp[..tmp_len], io, prompt);
        }
    }

    /// Find the word under/before the cursor.
    /// Returns (word_start, partial_slice, is_first_token).
    fn find_partial(&self) -> (usize, &[u8], bool) {
        let s = &self.buf[..self.cursor];
        // Skip trailing spaces (shouldn't happen but safe)
        let end = self.cursor;
        // Walk back to find word start
        let start = s.iter().rposition(|&b| b == b' ' || b == b'\t')
            .map(|i| i + 1)
            .unwrap_or(0);
        let partial = &self.buf[start..end];
        // Is this the first token? Yes if no non-space chars before start
        let is_cmd = self.buf[..start].iter().all(|&b| b == b' ' || b == b'\t');
        (start, partial, is_cmd)
    }

    /// Replace buf[word_start..cursor] with `completion` and redraw.
    fn apply_completion(
        &mut self,
        word_start:  usize,
        completion:  &[u8],
        io:          &mut dyn ShellIo,
        prompt:      &[u8],
    ) {
        let old_word_len = self.cursor - word_start;
        let new_word_len = completion.len().min(LINE_MAX - word_start - 1);
        let after        = self.len - self.cursor;

        // Shift tail right/left to fit new completion
        let new_len = word_start + new_word_len + after;
        if new_len >= LINE_MAX { return; }

        // Move everything after cursor
        if new_word_len != old_word_len {
            if new_word_len > old_word_len {
                // Shift right
                let delta = new_word_len - old_word_len;
                if self.len + delta >= LINE_MAX { return; }
                let mut i = self.len + delta;
                while i > word_start + new_word_len {
                    self.buf[i - 1] = self.buf[i - 1 - delta];
                    i -= 1;
                }
            } else {
                // Shift left
                let delta = old_word_len - new_word_len;
                for i in word_start + new_word_len..self.len - delta {
                    self.buf[i] = self.buf[i + delta];
                }
            }
        }

        // Write completion into buffer
        self.buf[word_start..word_start + new_word_len]
            .copy_from_slice(&completion[..new_word_len]);
        self.len    = new_len;
        self.cursor = word_start + new_word_len;
        self.redraw(io, prompt);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn load_line(&mut self, src: &[u8]) {
        let n = src.len().min(LINE_MAX - 1);
        self.buf[..n].copy_from_slice(&src[..n]);
        self.len    = n;
        self.cursor = n;
    }

    fn redraw(&mut self, io: &mut dyn ShellIo, prompt: &[u8]) {
        io.write_byte(b'\r');
        io.write_bytes(prompt);
        io.write_bytes(&self.buf[..self.len]);
        let erase = self.prev_len.saturating_sub(self.len);
        for _ in 0..erase { io.write_byte(b' '); }
        self.prev_len = self.len;
        let back = (self.len - self.cursor) + erase;
        for _ in 0..back { io.write_byte(0x08); }
    }
}
