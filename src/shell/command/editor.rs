//! Shared text buffer for nano and vim.
//!
//! Line-based, fixed capacity, no heap allocation.
//! Stored as `static mut` in each editor to avoid stack overflow.

/// Maximum number of lines.
pub const MAX_LINES: usize = 100;
/// Maximum bytes per line (one VGA column width).
pub const LINE_CAP: usize = 80;

/// Fixed-size line-based text buffer.
pub struct EditorBuf {
    pub lines: [[u8; LINE_CAP]; MAX_LINES],
    pub lens:  [usize; MAX_LINES],
    pub count: usize,
}

impl EditorBuf {
    pub const fn new() -> Self {
        Self {
            lines: [[0u8; LINE_CAP]; MAX_LINES],
            lens:  [0usize; MAX_LINES],
            count: 1, // always at least one (empty) line
        }
    }

    /// Reset to a single empty line.
    pub fn clear(&mut self) {
        self.count = 1;
        self.lens[0] = 0;
    }

    /// Load content from a static byte slice, splitting on `\n`.
    pub fn load(&mut self, content: &[u8]) {
        self.count = 0;
        let mut start = 0;
        for (i, &b) in content.iter().enumerate() {
            if b == b'\n' {
                self.append_raw(&content[start..i]);
                start = i + 1;
            }
        }
        // Last line (no trailing newline)
        if start < content.len() {
            self.append_raw(&content[start..]);
        }
        if self.count == 0 { self.count = 1; }
    }

    fn append_raw(&mut self, bytes: &[u8]) {
        if self.count >= MAX_LINES { return; }
        let len = bytes.len().min(LINE_CAP);
        self.lines[self.count][..len].copy_from_slice(&bytes[..len]);
        self.lens[self.count] = len;
        self.count += 1;
    }

    /// Return line as byte slice (empty slice if out of range).
    pub fn line(&self, idx: usize) -> &[u8] {
        if idx >= self.count { return b""; }
        &self.lines[idx][..self.lens[idx]]
    }

    /// Insert `ch` at (line, col), shifting the rest of the line right.
    pub fn insert_char(&mut self, line: usize, col: usize, ch: u8) {
        if line >= self.count { return; }
        let len = self.lens[line];
        if len >= LINE_CAP { return; }
        let col = col.min(len);
        let mut i = len;
        while i > col { self.lines[line][i] = self.lines[line][i - 1]; i -= 1; }
        self.lines[line][col] = ch;
        self.lens[line] += 1;
    }

    /// Delete the character before (line, col).
    /// If col == 0 and line > 0, joins this line with the previous one.
    /// Updates `line` and `col` through mutable references.
    pub fn backspace(&mut self, line: &mut usize, col: &mut usize) {
        if *col > 0 {
            let l = *line;
            let c = *col;
            let len = self.lens[l];
            let mut i = c - 1;
            while i + 1 < len { self.lines[l][i] = self.lines[l][i + 1]; i += 1; }
            self.lens[l] -= 1;
            *col -= 1;
        } else if *line > 0 {
            let prev = *line - 1;
            let prev_len = self.lens[prev];
            let cur_len  = self.lens[*line];
            if prev_len + cur_len <= LINE_CAP {
                let li = *line;
                for i in 0..cur_len {
                    self.lines[prev][prev_len + i] = self.lines[li][i];
                }
                self.lens[prev] = prev_len + cur_len;
                self.remove_line(li);
                *col  = prev_len;
                *line = prev;
            }
        }
    }

    /// Delete the character at (line, col) — Delete key.
    pub fn delete_char(&mut self, line: usize, col: usize) {
        if line >= self.count { return; }
        let len = self.lens[line];
        if col >= len {
            // At end of line: join with next
            if line + 1 < self.count {
                let next_len = self.lens[line + 1];
                if len + next_len <= LINE_CAP {
                    let next = line + 1;
                    for i in 0..next_len {
                        self.lines[line][len + i] = self.lines[next][i];
                    }
                    self.lens[line] = len + next_len;
                    self.remove_line(next);
                }
            }
            return;
        }
        let mut i = col;
        while i + 1 < len { self.lines[line][i] = self.lines[line][i + 1]; i += 1; }
        self.lens[line] -= 1;
    }

    /// Split line at `col` (Enter key). Creates a new line below.
    pub fn split_line(&mut self, line: usize, col: usize) {
        if self.count >= MAX_LINES { return; }
        let len = self.lens[line];
        let col = col.min(len);
        // Shift all lines below down by one
        let mut i = self.count;
        while i > line + 1 {
            self.lines[i] = self.lines[i - 1];
            self.lens[i]  = self.lens[i - 1];
            i -= 1;
        }
        // New line = rest of current line after col
        let rest = len - col;
        for j in 0..rest {
            self.lines[line + 1][j] = self.lines[line][col + j];
        }
        self.lens[line + 1] = rest;
        // Truncate current line
        self.lens[line] = col;
        self.count += 1;
    }

    /// Remove line at `idx`, shifting subsequent lines up.
    pub fn remove_line(&mut self, idx: usize) {
        if self.count <= 1 { self.lens[0] = 0; return; }
        let count = self.count;
        for i in idx..count - 1 {
            self.lines[i] = self.lines[i + 1];
            self.lens[i]  = self.lens[i + 1];
        }
        self.count -= 1;
    }
}

// ── VGA color constants (attr byte = bg<<4 | fg) ──────────────────────────────

pub const CLR_TEXT:   u8 = 0x07; // LightGray on Black
pub const CLR_TITLE:  u8 = 0x1F; // White on Blue
pub const CLR_STATUS: u8 = 0x70; // Black on LightGray
pub const CLR_TILDE:  u8 = 0x08; // DarkGray on Black  (~ below text)
pub const CLR_INSERT: u8 = 0x2F; // White on Green     (vim INSERT mode)
pub const CLR_CMD:    u8 = 0x0E; // Yellow on Black    (vim command line)
