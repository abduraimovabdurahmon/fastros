//! Shell environment state
//!
//! Pure data — no I/O, no arch, no kernel imports.
//! Everything the shell needs to track between commands.

/// Maximum CWD path length.
pub const CWD_MAX: usize = 256;

/// Shell runtime environment.
/// Passed (by mutable reference) to every command handler.
pub struct ShellEnv {
    /// Current working directory — null-terminated byte string.
    cwd:      [u8; CWD_MAX],
    cwd_len:  usize,
    /// Exit code of the last command (0 = success).
    pub last_exit: i32,
}

impl ShellEnv {
    pub const fn new() -> Self {
        let mut cwd = [0u8; CWD_MAX];
        cwd[0] = b'/';
        Self { cwd, cwd_len: 1, last_exit: 0 }
    }

    /// Current working directory as a byte slice (no null terminator).
    pub fn cwd(&self) -> &[u8] {
        &self.cwd[..self.cwd_len]
    }

    /// Attempt to change directory.
    /// Returns `false` if the path is not recognised.
    pub fn chdir(&mut self, path: &[u8]) -> bool {
        if path.is_empty() {
            return false;
        }
        if path == b"/" {
            self.cwd[0] = b'/';
            self.cwd_len = 1;
            return true;
        }
        // Handle ".." — go up one level
        if path == b".." {
            if self.cwd_len <= 1 { return true; } // already at root
            let mut i = self.cwd_len - 1;
            while i > 0 && self.cwd[i] != b'/' { i -= 1; }
            self.cwd_len = if i == 0 { 1 } else { i };
            return true;
        }
        // Absolute path
        let new_path = if path[0] == b'/' {
            path
        } else {
            // Build absolute: CWD + '/' + path
            return self.append_segment(path);
        };
        if new_path.len() < CWD_MAX {
            self.cwd[..new_path.len()].copy_from_slice(new_path);
            self.cwd_len = new_path.len();
            return true;
        }
        false
    }

    fn append_segment(&mut self, seg: &[u8]) -> bool {
        let sep = if self.cwd_len > 1 { 1 } else { 0 }; // add '/' if not root
        let needed = self.cwd_len + sep + seg.len();
        if needed >= CWD_MAX { return false; }
        if sep == 1 { self.cwd[self.cwd_len] = b'/'; }
        let base = self.cwd_len + sep;
        self.cwd[base..base + seg.len()].copy_from_slice(seg);
        self.cwd_len = needed;
        true
    }
}
