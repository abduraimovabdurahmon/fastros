//! Shell environment state
//!
//! Tracks everything the shell needs between commands:
//!   - current working directory (cwd)
//!   - current user session (uid, gid, euid, egid, home)
//!   - last command exit code
//!
//! No I/O, no arch, no kernel imports — pure data.

pub const CWD_MAX:  usize = 256;
pub const HOME_MAX: usize = 64;

pub struct ShellEnv {
    // ── Working directory ──────────────────────────────────────────────────────
    cwd:     [u8; CWD_MAX],
    cwd_len: usize,

    // ── User session (mirrors Linux struct cred) ───────────────────────────────
    uid:     u32,   // real user ID
    gid:     u32,   // real group ID
    euid:    u32,   // effective user ID  (sudo sets this to 0 temporarily)
    egid:    u32,   // effective group ID
    home:    [u8; HOME_MAX],
    home_len: usize,
    username: [u8; 32],
    uname_len: usize,

    /// Exit code of the last command (0 = success).
    pub last_exit: i32,
}

impl ShellEnv {
    pub const fn new() -> Self {
        let mut cwd = [0u8; CWD_MAX];
        cwd[0] = b'/';
        let mut home = [0u8; HOME_MAX];
        // default home = /root (root user)
        home[0] = b'/'; home[1] = b'r'; home[2] = b'o'; home[3] = b'o'; home[4] = b't';
        let mut username = [0u8; 32];
        username[0] = b'r'; username[1] = b'o'; username[2] = b'o'; username[3] = b't';
        Self {
            cwd, cwd_len: 1,
            uid: 0, gid: 0, euid: 0, egid: 0,
            home, home_len: 5,
            username, uname_len: 4,
            last_exit: 0,
        }
    }

    // ── CWD ───────────────────────────────────────────────────────────────────

    pub fn cwd(&self) -> &[u8] { &self.cwd[..self.cwd_len] }

    pub fn chdir(&mut self, path: &[u8]) -> bool {
        if path.is_empty() { return false; }

        // cd ~ or cd with no args → home
        if path == b"~" || path == b"" {
            let hn = self.home_len;
            self.cwd[..hn].copy_from_slice(&self.home[..hn]);
            self.cwd_len = hn;
            return true;
        }

        // cd ~/... → home + rest
        if path.len() >= 2 && path[0] == b'~' && path[1] == b'/' {
            let rest = &path[2..];
            let hn = self.home_len;
            let total = hn + 1 + rest.len();
            if total >= CWD_MAX { return false; }
            self.cwd[..hn].copy_from_slice(&self.home[..hn]);
            self.cwd[hn] = b'/';
            self.cwd[hn + 1..total].copy_from_slice(rest);
            self.cwd_len = total;
            return true;
        }

        if path == b"/" {
            self.cwd[0] = b'/';
            self.cwd_len = 1;
            return true;
        }

        if path == b".." {
            if self.cwd_len <= 1 { return true; }
            let mut i = self.cwd_len - 1;
            while i > 0 && self.cwd[i] != b'/' { i -= 1; }
            self.cwd_len = if i == 0 { 1 } else { i };
            return true;
        }

        let new_path: &[u8] = if path[0] == b'/' {
            path
        } else {
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
        let sep = if self.cwd_len > 1 { 1 } else { 0 };
        let needed = self.cwd_len + sep + seg.len();
        if needed >= CWD_MAX { return false; }
        if sep == 1 { self.cwd[self.cwd_len] = b'/'; }
        let base = self.cwd_len + sep;
        self.cwd[base..base + seg.len()].copy_from_slice(seg);
        self.cwd_len = needed;
        true
    }

    // ── Session ───────────────────────────────────────────────────────────────

    pub fn uid(&self)  -> u32 { self.uid  }
    pub fn gid(&self)  -> u32 { self.gid  }
    pub fn euid(&self) -> u32 { self.euid }
    pub fn egid(&self) -> u32 { self.egid }
    pub fn home(&self) -> &[u8] { &self.home[..self.home_len] }
    pub fn username(&self) -> &[u8] { &self.username[..self.uname_len] }

    /// True if running with root privileges (euid == 0).
    pub fn is_root(&self) -> bool { self.euid == 0 }

    /// Update session after login or su.
    pub fn set_session(&mut self, uid: u32, gid: u32, home: &[u8], username: &[u8]) {
        self.uid  = uid;
        self.gid  = gid;
        self.euid = uid;
        self.egid = gid;

        let hn = home.len().min(HOME_MAX);
        self.home[..hn].copy_from_slice(&home[..hn]);
        self.home_len = hn;

        let un = username.len().min(32);
        self.username[..un].copy_from_slice(&username[..un]);
        self.uname_len = un;

        // cd to home directory after session switch
        self.cwd[..hn].copy_from_slice(&home[..hn]);
        self.cwd_len = hn;
    }

    /// Temporarily elevate to root (sudo). Returns old euid.
    pub fn elevate_root(&mut self) -> u32 {
        let old = self.euid;
        self.euid = 0;
        self.egid = 0;
        old
    }

    /// Restore euid after sudo elevation.
    pub fn restore_euid(&mut self, old_euid: u32) {
        self.euid = old_euid;
        self.egid = self.gid;
    }
}
