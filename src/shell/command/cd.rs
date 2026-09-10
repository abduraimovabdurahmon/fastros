//! `cd` — change working directory.
//!
//! Validates against the virtual filesystem; updates `ShellEnv::cwd`.

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;

pub struct CdCommand;
pub static CD: CdCommand = CdCommand;

/// Known directories in the virtual FS.
const KNOWN_DIRS: &[&[u8]] = &[
    b"/", b"/bin", b"/dev", b"/etc", b"/proc", b"/sys", b"/tmp",
];

impl Command for CdCommand {
    fn name(&self) -> &'static str { "cd" }
    fn description(&self) -> &'static str { "Change working directory" }

    fn execute(&self, args: &[&[u8]], env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        let target = match args.first() {
            Some(t) => *t,
            None    => b"/",        // cd with no args → go to root
        };

        // Resolve to absolute path for validation
        let resolved = resolve_absolute(env.cwd(), target);

        if KNOWN_DIRS.iter().any(|d| *d == resolved.as_slice()) {
            if env.chdir(resolved.as_slice()) {
                return 0;
            }
        }

        // Handle ".." specially — always allow going up
        if target == b".." {
            env.chdir(b"..");
            return 0;
        }

        io.write_bytes(b"cd: ");
        io.write_bytes(target);
        io.write_bytes(b": No such directory\n");
        1
    }
}

/// Resolve a path to absolute without heap allocation.
/// Returns a fixed-size buffer (max 256 bytes) containing the resolved path.
fn resolve_absolute(cwd: &[u8], path: &[u8]) -> PathBuf {
    let mut buf = PathBuf::new();
    if path.first() == Some(&b'/') {
        buf.append(path);
    } else {
        buf.append(cwd);
        if cwd != b"/" {
            buf.push(b'/');
        }
        buf.append(path);
    }
    buf
}

/// Minimal fixed-size path buffer (no heap).
struct PathBuf {
    data: [u8; 256],
    len:  usize,
}
impl PathBuf {
    fn new() -> Self { Self { data: [0; 256], len: 0 } }
    fn push(&mut self, b: u8) {
        if self.len < 255 { self.data[self.len] = b; self.len += 1; }
    }
    fn append(&mut self, s: &[u8]) {
        for &b in s { self.push(b); }
    }
    fn as_slice(&self) -> &[u8] { &self.data[..self.len] }
}
