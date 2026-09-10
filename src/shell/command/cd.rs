//! `cd` — change working directory.
//!
//! Validates against the virtual filesystem table in `virt_fs`.

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;

pub struct CdCommand;
pub static CD: CdCommand = CdCommand;

impl Command for CdCommand {
    fn name(&self) -> &'static str { "cd" }
    fn description(&self) -> &'static str { "Change working directory" }

    fn execute(&self, args: &[&[u8]], env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        let target = match args.first() {
            Some(t) => *t,
            None    => b"/",    // cd with no args → root
        };

        // Handle ".." — go up one level without full resolution
        if target == b".." {
            env.chdir(b"..");
            return 0;
        }

        let resolved = resolve_absolute(env.cwd(), target);

        if super::virt_fs::is_dir(resolved.as_slice()) {
            env.chdir(resolved.as_slice());
            return 0;
        }

        io.write_bytes(b"cd: ");
        io.write_bytes(target);
        io.write_bytes(b": No such directory\n");
        1
    }
}

/// Resolve `path` against `cwd` into an absolute path (no heap, max 256 B).
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
