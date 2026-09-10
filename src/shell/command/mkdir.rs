//! `mkdir` — create directories.
//!
//! Usage:
//!   mkdir <dir>              — create one directory
//!   mkdir <dir1> <dir2> ...  — create multiple directories
//!   mkdir -p <dir>           — create directory and all missing parents
//!   mkdir -m <mode> <dir>    — accepted but mode is ignored (no real permissions)
//!
//! Error messages match Linux coreutils exactly:
//!   mkdir: cannot create directory 'foo': File exists
//!   mkdir: cannot create directory 'foo': No such file or directory
//!   mkdir: cannot create directory 'foo': No space left on device

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;
use crate::shell::memdir;

pub struct MkdirCommand;
pub static MKDIR: MkdirCommand = MkdirCommand;

impl Command for MkdirCommand {
    fn name(&self) -> &'static str { "mkdir" }
    fn description(&self) -> &'static str { "Create directories (-p: create with parents)" }

    fn execute(&self, args: &[&[u8]], env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        let mut create_parents = false;
        let mut skip_next      = false;
        let mut any_target     = false;
        let mut exit_code      = 0;

        for &arg in args {
            if skip_next { skip_next = false; continue; } // consumed by -m

            if arg.starts_with(b"-") && arg.len() > 1 {
                // Parse flags (may be combined, e.g. -pm)
                let flags = &arg[1..];
                let mut i = 0;
                while i < flags.len() {
                    match flags[i] {
                        b'p' => { create_parents = true; }
                        b'm' => {
                            // -m mode — consume the next token (we ignore the value)
                            if i + 1 < flags.len() {
                                // mode glued: -m755 — rest is the mode, done with flags
                                break;
                            } else {
                                skip_next = true;
                            }
                        }
                        b'v' => { /* -v verbose: we always stay quiet */ }
                        _ => {
                            io.write_bytes(b"mkdir: invalid option -- '");
                            io.write_byte(flags[i]);
                            io.write_bytes(b"'\n");
                            io.write_bytes(b"Usage: mkdir [-p] [-m mode] <dir>...\n");
                            return 1;
                        }
                    }
                    i += 1;
                }
                continue;
            }

            // Positional argument — directory to create
            any_target = true;
            let mut abs_buf = [0u8; 256];
            let abs = resolve_path(env.cwd(), arg, &mut abs_buf);

            let code = if create_parents {
                make_with_parents(abs, io)
            } else {
                make_one(abs, arg, io)
            };
            if code != 0 { exit_code = code; }
        }

        if !any_target {
            io.write_bytes(b"mkdir: missing operand\n");
            io.write_bytes(b"Usage: mkdir [-p] [-m mode] <dir>...\n");
            return 1;
        }

        exit_code
    }
}

// ── Core creation logic ───────────────────────────────────────────────────────

/// Create a single directory; returns 0 on success, 1 on error.
/// `display` is the original argument (used in error messages).
fn make_one(abs: &[u8], display: &[u8], io: &mut dyn ShellIo) -> i32 {
    // Already exists (virt_fs static tree OR memdir)?
    if super::virt_fs::is_dir(abs) {
        io.write_bytes(b"mkdir: cannot create directory '");
        io.write_bytes(display);
        io.write_bytes(b"': File exists\n");
        return 1;
    }

    // Is a memfs file?
    if crate::shell::memfs::exists(abs) {
        io.write_bytes(b"mkdir: cannot create directory '");
        io.write_bytes(display);
        io.write_bytes(b"': File exists\n");
        return 1;
    }

    // Parent must exist
    let parent = parent_of(abs);
    if !super::virt_fs::is_dir(parent) {
        io.write_bytes(b"mkdir: cannot create directory '");
        io.write_bytes(display);
        io.write_bytes(b"': No such file or directory\n");
        return 1;
    }

    if !memdir::create(abs) {
        io.write_bytes(b"mkdir: cannot create directory '");
        io.write_bytes(display);
        io.write_bytes(b"': No space left on device\n");
        return 1;
    }
    0
}

/// Create `abs` and all missing parent directories (mkdir -p).
/// Never errors on "already exists"; only errors on store-full.
fn make_with_parents(abs: &[u8], io: &mut dyn ShellIo) -> i32 {
    // Walk the path component by component, creating each missing dir.
    // Start from index 1 (skip the leading '/').
    let mut i = 1usize;
    let len = abs.len();

    loop {
        // Find the next '/' or end of string
        let end = {
            let mut j = i;
            while j < len && abs[j] != b'/' { j += 1; }
            j
        };

        let segment = &abs[..end]; // e.g. "/home" or "/home/user"
        if segment.is_empty() || segment == b"/" {
            if end >= len { break; }
            i = end + 1;
            continue;
        }

        // Only try to create if it doesn't already exist
        if !super::virt_fs::is_dir(segment) && !crate::shell::memfs::exists(segment) {
            if !memdir::create(segment) {
                io.write_bytes(b"mkdir: cannot create directory '");
                io.write_bytes(segment);
                io.write_bytes(b"': No space left on device\n");
                return 1;
            }
        }

        if end >= len { break; }
        i = end + 1;
    }
    0
}

// ── Path helpers ──────────────────────────────────────────────────────────────

/// Resolve `path` against `cwd` into `buf`. Returns slice of buf.
fn resolve_path<'a>(cwd: &[u8], path: &[u8], buf: &'a mut [u8; 256]) -> &'a [u8] {
    if path.first() == Some(&b'/') {
        let n = path.len().min(255);
        buf[..n].copy_from_slice(&path[..n]);
        return &buf[..n];
    }
    let mut n = 0usize;
    for &b in cwd  { if n < 255 { buf[n] = b; n += 1; } }
    if cwd != b"/" && n < 255 { buf[n] = b'/'; n += 1; }
    for &b in path { if n < 255 { buf[n] = b; n += 1; } }
    &buf[..n]
}

/// Return the parent directory of `path`.
/// "/a/b/c" → "/a/b",  "/a" → "/",  "/" → "/"
fn parent_of(path: &[u8]) -> &[u8] {
    if path == b"/" { return b"/"; }
    match path.iter().rposition(|&b| b == b'/') {
        None | Some(0) => b"/",
        Some(i)        => &path[..i],
    }
}
