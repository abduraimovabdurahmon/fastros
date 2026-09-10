//! `rm` — remove files and directories.
//!
//! Usage:
//!   rm file              — remove a file
//!   rm -r dir/           — remove directory recursively
//!   rm -f file           — force (no error if not found)
//!   rm -rf dir/          — force recursive removal
//!
//! Permission model (mirrors Linux):
//!   To remove a file, the caller needs WRITE permission on the PARENT directory.
//!   The file's own permissions are irrelevant (root can remove anything).
//!   Exception: sticky bit (0o1000) on parent means only owner can delete.

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;
use crate::shell::memfs;
use crate::shell::memdir;
use crate::kernel::users::permission::{self, MAY_WRITE};

pub struct RmCommand;
pub static RM: RmCommand = RmCommand;

impl Command for RmCommand {
    fn name(&self) -> &'static str { "rm" }
    fn description(&self) -> &'static str { "Remove files or directories (-r recursive, -f force)" }

    fn execute(&self, args: &[&[u8]], env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        let mut recursive = false;
        let mut force     = false;
        let mut paths: [&[u8]; 32] = [b""; 32];
        let mut pc = 0usize;

        for &arg in args {
            if arg.starts_with(b"-") {
                for &c in &arg[1..] {
                    match c {
                        b'r' | b'R' => { recursive = true; }
                        b'f'        => { force     = true; }
                        _ => {}
                    }
                }
            } else if pc < 32 {
                paths[pc] = arg;
                pc += 1;
            }
        }

        if pc == 0 {
            if !force {
                io.write_bytes(b"rm: missing operand\nUsage: rm [-r] [-f] <file>...\n");
            }
            return if force { 0 } else { 1 };
        }

        let mut exit_code = 0;
        for i in 0..pc {
            let mut buf = [0u8; 256];
            let abs = resolve(env.cwd(), paths[i], &mut buf);
            let code = do_rm(abs, paths[i], env, io, recursive, force);
            if code != 0 && !force { exit_code = code; }
        }
        exit_code
    }
}

fn do_rm(abs: &[u8], display: &[u8], env: &ShellEnv, io: &mut dyn ShellIo,
         recursive: bool, force: bool) -> i32 {

    let is_dir = super::virt_fs::is_dir(abs);

    // Check if it's a static virt_fs entry (cannot delete)
    if super::virt_fs::lookup(abs).is_some() {
        if !force {
            io.write_bytes(b"rm: cannot remove '");
            io.write_bytes(display);
            io.write_bytes(b"': Operation not permitted\n");
        }
        return 1;
    }

    if is_dir {
        if !recursive {
            io.write_bytes(b"rm: cannot remove '");
            io.write_bytes(display);
            io.write_bytes(b"': Is a directory (use -r)\n");
            return 1;
        }
        return rm_dir(abs, display, env, io, force);
    }

    // It's a file — check write permission on parent dir
    let parent = parent_of(abs);
    let (puid, pgid, pmode) = super::virt_fs::get_stat(parent);

    if !permission::check(puid, pgid, pmode, env.euid(), env.egid(), MAY_WRITE) {
        if !force {
            io.write_bytes(b"rm: cannot remove '");
            io.write_bytes(display);
            io.write_bytes(b"': Permission denied\n");
        }
        return 1;
    }

    // Sticky bit check: only owner or root can delete in sticky directories
    if pmode & 0o1000 != 0 && env.euid() != 0 {
        let (fuid, _, _) = super::virt_fs::get_stat(abs);
        if env.euid() != fuid && env.euid() != puid {
            if !force {
                io.write_bytes(b"rm: cannot remove '");
                io.write_bytes(display);
                io.write_bytes(b"': Operation not permitted\n");
            }
            return 1;
        }
    }

    if !memfs::remove(abs) {
        if !force {
            io.write_bytes(b"rm: cannot remove '");
            io.write_bytes(display);
            io.write_bytes(b"': No such file or directory\n");
        }
        return if force { 0 } else { 1 };
    }
    0
}

fn rm_dir(abs: &[u8], display: &[u8], env: &ShellEnv, io: &mut dyn ShellIo, force: bool) -> i32 {
    // Check write on parent
    let parent = parent_of(abs);
    let (puid, pgid, pmode) = super::virt_fs::get_stat(parent);
    if !permission::check(puid, pgid, pmode, env.euid(), env.egid(), MAY_WRITE) {
        if !force {
            io.write_bytes(b"rm: cannot remove '");
            io.write_bytes(display);
            io.write_bytes(b"': Permission denied\n");
        }
        return 1;
    }

    // Remove all memfs files under this dir
    let mut file_paths = [b"" as &'static [u8]; 16];
    let fc = memfs::list(&mut file_paths);
    for i in 0..fc {
        if file_paths[i].starts_with(abs) {
            memfs::remove(file_paths[i]);
        }
    }

    // Remove all memdir entries under this dir (recursively), then the dir itself
    memdir::remove_recursive(abs);
    memdir::remove(abs);
    0
}

fn parent_of(path: &[u8]) -> &[u8] {
    if path == b"/" { return b"/"; }
    match path.iter().rposition(|&b| b == b'/') {
        None | Some(0) => b"/",
        Some(i)        => &path[..i],
    }
}

fn resolve<'a>(cwd: &[u8], path: &[u8], buf: &'a mut [u8; 256]) -> &'a [u8] {
    if path.first() == Some(&b'/') {
        let n = path.len().min(255); buf[..n].copy_from_slice(&path[..n]); return &buf[..n];
    }
    let mut n = 0;
    for &b in cwd  { if n < 255 { buf[n] = b; n += 1; } }
    if cwd != b"/" && n < 255 { buf[n] = b'/'; n += 1; }
    for &b in path { if n < 255 { buf[n] = b; n += 1; } }
    &buf[..n]
}
