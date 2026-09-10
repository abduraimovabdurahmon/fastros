//! `cat` — print file contents to the terminal.
//!
//! Permission check: caller must have read permission on the file.

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;
use crate::kernel::users::permission::{self, MAY_READ};

pub struct CatCommand;
pub static CAT: CatCommand = CatCommand;

impl Command for CatCommand {
    fn name(&self) -> &'static str { "cat" }
    fn description(&self) -> &'static str { "Print file contents" }

    fn execute(&self, args: &[&[u8]], env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        if args.is_empty() {
            io.write_bytes(b"Usage: cat <file>\n");
            return 1;
        }

        let mut exit_code = 0;

        for &arg in args {
            let mut path_buf = [0u8; 256];
            let path = resolve(env.cwd(), arg, &mut path_buf);

            if super::virt_fs::is_dir(path) {
                io.write_bytes(b"cat: ");
                io.write_bytes(arg);
                io.write_bytes(b": Is a directory\n");
                exit_code = 1;
                continue;
            }

            // Permission check
            let (uid, gid, mode) = super::virt_fs::get_stat(path);
            if !permission::check(uid, gid, mode, env.euid(), env.egid(), MAY_READ) {
                io.write_bytes(b"cat: ");
                io.write_bytes(arg);
                io.write_bytes(b": Permission denied\n");
                exit_code = 1;
                continue;
            }

            match super::virt_fs::get_content(path) {
                Some(content) => { io.write_bytes(content); }
                None => {
                    io.write_bytes(b"cat: ");
                    io.write_bytes(arg);
                    io.write_bytes(b": No such file or directory\n");
                    exit_code = 1;
                }
            }
        }

        exit_code
    }
}

fn resolve<'a>(cwd: &[u8], path: &[u8], buf: &'a mut [u8; 256]) -> &'a [u8] {
    if path.first() == Some(&b'/') {
        let len = path.len().min(255);
        buf[..len].copy_from_slice(&path[..len]);
        return &buf[..len];
    }
    let mut len = 0;
    for &b in cwd { if len < 255 { buf[len] = b; len += 1; } }
    if cwd != b"/" && len < 255 { buf[len] = b'/'; len += 1; }
    for &b in path { if len < 255 { buf[len] = b; len += 1; } }
    &buf[..len]
}
