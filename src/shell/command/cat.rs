//! `cat` — print file contents to the terminal.
//!
//! Reads from the virtual file store (virt_fs::get_content).
//! No real disk I/O yet; all content is static.

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;

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
            // Resolve relative path against CWD
            let mut path_buf = [0u8; 256];
            let path = resolve(env.cwd(), arg, &mut path_buf);

            if super::virt_fs::is_dir(path) {
                io.write_bytes(b"cat: ");
                io.write_bytes(arg);
                io.write_bytes(b": Is a directory\n");
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

/// Resolve `path` against `cwd` into `buf`. Returns slice into `buf`.
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
