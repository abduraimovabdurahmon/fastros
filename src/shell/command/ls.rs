//! `ls` — list directory contents.
//!
//! Virtual filesystem view (tmpfs/VFS not fully mounted yet).
//! Shows the logical directory tree that will be backed by real inodes
//! once fs::tmpfs is wired to the VFS mount table.

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;

pub struct LsCommand;
pub static LS: LsCommand = LsCommand;

/// Static virtual directory entries.
/// Each entry: (path, &[child names])
const VIRT_FS: &[(&[u8], &[&[u8]])] = &[
    (b"/",      &[b"bin", b"dev", b"etc", b"proc", b"sys", b"tmp"]),
    (b"/bin",   &[b"sh", b"ls", b"echo", b"cat"]),
    (b"/dev",   &[b"null", b"zero", b"tty0", b"serial0"]),
    (b"/etc",   &[b"hostname", b"os-release"]),
    (b"/proc",  &[b"cpuinfo", b"meminfo", b"version", b"uptime"]),
    (b"/sys",   &[b"kernel", b"devices"]),
    (b"/tmp",   &[]),
];

impl Command for LsCommand {
    fn name(&self) -> &'static str { "ls" }
    fn description(&self) -> &'static str { "List directory contents" }

    fn execute(&self, args: &[&[u8]], env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        // Determine target path
        let target: &[u8] = if args.is_empty() {
            env.cwd()
        } else {
            args[0]
        };

        // Find the virtual directory
        for &(path, children) in VIRT_FS {
            if path == target {
                if children.is_empty() {
                    io.write_bytes(b"(empty)\n");
                } else {
                    for name in children.iter() {
                        io.write_bytes(name);
                        io.write_bytes(b"  ");
                    }
                    io.newline();
                }
                return 0;
            }
        }

        // Not found
        io.write_bytes(b"ls: ");
        io.write_bytes(target);
        io.write_bytes(b": No such directory\n");
        1
    }
}
