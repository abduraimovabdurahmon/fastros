//! `chown` — change file owner and/or group.
//!
//! Usage:
//!   chown user file          — change owner
//!   chown user:group file    — change owner and group
//!   chown :group file        — change group only
//!   chown -R user dir/       — recursive
//!
//! Only root can change file ownership (mirrors Linux).

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;
use crate::kernel::users;
use crate::shell::memfs;
use crate::shell::memdir;

pub struct ChownCommand;
pub static CHOWN: ChownCommand = ChownCommand;

impl Command for ChownCommand {
    fn name(&self) -> &'static str { "chown" }
    fn description(&self) -> &'static str { "Change file owner and group" }

    fn execute(&self, args: &[&[u8]], env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        let mut recursive = false;
        let mut spec:  &[u8] = b"";
        let mut paths: [&[u8]; 16] = [b""; 16];
        let mut pc = 0usize;
        let mut spec_set = false;

        for &arg in args {
            if arg == b"-R" || arg == b"-r" { recursive = true; continue; }
            if !spec_set { spec = arg; spec_set = true; }
            else if pc < 16 { paths[pc] = arg; pc += 1; }
        }

        if !spec_set || pc == 0 {
            io.write_bytes(b"Usage: chown [-R] user[:group] <file>...\n");
            return 1;
        }

        if !env.is_root() {
            io.write_bytes(b"chown: Permission denied (must be root)\n");
            return 1;
        }

        // Parse "user", "user:group", ":group"
        let (user_part, group_part) = match spec.iter().position(|&b| b == b':') {
            None    => (spec, b"" as &[u8]),
            Some(i) => (&spec[..i], &spec[i + 1..]),
        };

        let new_uid: Option<u32> = if user_part.is_empty() {
            None
        } else {
            match users::with_users(|db| db.find_by_name(user_part).map(|u| u.uid)) {
                Some(uid) => Some(uid),
                None => {
                    // Try numeric
                    parse_u32(user_part).or_else(|| {
                        io.write_bytes(b"chown: invalid user: '");
                        io.write_bytes(user_part);
                        io.write_bytes(b"'\n");
                        None
                    })
                }
            }
        };

        let new_gid: Option<u32> = if group_part.is_empty() {
            None
        } else {
            match users::with_groups(|db| db.find_by_name(group_part).map(|g| g.gid)) {
                Some(gid) => Some(gid),
                None => {
                    parse_u32(group_part).or_else(|| {
                        io.write_bytes(b"chown: invalid group: '");
                        io.write_bytes(group_part);
                        io.write_bytes(b"'\n");
                        None
                    })
                }
            }
        };

        let mut exit_code = 0;
        for i in 0..pc {
            let mut buf = [0u8; 256];
            let abs = resolve(env.cwd(), paths[i], &mut buf);
            let code = do_chown(abs, paths[i], new_uid, new_gid, io, recursive);
            if code != 0 { exit_code = code; }
        }
        exit_code
    }
}

fn do_chown(abs: &[u8], display: &[u8], new_uid: Option<u32>, new_gid: Option<u32>,
            io: &mut dyn ShellIo, recursive: bool) -> i32 {
    let (old_uid, old_gid, _) = super::virt_fs::get_stat(abs);
    let uid = new_uid.unwrap_or(old_uid);
    let gid = new_gid.unwrap_or(old_gid);

    let is_dir = super::virt_fs::is_dir(abs);
    let changed = if is_dir {
        memdir::set_owner(abs, uid, gid)
    } else {
        memfs::set_owner(abs, uid, gid)
    };

    if !changed {
        io.write_bytes(b"chown: cannot access '");
        io.write_bytes(display);
        io.write_bytes(b"': No such file or directory\n");
        return 1;
    }

    if recursive && is_dir {
        let mut dirs = [b"" as &'static [u8]; 32];
        let dc = memdir::list(&mut dirs);
        for i in 0..dc {
            if dirs[i].starts_with(abs) && dirs[i] != abs {
                memdir::set_owner(dirs[i], uid, gid);
            }
        }
        let mut files = [b"" as &'static [u8]; 16];
        let fc = memfs::list(&mut files);
        for i in 0..fc {
            if files[i].starts_with(abs) {
                memfs::set_owner(files[i], uid, gid);
            }
        }
    }
    0
}

fn parse_u32(s: &[u8]) -> Option<u32> {
    let mut n = 0u32;
    for &b in s {
        if b < b'0' || b > b'9' { return None; }
        n = n.saturating_mul(10).saturating_add((b - b'0') as u32);
    }
    Some(n)
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
