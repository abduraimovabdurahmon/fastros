//! `useradd` — create a new user account.
//!
//! Usage:
//!   useradd username
//!   useradd -m username          — create home directory (default behaviour)
//!   useradd -m -s /bin/sh user   — specify shell
//!   useradd -u 1001 -g users user — specify uid/gid
//!
//! Only root (euid==0) may create users.
//! Creates /home/username with mode 0700.
//! Adds default .bashrc and .profile in the new home.

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;
use crate::kernel::users;
use crate::kernel::users::permission::MODE_HOME;
use crate::shell::memdir;
use crate::shell::memfs;

pub struct UseraддCommand;
pub static USERADD: UseraддCommand = UseraддCommand;

impl Command for UseraддCommand {
    fn name(&self) -> &'static str { "useradd" }
    fn description(&self) -> &'static str { "Create a new user account" }

    fn execute(&self, args: &[&[u8]], env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        if !env.is_root() {
            io.write_bytes(b"useradd: Permission denied (must be root)\n");
            return 1;
        }
        if args.is_empty() {
            io.write_bytes(b"Usage: useradd [-m] [-s shell] [-u uid] [-g gid] <username>\n");
            return 1;
        }

        // Parse args
        let mut username:  &[u8] = b"";
        let mut shell:     &[u8] = b"/bin/sh";
        let mut custom_uid: Option<u32> = None;
        let mut custom_gid: Option<u32> = None;
        let mut i = 0;
        while i < args.len() {
            let a = args[i];
            match a {
                b"-m" | b"--create-home" => {}           // default; always create home
                b"-s" => { i += 1; if i < args.len() { shell = args[i]; } }
                b"-u" => { i += 1; if i < args.len() { custom_uid = parse_u32(args[i]); } }
                b"-g" => { i += 1; if i < args.len() { custom_gid = parse_u32(args[i]); } }
                b"-r" => {}  // system account — accept but ignore
                b"-M" => {}  // no-home — we create home anyway for simplicity
                _ if !a.starts_with(b"-") => { username = a; }
                _ => {}
            }
            i += 1;
        }

        if username.is_empty() {
            io.write_bytes(b"useradd: missing username\n");
            return 1;
        }
        if username.len() > 32 {
            io.write_bytes(b"useradd: username too long\n");
            return 1;
        }

        // Determine uid/gid
        let uid = custom_uid.unwrap_or_else(|| users::with_users(|db| db.next_uid()));
        let gid = custom_gid.unwrap_or_else(|| users::with_groups(|db| db.next_gid()));

        // Build home path: /home/username
        let mut home = [0u8; 64];
        let mut hlen = 0;
        for &b in b"/home/" { home[hlen] = b; hlen += 1; }
        let un = username.len().min(57);
        home[hlen..hlen + un].copy_from_slice(&username[..un]);
        hlen += un;
        let home_slice = &home[..hlen];

        // Add to user database (password = "", locked until passwd is set)
        let ok = users::with_users_mut(|db| {
            db.add(uid, gid, username, b"", home_slice, shell)
        });
        if !ok {
            io.write_bytes(b"useradd: user '");
            io.write_bytes(username);
            io.write_bytes(b"' already exists or table full\n");
            return 1;
        }

        // Create primary group with same name as user (Linux useradd default)
        users::with_groups_mut(|db| {
            db.add(gid, username);
            db.add_member(gid, uid);
            // Also add to 'users' group (gid=100)
            db.add_member(100, uid);
        });

        // Create home directory: /home/username (mode 0700, owned by new user)
        if !memdir::create_owned(home_slice, uid, gid, MODE_HOME) {
            // Already exists (fine)
        }

        // Populate home with skeleton files (like /etc/skel in Linux)
        create_skel(home_slice, hlen, username, uid, gid);

        io.write_bytes(b"useradd: user '");
        io.write_bytes(username);
        io.write_bytes(b"' created with uid=");
        write_u32(io, uid);
        io.write_bytes(b" gid=");
        write_u32(io, gid);
        io.write_bytes(b" home=");
        io.write_bytes(home_slice);
        io.newline();
        io.write_bytes(b"useradd: set password with 'passwd ");
        io.write_bytes(username);
        io.write_bytes(b"'\n");
        0
    }
}

/// Create skeleton files in the new home directory.
fn create_skel(home: &[u8], hlen: usize, username: &[u8], uid: u32, gid: u32) {
    let mut path = [0u8; 128];

    // ~/.bashrc
    let file = b"/.bashrc";
    path[..hlen].copy_from_slice(home);
    path[hlen..hlen + file.len()].copy_from_slice(file);
    let bashrc_content = b"# ~/.bashrc\nexport PS1='\\u@fastros:\\w\\$ '\nexport PATH=/bin:/usr/bin:/usr/local/bin\n";
    memfs::write_owned(&path[..hlen + file.len()], bashrc_content, uid, gid, 0o644);

    // ~/.profile
    let file2 = b"/.profile";
    path[hlen..hlen + file2.len()].copy_from_slice(file2);
    let profile = b"# ~/.profile\n[ -f ~/.bashrc ] && . ~/.bashrc\n";
    memfs::write_owned(&path[..hlen + file2.len()], profile, uid, gid, 0o644);

    let _ = username;
}

fn parse_u32(s: &[u8]) -> Option<u32> {
    let mut n = 0u32;
    for &b in s {
        if b < b'0' || b > b'9' { return None; }
        n = n.saturating_mul(10).saturating_add((b - b'0') as u32);
    }
    Some(n)
}

fn write_u32(io: &mut dyn ShellIo, mut n: u32) {
    if n == 0 { io.write_byte(b'0'); return; }
    let mut buf = [0u8; 10];
    let mut len = 0;
    while n > 0 { buf[len] = b'0' + (n % 10) as u8; n /= 10; len += 1; }
    for i in (0..len).rev() { io.write_byte(buf[i]); }
}
