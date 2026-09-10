//! `id` — print real and effective user/group IDs.
//!
//! Output mirrors Linux id(1):
//!   uid=0(root) gid=0(root) groups=0(root),4(adm),27(sudo)

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;
use crate::kernel::users;

pub struct IdCommand;
pub static ID: IdCommand = IdCommand;

impl Command for IdCommand {
    fn name(&self) -> &'static str { "id" }
    fn description(&self) -> &'static str { "Print user and group IDs" }

    fn execute(&self, _args: &[&[u8]], env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        let uid  = env.uid();
        let gid  = env.gid();
        let euid = env.euid();
        let egid = env.egid();

        let mut uname = [0u8; 32]; let un = users::uid_to_name(uid,  &mut uname);
        let mut gname = [0u8; 32]; let gn = users::gid_to_name(gid,  &mut gname);
        let mut ename = [0u8; 32]; let en = users::uid_to_name(euid, &mut ename);
        let mut egnam = [0u8; 32]; let eg = users::gid_to_name(egid, &mut egnam);

        // uid=N(name)
        io.write_bytes(b"uid="); write_id(io, uid); io.write_byte(b'('); io.write_bytes(&uname[..un]); io.write_byte(b')');
        io.write_bytes(b" gid="); write_id(io, gid); io.write_byte(b'('); io.write_bytes(&gname[..gn]); io.write_byte(b')');

        // euid/egid if different from real
        if euid != uid {
            io.write_bytes(b" euid="); write_id(io, euid); io.write_byte(b'('); io.write_bytes(&ename[..en]); io.write_byte(b')');
        }
        if egid != gid {
            io.write_bytes(b" egid="); write_id(io, egid); io.write_byte(b'('); io.write_bytes(&egnam[..eg]); io.write_byte(b')');
        }

        // groups=
        io.write_bytes(b" groups=");
        let mut group_ids = [0u32; 16];
        let gc = users::with_groups(|db| db.groups_for_uid(uid, &mut group_ids));
        if gc == 0 {
            write_id(io, gid); io.write_byte(b'('); io.write_bytes(&gname[..gn]); io.write_byte(b')');
        } else {
            for i in 0..gc {
                if i > 0 { io.write_byte(b','); }
                let gid2 = group_ids[i];
                let mut gn2 = [0u8; 32];
                let gl = users::gid_to_name(gid2, &mut gn2);
                write_id(io, gid2); io.write_byte(b'('); io.write_bytes(&gn2[..gl]); io.write_byte(b')');
            }
        }

        io.newline();
        0
    }
}

fn write_id(io: &mut dyn ShellIo, n: u32) {
    let mut buf = [0u8; 10];
    let mut len = 0;
    if n == 0 { io.write_byte(b'0'); return; }
    let mut v = n;
    while v > 0 { buf[len] = b'0' + (v % 10) as u8; v /= 10; len += 1; }
    for i in (0..len).rev() { io.write_byte(buf[i]); }
}
