//! `groups` — print group memberships of the current user.

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;
use crate::kernel::users;

pub struct GroupsCommand;
pub static GROUPS: GroupsCommand = GroupsCommand;

impl Command for GroupsCommand {
    fn name(&self) -> &'static str { "groups" }
    fn description(&self) -> &'static str { "Print group memberships" }

    fn execute(&self, _args: &[&[u8]], env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        let uid = env.uid();
        let mut gids = [0u32; 16];
        let gc = users::with_groups(|db| db.groups_for_uid(uid, &mut gids));

        if gc == 0 {
            // At minimum show primary group
            let mut gname = [0u8; 32];
            let gn = users::gid_to_name(env.gid(), &mut gname);
            io.write_bytes(&gname[..gn]);
        } else {
            for i in 0..gc {
                if i > 0 { io.write_byte(b' '); }
                let mut gname = [0u8; 32];
                let gn = users::gid_to_name(gids[i], &mut gname);
                io.write_bytes(&gname[..gn]);
            }
        }
        io.newline();
        0
    }
}
