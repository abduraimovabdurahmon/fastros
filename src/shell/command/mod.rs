//! Shell command subsystem

pub mod cat;
pub mod cd;
pub mod chmod;
pub mod chown;
pub mod editor;
pub mod exit;
pub mod groups;
pub mod history;
pub mod htop;
pub mod id;
pub mod ifconfig;
pub mod mkdir;
pub mod nano;
pub mod netstat;
pub mod passwd;
pub mod ping;
pub mod rm;
pub mod su;
pub mod sshd;
pub mod sudo;
pub mod useradd;
pub mod userdel;
pub mod vim;
pub mod virt_fs;
pub mod whoami;
pub mod clear;
pub mod echo;
pub mod help;
pub mod ls;
pub mod mem;
pub mod ps;
pub mod reboot;
pub mod uname;
pub mod uptime;

use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;

pub trait Command: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn execute(&self, args: &[&[u8]], env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32;
}

pub const MAX_COMMANDS: usize = 56;

pub struct CommandRegistry {
    entries: [Option<&'static dyn Command>; MAX_COMMANDS],
    count:   usize,
}

impl CommandRegistry {
    pub const fn empty() -> Self {
        Self { entries: [None; MAX_COMMANDS], count: 0 }
    }

    pub fn register(&mut self, cmd: &'static dyn Command) {
        if self.count < MAX_COMMANDS {
            self.entries[self.count] = Some(cmd);
            self.count += 1;
        }
    }

    pub fn find(&self, name: &[u8]) -> Option<&'static dyn Command> {
        for i in 0..self.count {
            if let Some(cmd) = self.entries[i] {
                if cmd.name().as_bytes() == name { return Some(cmd); }
            }
        }
        None
    }

    pub fn iter(&self) -> impl Iterator<Item = &'static dyn Command> + '_ {
        self.entries[..self.count].iter().filter_map(|e| *e)
    }

    pub fn init() -> Self {
        let mut r = Self::empty();
        // Core utils
        r.register(&help::HELP);
        r.register(&clear::CLEAR);
        r.register(&echo::ECHO);
        r.register(&uname::UNAME);
        r.register(&uptime::UPTIME);
        r.register(&reboot::REBOOT);
        r.register(&exit::EXIT);
        // Process / memory
        r.register(&ps::PS);
        r.register(&mem::MEM);
        r.register(&htop::HTOP);
        // Filesystem
        r.register(&ls::LS);
        r.register(&cd::CD);
        r.register(&cat::CAT);
        r.register(&mkdir::MKDIR);
        r.register(&rm::RM);
        r.register(&chmod::CHMOD);
        r.register(&chown::CHOWN);
        // Editors
        r.register(&nano::NANO);
        r.register(&vim::VIM);
        // User management
        r.register(&whoami::WHOAMI);
        r.register(&id::ID);
        r.register(&groups::GROUPS);
        r.register(&su::SU);
        r.register(&sudo::SUDO);
        r.register(&useradd::USERADD);
        r.register(&userdel::USERDEL);
        r.register(&passwd::PASSWD);
        // Networking
        r.register(&ping::PING);
        r.register(&ifconfig::IFCONFIG);
        r.register(&netstat::NETSTAT);
        r.register(&sshd::SSHD);
        // History
        r.register(&history::HISTORY);
        r
    }
}
