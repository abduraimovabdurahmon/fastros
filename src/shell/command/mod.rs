//! Shell command subsystem
//!
//! Design principles:
//!   • Each command is a zero-sized unit struct in its own file.
//!   • All commands implement the `Command` trait.
//!   • Commands interact with the world ONLY through `ShellIo` and `ShellEnv`.
//!   • No command imports VGA, serial, or keyboard directly.
//!   • Adding a new command = create a file + add one line in CommandRegistry::init().
//!
//! Command files:
//!   help.rs   — list all commands
//!   clear.rs  — clear screen
//!   echo.rs   — print arguments
//!   mem.rs    — physical memory stats
//!   uname.rs  — kernel version info
//!   uptime.rs — elapsed ticks since boot
//!   reboot.rs — reset the machine
//!   ps.rs     — list kernel processes
//!   ls.rs     — list directory contents (virtual FS view)
//!   cd.rs     — change working directory
//!   exit.rs   — ACPI power-off (shuts down QEMU)

pub mod cd;
pub mod exit;
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

// ── Command trait ─────────────────────────────────────────────────────────────

/// Every shell command implements this trait.
///
/// Object-safe: all methods take `&self` (commands are stateless unit structs).
pub trait Command: Send + Sync {
    /// The name the user types (e.g. `"ls"`).
    fn name(&self) -> &'static str;

    /// One-line description shown by `help`.
    fn description(&self) -> &'static str;

    /// Execute the command.
    ///
    /// `args` — slice of argument tokens (does NOT include the command name).
    /// Returns an exit code (0 = success, non-zero = error).
    fn execute(&self, args: &[&[u8]], env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32;
}

// ── CommandRegistry ───────────────────────────────────────────────────────────

/// Maximum number of simultaneously registered commands.
pub const MAX_COMMANDS: usize = 32;

/// Static registry of all available commands.
///
/// Commands are `&'static dyn Command` — each command is a static singleton.
/// Registered at boot time; never mutated afterwards.
pub struct CommandRegistry {
    entries: [Option<&'static dyn Command>; MAX_COMMANDS],
    count:   usize,
}

impl CommandRegistry {
    pub const fn empty() -> Self {
        Self { entries: [None; MAX_COMMANDS], count: 0 }
    }

    /// Register a command. Silently ignores if the registry is full.
    pub fn register(&mut self, cmd: &'static dyn Command) {
        if self.count < MAX_COMMANDS {
            self.entries[self.count] = Some(cmd);
            self.count += 1;
        }
    }

    /// Look up a command by name.  O(n) — registry is small.
    pub fn find(&self, name: &[u8]) -> Option<&'static dyn Command> {
        for i in 0..self.count {
            if let Some(cmd) = self.entries[i] {
                if cmd.name().as_bytes() == name {
                    return Some(cmd);
                }
            }
        }
        None
    }

    /// Iterate over all registered commands.
    pub fn iter(&self) -> impl Iterator<Item = &'static dyn Command> + '_ {
        self.entries[..self.count]
            .iter()
            .filter_map(|e| *e)
    }

    /// Build and return the populated registry.
    pub fn init() -> Self {
        let mut r = Self::empty();
        r.register(&help::HELP);
        r.register(&clear::CLEAR);
        r.register(&echo::ECHO);
        r.register(&mem::MEM);
        r.register(&uname::UNAME);
        r.register(&uptime::UPTIME);
        r.register(&reboot::REBOOT);
        r.register(&ps::PS);
        r.register(&ls::LS);
        r.register(&cd::CD);
        r.register(&exit::EXIT);
        r
    }
}
