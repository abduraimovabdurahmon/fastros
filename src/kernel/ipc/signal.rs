//! UNIX-like Signals
//!
//! Asynchronous notifications sent to a process.
//! Examples: SIGKILL (9), SIGTERM (15), SIGSEGV (11), SIGCHLD (17).
//!
//! Delivery: checked at syscall return or interrupt return.
//! Handlers: default (kill/ignore/stop) or user-registered (sigaction).

pub const SIGHUP:  u8 = 1;
pub const SIGINT:  u8 = 2;
pub const SIGQUIT: u8 = 3;
pub const SIGILL:  u8 = 4;
pub const SIGTRAP: u8 = 5;
pub const SIGABRT: u8 = 6;
pub const SIGFPE:  u8 = 8;
pub const SIGKILL: u8 = 9;
pub const SIGSEGV: u8 = 11;
pub const SIGPIPE: u8 = 13;
pub const SIGTERM: u8 = 15;
pub const SIGCHLD: u8 = 17;
pub const SIGSTOP: u8 = 19;
pub const SIGCONT: u8 = 18;

// TODO: Implement signal mask (sigset_t), sigaction, signal delivery.
