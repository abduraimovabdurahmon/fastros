//! Command executor
//!
//! Responsibility: given a `ParsedCommand` and a `CommandRegistry`,
//! look up the command handler and call it.
//!
//! This layer knows nothing about I/O implementation or line editing.
//! It is the boundary between "what the user typed" and "what runs".

use crate::shell::command::CommandRegistry;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;
use crate::shell::parser::{ParsedCommand, MAX_ARGS};

/// Execute `cmd` against `registry`.
///
/// Returns the command's exit code, or -1 if the command was not found.
pub fn execute(
    cmd: &ParsedCommand<'_>,
    registry: &CommandRegistry,
    env: &mut ShellEnv,
    io: &mut dyn ShellIo,
) -> i32 {
    match registry.find(cmd.name) {
        Some(handler) => {
            // Build a &[&[u8]] view over the fixed-size args array
            let args: &[&[u8]] = &cmd.args[..cmd.argc.min(MAX_ARGS - 1)];
            let code = handler.execute(args, env, io);
            env.last_exit = code;
            code
        }
        None => {
            io.write_bytes(cmd.name);
            io.write_bytes(b": command not found  (try 'help')\n");
            env.last_exit = 127;
            127
        }
    }
}
