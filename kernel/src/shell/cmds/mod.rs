//! Native commands (the contents of `/bin`).

pub mod basic;
pub mod files;
pub mod fmtutil;
pub mod text;

use super::ctx::CommandDef;

macro_rules! cmd {
    ($name:literal, $main:path, $about:literal, $usage:literal) => {
        CommandDef { name: $name, main: $main, about: $about, usage: $usage }
    };
}

/// Every command, sorted by name.
pub static COMMANDS: &[CommandDef] = &[
    cmd!("[", basic::test, "evaluate a conditional expression", "EXPRESSION ]"),
    cmd!("basename", files::basename, "strip directory and suffix from a file name", "NAME [SUFFIX]"),
    cmd!("cat", text::cat, "concatenate files and print them", "[-nbsAE] [FILE]..."),
    cmd!("clear", basic::clear, "clear the terminal screen", ""),
    cmd!("dirname", files::dirname, "strip the last component from a file name", "NAME..."),
    cmd!("echo", basic::echo, "display a line of text", "[-neE] [STRING]..."),
    cmd!("env", basic::env, "print or modify the environment", "[-i] [NAME=VALUE]... [COMMAND [ARG]...]"),
    cmd!("false", basic::false_, "do nothing, unsuccessfully", ""),
    cmd!("ls", files::ls, "list directory contents", "[-aAlhdRrtSi1CF] [--color=WHEN] [FILE]..."),
    cmd!("printenv", basic::printenv, "print environment variables", "[NAME]..."),
    cmd!("printf", basic::printf, "format and print data", "FORMAT [ARGUMENT]..."),
    cmd!("pwd", basic::pwd, "print the current working directory", "[-LP]"),
    cmd!("sleep", basic::sleep, "delay for a specified amount of time", "NUMBER[smhd]..."),
    cmd!("test", basic::test, "evaluate a conditional expression", "EXPRESSION"),
    cmd!("true", basic::true_, "do nothing, successfully", ""),
    cmd!("uname", basic::uname, "print system information", "[-asnrvmpio]"),
];

pub fn find(name: &str) -> Option<&'static CommandDef> {
    COMMANDS.iter().find(|c| c.name == name)
}

pub fn all() -> &'static [CommandDef] {
    COMMANDS
}
