//! Native commands (the contents of `/bin`).

pub mod basic;
pub mod fileops;
pub mod files;
pub mod fmtutil;
pub mod text;
pub mod textutils;

use super::ctx::CommandDef;

macro_rules! cmd {
    ($name:literal, $main:path, $about:literal, $usage:literal) => {
        CommandDef { name: $name, main: $main, about: $about, usage: $usage }
    };
}

/// Every command, sorted by name.
pub static COMMANDS: &[CommandDef] = &[
    cmd!("[", basic::test, "evaluate a conditional expression", "EXPRESSION ]"),
    cmd!("base64", textutils::base64, "base64 encode/decode data", "[-d] [-w COLS] [FILE]"),
    cmd!("basename", files::basename, "strip directory and suffix from a file name", "NAME [SUFFIX]"),
    cmd!("cat", text::cat, "concatenate files and print them", "[-nbsAE] [FILE]..."),
    cmd!("chgrp", fileops::chgrp, "change group ownership", "[-Rhv] GROUP FILE..."),
    cmd!("chmod", fileops::chmod, "change file mode bits", "[-Rvcf] MODE FILE..."),
    cmd!("chown", fileops::chown, "change file owner and group", "[-Rhv] OWNER[:GROUP] FILE..."),
    cmd!("clear", basic::clear, "clear the terminal screen", ""),
    cmd!("cp", fileops::cp, "copy files and directories", "[-rapfinvuls] SOURCE... DEST"),
    cmd!("cut", textutils::cut, "remove sections from each line", "-b|-c|-f LIST [-d DELIM] [FILE]..."),
    cmd!("dirname", files::dirname, "strip the last component from a file name", "NAME..."),
    cmd!("echo", basic::echo, "display a line of text", "[-neE] [STRING]..."),
    cmd!("env", basic::env, "print or modify the environment", "[-i] [NAME=VALUE]... [COMMAND [ARG]...]"),
    cmd!("false", basic::false_, "do nothing, unsuccessfully", ""),
    cmd!("head", textutils::head, "output the first part of files", "[-n NUM] [-c NUM] [FILE]..."),
    cmd!("hexdump", textutils::hexdump, "display file contents in hexadecimal", "[-C] [FILE]..."),
    cmd!("ln", fileops::ln, "make links between files", "[-sfvn] TARGET [LINK]"),
    cmd!("ls", files::ls, "list directory contents", "[-aAlhdRrtSi1CF] [--color=WHEN] [FILE]..."),
    cmd!("mkdir", fileops::mkdir, "make directories", "[-pv] [-m MODE] DIRECTORY..."),
    cmd!("mkfifo", fileops::mkfifo, "make named pipes", "[-m MODE] NAME..."),
    cmd!("mktemp", fileops::mktemp, "create a temporary file or directory", "[-dqu] [-p DIR] [TEMPLATE]"),
    cmd!("mv", fileops::mv, "move (rename) files", "[-finvu] SOURCE... DEST"),
    cmd!("nl", textutils::nl, "number lines of files", "[-b STYLE] [-w N] [FILE]..."),
    cmd!("printenv", basic::printenv, "print environment variables", "[NAME]..."),
    cmd!("printf", basic::printf, "format and print data", "FORMAT [ARGUMENT]..."),
    cmd!("pwd", basic::pwd, "print the current working directory", "[-LP]"),
    cmd!("rev", textutils::rev, "reverse lines characterwise", "[FILE]..."),
    cmd!("rm", fileops::rm, "remove files or directories", "[-rfivd] FILE..."),
    cmd!("rmdir", fileops::rmdir, "remove empty directories", "[-pv] DIRECTORY..."),
    cmd!("seq", textutils::seq, "print a sequence of numbers", "[-w] [-s SEP] [FIRST [INCR]] LAST"),
    cmd!("sha256sum", textutils::sha256sum, "compute and check SHA256 checksums", "[-c] [FILE]..."),
    cmd!("sleep", basic::sleep, "delay for a specified amount of time", "NUMBER[smhd]..."),
    cmd!("sort", textutils::sort, "sort lines of text files", "[-nrufbhVs] [-k KEY] [-t SEP] [FILE]..."),
    cmd!("sync", fileops::sync, "write cached data to disk", ""),
    cmd!("tac", textutils::tac, "concatenate and print files in reverse", "[FILE]..."),
    cmd!("tail", textutils::tail, "output the last part of files", "[-n NUM] [-c NUM] [-f] [FILE]..."),
    cmd!("tee", textutils::tee, "copy standard input to files and standard output", "[-a] [FILE]..."),
    cmd!("test", basic::test, "evaluate a conditional expression", "EXPRESSION"),
    cmd!("touch", fileops::touch, "change file timestamps / create files", "[-acm] [-d DATE] [-r FILE] FILE..."),
    cmd!("tr", textutils::tr, "translate or delete characters", "[-dsc] SET1 [SET2]"),
    cmd!("true", basic::true_, "do nothing, successfully", ""),
    cmd!("truncate", fileops::truncate, "shrink or extend a file", "-s SIZE FILE..."),
    cmd!("uname", basic::uname, "print system information", "[-asnrvmpio]"),
    cmd!("uniq", textutils::uniq, "report or omit repeated lines", "[-cdui] [INPUT [OUTPUT]]"),
    cmd!("wc", textutils::wc, "print line, word and byte counts", "[-lwcmL] [FILE]..."),
    cmd!("xxd", textutils::hexdump, "make a hex dump", "[FILE]"),
    cmd!("yes", textutils::yes, "output a string repeatedly", "[STRING]..."),
];

pub fn find(name: &str) -> Option<&'static CommandDef> {
    COMMANDS.iter().find(|c| c.name == name)
}

pub fn all() -> &'static [CommandDef] {
    COMMANDS
}
