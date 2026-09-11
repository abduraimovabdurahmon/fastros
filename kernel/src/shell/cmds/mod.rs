//! Native commands (the contents of `/bin`).

pub mod account;
pub mod archive;
pub mod basic;
pub mod diff;
pub mod fileinfo;
pub mod fileops;
pub mod files;
pub mod findutils;
pub mod fmtutil;
pub mod grep;
pub mod http;
pub mod net;
pub mod pager;
pub mod posixre;
pub mod procinfo;
pub mod procps;
pub mod runutil;
pub mod sed;
pub mod sysutil;
pub mod text;
pub mod textutils;
pub mod top;

use super::ctx::CommandDef;

macro_rules! cmd {
    ($name:literal, $main:path, $about:literal, $usage:literal) => {
        CommandDef { name: $name, main: $main, about: $about, usage: $usage }
    };
}

/// Every command, sorted by name.
pub static COMMANDS: &[CommandDef] = &[
    cmd!("[", basic::test, "evaluate a conditional expression", "EXPRESSION ]"),
    cmd!("adduser", account::adduser, "add a user and set its password", "USER"),
    cmd!("arp", net::arp, "manipulate the system ARP cache", "[-n]"),
    cmd!("base64", textutils::base64, "base64 encode/decode data", "[-d] [-w COLS] [FILE]"),
    cmd!("basename", files::basename, "strip directory and suffix from a file name", "NAME [SUFFIX]"),
    cmd!("cat", text::cat, "concatenate files and print them", "[-nbsAE] [FILE]..."),
    cmd!("chgrp", fileops::chgrp, "change group ownership", "[-Rhv] GROUP FILE..."),
    cmd!("chmod", fileops::chmod, "change file mode bits", "[-Rvcf] MODE FILE..."),
    cmd!("chown", fileops::chown, "change file owner and group", "[-Rhv] OWNER[:GROUP] FILE..."),
    cmd!("chpasswd", account::chpasswd, "update passwords in batch mode", "< USER:PASSWORD..."),
    cmd!("clear", basic::clear, "clear the terminal screen", ""),
    cmd!("cp", fileops::cp, "copy files and directories", "[-rapfinvuls] SOURCE... DEST"),
    cmd!("curl", http::curl, "transfer data from or to a server", "[-sSLIifO] [-X METHOD] [-H HEADER] [-d DATA] [-o FILE] [-w FMT] URL..."),
    cmd!("cut", textutils::cut, "remove sections from each line", "-b|-c|-f LIST [-d DELIM] [FILE]..."),
    cmd!("date", sysutil::date, "print or set the system date and time", "[-uR] [-d STRING] [-s STRING] [-I[FMT]] [+FORMAT]"),
    cmd!("df", sysutil::df, "report file system disk space usage", "[-ahHiTP] [-t TYPE] [-x TYPE] [-B SIZE] [FILE]..."),
    cmd!("diff", diff::diff, "compare files line by line", "[-uqsrNibwa] [-U N] FILE1 FILE2"),
    cmd!("dig", net::dig, "DNS lookup utility", "[@server] NAME [type]"),
    cmd!("dirname", files::dirname, "strip the last component from a file name", "NAME..."),
    cmd!("dmesg", sysutil::dmesg, "print the kernel ring buffer", "[-TxrctwW] [-l LEVELS]"),
    cmd!("du", fileinfo::du, "estimate file space usage", "[-ashbcxL] [-d N] [FILE]..."),
    cmd!("echo", basic::echo, "display a line of text", "[-neE] [STRING]..."),
    cmd!("egrep", grep::egrep, "search with extended regular expressions (grep -E)", "PATTERNS [FILE]..."),
    cmd!("env", basic::env, "print or modify the environment", "[-i] [NAME=VALUE]... [COMMAND [ARG]...]"),
    cmd!("false", basic::false_, "do nothing, unsuccessfully", ""),
    cmd!("fexec", runutil::fexec, "run a native (Linux ABI) ELF program", "PATH [ARG]..."),
    cmd!("fgrep", grep::fgrep, "search for fixed strings (grep -F)", "PATTERNS [FILE]..."),
    cmd!("find", findutils::find, "search for files in a directory hierarchy", "[-H] [-L] [-P] [PATH...] [EXPRESSION]"),
    cmd!("free", procps::free, "display amount of free and used memory", "[-bkmgh] [-w] [-t] [-s N] [-c N]"),
    cmd!("fsh", crate::shell::sh_main, "the FastROS shell", "[-euxfC] [-c COMMAND [NAME [ARG]...]] [FILE [ARG]...]"),
    cmd!("fw", net::fw, "manage the system firewall", "[status | allow PROTO PORT | deny PROTO PORT | ban IP | unban IP | bans]"),
    cmd!("gpasswd", account::gpasswd, "administer /etc/group", "[-a USER | -d USER | -M USERS] GROUP"),
    cmd!("grep", grep::grep, "print lines that match patterns", "[OPTION]... PATTERNS [FILE]..."),
    cmd!("groupadd", account::groupadd, "create a new group", "[-g GID] [-f] GROUP"),
    cmd!("groupdel", account::groupdel, "delete a group", "GROUP"),
    cmd!("groups", sysutil::groups, "print the groups a user is in", "[USER]..."),
    cmd!("gunzip", archive::gzip::gunzip, "decompress files", "[-cfkNqrtv] [FILE]..."),
    cmd!("gzip", archive::gzip::gzip, "compress or expand files", "[-cdfklnNqrtv1-9] [-S SUF] [FILE]..."),
    cmd!("halt", sysutil::halt, "halt the system", "[-p]"),
    cmd!("head", textutils::head, "output the first part of files", "[-n NUM] [-c NUM] [FILE]..."),
    cmd!("hexdump", textutils::hexdump, "display file contents in hexadecimal", "[-C] [FILE]..."),
    cmd!("host", net::host, "resolve a host name", "NAME"),
    cmd!("hostname", sysutil::hostname, "show or set the system host name", "[-sfdiI] [-b] [NAME]"),
    cmd!("htop", top::htop, "interactive process viewer", "[-Ct] [-d DELAY] [-u USER] [-p PID] [-s COLUMN]"),
    cmd!("id", sysutil::id, "print real and effective user and group IDs", "[-ugGnrz] [USER]"),
    cmd!("ifconfig", net::ifconfig, "configure a network interface", "[INTERFACE]"),
    cmd!("ip", net::ip, "show / manipulate routing, devices, addresses", "{addr|link|route|neigh} ..."),
    cmd!("kill", procps::kill, "send a signal to a process", "[-s SIGNAL | -SIGNAL] PID... | -l [SIGNAL]"),
    cmd!("killall", procps::killall, "kill processes by name", "[-eIiqrvw] [-s SIGNAL | -SIGNAL] [-u USER] NAME..."),
    cmd!("last", procps::last, "show a listing of last logged in users", "[-n N] [-x] [-f FILE] [USER|TTY]..."),
    cmd!("less", pager::less, "view text one screen at a time", "[-NSRFXiIe] [FILE]..."),
    cmd!("ln", fileops::ln, "make links between files", "[-sfvn] TARGET [LINK]"),
    cmd!("locate", findutils::locate, "find files by name in the locate database", "[-icbeA0] [-l N] PATTERN..."),
    cmd!("ls", files::ls, "list directory contents", "[-aAlhdRrtSi1CF] [--color=WHEN] [FILE]..."),
    cmd!("lsblk", sysutil::lsblk, "list block devices", "[-bnl]"),
    cmd!("lscpu", sysutil::lscpu, "display information about the CPU architecture", ""),
    cmd!("lspci", sysutil::lspci, "list all PCI devices", "[-n|-nn] [-v]"),
    cmd!("mkdir", fileops::mkdir, "make directories", "[-pv] [-m MODE] DIRECTORY..."),
    cmd!("mkfifo", fileops::mkfifo, "make named pipes", "[-m MODE] NAME..."),
    cmd!("mktemp", fileops::mktemp, "create a temporary file or directory", "[-dqu] [-p DIR] [TEMPLATE]"),
    cmd!("more", pager::more, "file perusal filter for viewing text", "[-s] [-n LINES] [FILE]..."),
    cmd!("mount", sysutil::mount, "mount a filesystem", "[-t TYPE] [-o OPTIONS] [--bind] SOURCE TARGET"),
    cmd!("mv", fileops::mv, "move (rename) files", "[-finvu] SOURCE... DEST"),
    cmd!("nc", net::nc, "arbitrary TCP and UDP connections and listens", "[-lukvnz] [-w SECS] [HOST] PORT"),
    cmd!("netstat", net::netstat, "print network connections and interfaces", "[-tulnpraies]"),
    cmd!("nl", textutils::nl, "number lines of files", "[-b STYLE] [-w N] [FILE]..."),
    cmd!("nohup", runutil::nohup, "run a command immune to hangups", "COMMAND [ARG]..."),
    cmd!("nproc", procps::nproc, "print the number of processing units available", ""),
    cmd!("nslookup", net::nslookup, "query DNS name servers", "HOST"),
    cmd!("passwd", account::passwd, "change user password", "[-l|-u|-S] [--stdin] [LOGIN]"),
    cmd!("pgrep", procps::pgrep, "look up processes by name and other attributes", "[-flcnoxvia] [-d DELIM] [-P PPID] [-u USER] [-t TTY] PATTERN"),
    cmd!("pidof", procps::pidof, "find the process ID of a running program", "[-sq] [-o PID] NAME..."),
    cmd!("ping", net::ping, "send ICMP ECHO_REQUEST to network hosts", "[-c COUNT] [-i INT] [-W TIMEOUT] [-s SIZE] [-q] HOST"),
    cmd!("pkill", procps::pkill, "signal processes by name and other attributes", "[-SIGNAL] [-fnoxvie] [-P PPID] [-u USER] [-t TTY] PATTERN"),
    cmd!("poweroff", sysutil::poweroff, "power off the system", ""),
    cmd!("printenv", basic::printenv, "print environment variables", "[NAME]..."),
    cmd!("printf", basic::printf, "format and print data", "FORMAT [ARGUMENT]..."),
    cmd!("ps", procps::ps, "report a snapshot of the current processes", "[-efjH] [aux] [-o FORMAT] [-p PID] [-u USER] [--sort KEY]"),
    cmd!("pwd", basic::pwd, "print the current working directory", "[-LP]"),
    cmd!("readlink", fileinfo::readlink, "print resolved symbolic links or canonical file names", "[-femnqvz] FILE..."),
    cmd!("realpath", fileinfo::realpath, "print the resolved path", "[-emsqz] [--relative-to=DIR] FILE..."),
    cmd!("reboot", sysutil::reboot, "reboot the system", ""),
    cmd!("rev", textutils::rev, "reverse lines characterwise", "[FILE]..."),
    cmd!("rm", fileops::rm, "remove files or directories", "[-rfivd] FILE..."),
    cmd!("rmdir", fileops::rmdir, "remove empty directories", "[-pv] DIRECTORY..."),
    cmd!("route", net::route, "show / manipulate the IP routing table", "[-n]"),
    cmd!("sed", sed::sed, "stream editor for filtering and transforming text", "[-nEsiz] [-e SCRIPT] [-f FILE] [FILE]..."),
    cmd!("seq", textutils::seq, "print a sequence of numbers", "[-w] [-s SEP] [FIRST [INCR]] LAST"),
    cmd!("sh", crate::shell::sh_main, "the FastROS shell (POSIX sh)", "[-euxfC] [-c COMMAND [NAME [ARG]...]] [FILE [ARG]...]"),
    cmd!("sha256sum", textutils::sha256sum, "compute and check SHA256 checksums", "[-c] [FILE]..."),
    cmd!("shutdown", sysutil::shutdown, "halt, power off or reboot the machine", "[-hPrHc] [TIME] [MESSAGE]"),
    cmd!("sleep", basic::sleep, "delay for a specified amount of time", "NUMBER[smhd]..."),
    cmd!("sort", textutils::sort, "sort lines of text files", "[-nrufbhVs] [-k KEY] [-t SEP] [FILE]..."),
    cmd!("ss", net::ss, "another utility to investigate sockets", "[-tulnpa]"),
    cmd!("stat", fileinfo::stat, "display file or file system status", "[-Lft] [-c FORMAT] FILE..."),
    cmd!("stty", sysutil::stty, "change and print terminal line settings", "[-a] [SETTING]..."),
    cmd!("su", account::su, "run a command with substitute user and group ID", "[-] [-c COMMAND] [-m] [USER]"),
    cmd!("sudo", account::sudo, "execute a command as another user", "[-iklnsSvEK] [-u USER] [COMMAND [ARG]...]"),
    cmd!("sync", fileops::sync, "write cached data to disk", ""),
    cmd!("sysctl", sysutil::sysctl, "read or write kernel parameters", "[-anNqe] [KEY[=VALUE]]..."),
    cmd!("tac", textutils::tac, "concatenate and print files in reverse", "[FILE]..."),
    cmd!("tail", textutils::tail, "output the last part of files", "[-n NUM] [-c NUM] [-f] [FILE]..."),
    cmd!("tar", archive::tar::tar, "an archiving utility", "[-]{c|x|t}[zvpOPkh] [-f ARCHIVE] [-C DIR] [FILE]..."),
    cmd!("tee", textutils::tee, "copy standard input to files and standard output", "[-a] [FILE]..."),
    cmd!("test", basic::test, "evaluate a conditional expression", "EXPRESSION"),
    cmd!("time", runutil::time, "time a simple command", "[-p] COMMAND [ARG]..."),
    cmd!("timeout", runutil::timeout, "run a command with a time limit", "[-s SIGNAL] [-k DURATION] [--preserve-status] DURATION COMMAND [ARG]..."),
    cmd!("top", top::top, "display processes", "[-bci] [-d SECS] [-n N] [-p PID] [-u USER] [-o FIELD]"),
    cmd!("touch", fileops::touch, "change file timestamps / create files", "[-acm] [-d DATE] [-r FILE] FILE..."),
    cmd!("tr", textutils::tr, "translate or delete characters", "[-dsc] SET1 [SET2]"),
    cmd!("true", basic::true_, "do nothing, successfully", ""),
    cmd!("truncate", fileops::truncate, "shrink or extend a file", "-s SIZE FILE..."),
    cmd!("tty", sysutil::tty, "print the file name of the terminal on standard input", "[-s]"),
    cmd!("umount", sysutil::umount, "unmount filesystems", "[-lfv] TARGET..."),
    cmd!("uname", basic::uname, "print system information", "[-asnrvmpio]"),
    cmd!("uniq", textutils::uniq, "report or omit repeated lines", "[-cdui] [INPUT [OUTPUT]]"),
    cmd!("unzip", archive::zip::unzip, "list, test and extract zip archives", "[-lqoptnj:] FILE[.zip] [MEMBER]... [-d DIR]"),
    cmd!("updatedb", findutils::updatedb, "update the locate database", "[-v]"),
    cmd!("uptime", procps::uptime, "tell how long the system has been running", "[-p] [-s]"),
    cmd!("useradd", account::useradd, "create a new user", "[-m] [-d HOME] [-s SHELL] [-u UID] [-g GROUP] [-G GROUPS] [-c COMMENT] LOGIN"),
    cmd!("userdel", account::userdel, "delete a user account", "[-r] [-f] LOGIN"),
    cmd!("usermod", account::usermod, "modify a user account", "[-aG GROUPS] [-s SHELL] [-d HOME] [-c COMMENT] [-g GROUP] [-l NAME] [-L|-U] LOGIN"),
    cmd!("users", procps::users, "print the user names of users currently logged in", ""),
    cmd!("vmstat", procps::vmstat, "report virtual memory statistics", "[DELAY [COUNT]]"),
    cmd!("w", procps::w, "show who is logged on and what they are doing", "[-hs] [USER]"),
    cmd!("wall", sysutil::wall, "write a message to all users", "[MESSAGE]"),
    cmd!("watch", runutil::watch, "execute a program periodically, showing output fullscreen", "[-n SECS] [-tdegx] COMMAND"),
    cmd!("wc", textutils::wc, "print line, word and byte counts", "[-lwcmL] [FILE]..."),
    cmd!("wget", http::wget, "a non-interactive network downloader", "[-qO FILE] URL..."),
    cmd!("which", fileinfo::which, "locate a command", "[-a] NAME..."),
    cmd!("who", procps::who, "show who is logged on", "[-abHmqsu] [am i]"),
    cmd!("whoami", sysutil::whoami, "print effective user name", ""),
    cmd!("xargs", findutils::xargs, "build and execute command lines from standard input", "[-0rtp] [-n N] [-I STR] [-d DELIM] [COMMAND [ARG]...]"),
    cmd!("xxd", textutils::hexdump, "make a hex dump", "[FILE]"),
    cmd!("yes", textutils::yes, "output a string repeatedly", "[STRING]..."),
    cmd!("zcat", archive::gzip::zcat, "decompress files to standard output", "[-f] [FILE]..."),
    cmd!("zip", archive::zip::zip, "package and compress files", "[-rjqyD0-9] ZIPFILE FILE..."),
];

/// Run a native command: uniform `CMD --help` / `CMD --version`, then its
/// main function, then flush its output.
pub fn invoke(def: &CommandDef, ctx: &mut super::ctx::Ctx) -> i32 {
    // Commands whose POSIX behaviour treats these words as operands.
    const LITERAL: &[&str] = &["echo", "printf", "test", "[", "true", "false", "sh", "fsh", "kill"];
    if ctx.args.len() == 2 && !LITERAL.contains(&def.name) {
        match ctx.args[1].as_str() {
            "--help" => {
                let mut about: alloc::string::String = def.about.into();
                if let Some(first) = about.get(..1) {
                    about = alloc::format!("{}{}.", first.to_uppercase(), &about[1..]);
                }
                ctx.print(&alloc::format!("Usage: {} {}\n{}\n", def.name, def.usage, about));
                ctx.flush();
                return 0;
            }
            "--version" => {
                ctx.print(&alloc::format!("{} (FastROS) {}\n", def.name, crate::VERSION));
                ctx.flush();
                return 0;
            }
            _ => {}
        }
    }
    let code = (def.main)(ctx);
    ctx.flush();
    code
}

pub fn find(name: &str) -> Option<&'static CommandDef> {
    COMMANDS.iter().find(|c| c.name == name)
}

pub fn all() -> &'static [CommandDef] {
    COMMANDS
}
