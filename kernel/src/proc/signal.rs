//! Signal numbers and default dispositions (Linux x86_64 values).

pub const SIGHUP: u32 = 1;
pub const SIGINT: u32 = 2;
pub const SIGQUIT: u32 = 3;
pub const SIGILL: u32 = 4;
pub const SIGTRAP: u32 = 5;
pub const SIGABRT: u32 = 6;
pub const SIGBUS: u32 = 7;
pub const SIGFPE: u32 = 8;
pub const SIGKILL: u32 = 9;
pub const SIGUSR1: u32 = 10;
pub const SIGSEGV: u32 = 11;
pub const SIGUSR2: u32 = 12;
pub const SIGPIPE: u32 = 13;
pub const SIGALRM: u32 = 14;
pub const SIGTERM: u32 = 15;
pub const SIGSTKFLT: u32 = 16;
pub const SIGCHLD: u32 = 17;
pub const SIGCONT: u32 = 18;
pub const SIGSTOP: u32 = 19;
pub const SIGTSTP: u32 = 20;
pub const SIGTTIN: u32 = 21;
pub const SIGTTOU: u32 = 22;
pub const SIGURG: u32 = 23;
pub const SIGXCPU: u32 = 24;
pub const SIGXFSZ: u32 = 25;
pub const SIGVTALRM: u32 = 26;
pub const SIGPROF: u32 = 27;
pub const SIGWINCH: u32 = 28;
pub const SIGIO: u32 = 29;
pub const SIGPWR: u32 = 30;
pub const SIGSYS: u32 = 31;
pub const NSIG: u32 = 64;

const NAMES: [&str; 32] = [
    "", "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "BUS", "FPE", "KILL", "USR1", "SEGV", "USR2", "PIPE", "ALRM",
    "TERM", "STKFLT", "CHLD", "CONT", "STOP", "TSTP", "TTIN", "TTOU", "URG", "XCPU", "XFSZ", "VTALRM", "PROF",
    "WINCH", "IO", "PWR", "SYS",
];

/// `TERM` for 15, `RTMIN+2` for 36...
pub fn name(sig: u32) -> alloc::string::String {
    use alloc::string::ToString;
    if (1..32).contains(&sig) {
        NAMES[sig as usize].to_string()
    } else if (32..=64).contains(&sig) {
        alloc::format!("RTMIN+{}", sig - 32)
    } else {
        alloc::format!("{sig}")
    }
}

/// Parse `TERM`, `SIGTERM`, `term` or `15`.
pub fn parse(s: &str) -> Option<u32> {
    if let Ok(n) = s.parse::<u32>() {
        return (n <= NSIG).then_some(n);
    }
    let up = s.to_ascii_uppercase();
    let bare = up.strip_prefix("SIG").unwrap_or(&up);
    NAMES.iter().position(|&n| !n.is_empty() && n == bare).map(|i| i as u32)
}

/// Signals whose default action is to ignore them.
pub fn ignored_by_default(sig: u32) -> bool {
    matches!(sig, SIGCHLD | SIGWINCH | SIGURG | SIGCONT)
}

/// Human description (as `strsignal` / shells print on abnormal exit).
pub fn describe(sig: u32) -> &'static str {
    match sig {
        SIGHUP => "Hangup",
        SIGINT => "Interrupt",
        SIGQUIT => "Quit",
        SIGILL => "Illegal instruction",
        SIGTRAP => "Trace/breakpoint trap",
        SIGABRT => "Aborted",
        SIGBUS => "Bus error",
        SIGFPE => "Floating point exception",
        SIGKILL => "Killed",
        SIGUSR1 => "User defined signal 1",
        SIGSEGV => "Segmentation fault",
        SIGUSR2 => "User defined signal 2",
        SIGPIPE => "Broken pipe",
        SIGALRM => "Alarm clock",
        SIGTERM => "Terminated",
        SIGSTOP => "Stopped (signal)",
        SIGTSTP => "Stopped",
        SIGXCPU => "CPU time limit exceeded",
        SIGSYS => "Bad system call",
        _ => "Unknown signal",
    }
}
