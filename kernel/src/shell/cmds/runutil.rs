//! Commands that run other commands: time, timeout, watch, nohup.

use crate::fs::file::flags;
use crate::proc::{self, signal, ExitStatus, WaitFor};
use crate::shell::ctx::{parse_opts, Ctx, OptSpec};
use crate::shell::tui::{self, Key, Screen, Terminal};
use crate::shell::Shell;
use crate::outln;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

/// A child started from argv with this process's descriptors.
fn start(ctx: &mut Ctx, argv: Vec<String>) -> Result<alloc::sync::Arc<proc::Process>, i32> {
    ctx.flush();
    let mut sh = Shell::new(ctx.proc.clone(), false);
    let fds = ctx.proc.fds.lock().clone();
    sh.spawn_argv(argv, fds, None, None).map_err(|(st, m)| {
        ctx.eprint(&alloc::format!("{}: {}\n", ctx.name(), m));
        st
    })
}

/// Wait for `child`, retrying across signals aimed at others.
fn wait_child(ctx: &Ctx, child: &proc::Process) -> Option<ExitStatus> {
    loop {
        match proc::wait(&ctx.proc, WaitFor::Pid(child.pid), false) {
            Ok(Some((_, st))) => return Some(st),
            Ok(None) => continue,
            Err(crate::errno::Errno::EINTR) => {
                if !proc::absorb_signals() {
                    return None;
                }
            }
            Err(_) => return None,
        }
    }
}

/// Parse `1.5`, `10s`, `2m`, `1h`, `1d` into milliseconds.
fn duration_ms(s: &str) -> Option<u64> {
    let (num, mult) = match s.chars().last()? {
        's' => (&s[..s.len() - 1], 1000u64),
        'm' => (&s[..s.len() - 1], 60_000),
        'h' => (&s[..s.len() - 1], 3_600_000),
        'd' => (&s[..s.len() - 1], 86_400_000),
        _ => (s, 1000),
    };
    let (i, f) = num.split_once('.').unwrap_or((num, ""));
    if i.is_empty() && f.is_empty() {
        return None;
    }
    let whole: u64 = if i.is_empty() { 0 } else { i.parse().ok()? };
    let mut frac = 0u64;
    let mut scale = mult / 10;
    for c in f.chars().take(6) {
        frac += c.to_digit(10)? as u64 * scale;
        scale /= 10;
    }
    whole.checked_mul(mult)?.checked_add(frac)
}

// ── time ───────────────────────────────────────────────────────────────────

/// bash's `0m0.004s`.
fn bash_time(ns: u64) -> String {
    let ms = ns / 1_000_000;
    alloc::format!("{}m{}.{:03}s", ms / 60_000, ms / 1000 % 60, ms % 1000)
}

pub fn time(ctx: &mut Ctx) -> i32 {
    let mut i = 1;
    let mut posix = false;
    while i < ctx.args.len() && ctx.args[i].starts_with('-') {
        match ctx.args[i].as_str() {
            "-p" | "--portability" => posix = true,
            "--" => {
                i += 1;
                break;
            }
            other => return ctx.fail(alloc::format!("invalid option -- '{}'", other.trim_start_matches('-'))),
        }
        i += 1;
    }
    let argv = ctx.args[i..].to_vec();
    let start_ns = crate::time::now_ns();
    let cpu_before = ctx.proc.children_cpu.load(Ordering::Relaxed);
    let st = if argv.is_empty() {
        0
    } else {
        match start(ctx, argv) {
            Ok(child) => match wait_child(ctx, &child) {
                Some(s) => s.shell_code(),
                None => 130,
            },
            Err(st) => st,
        }
    };
    let real = crate::time::now_ns() - start_ns;
    let user = ctx.proc.children_cpu.load(Ordering::Relaxed).saturating_sub(cpu_before);
    // Native programs run in the kernel, so all of their time is "user"
    // time from the program's point of view; system time is not split out.
    let report = if posix {
        let f = |ns: u64| alloc::format!("{}.{:02}", ns / 1_000_000_000, ns / 10_000_000 % 100);
        alloc::format!("real {}\nuser {}\nsys {}\n", f(real), f(user), f(0))
    } else {
        alloc::format!("\nreal\t{}\nuser\t{}\nsys\t{}\n", bash_time(real), bash_time(user), bash_time(0))
    };
    ctx.eprint(&report);
    st
}

// ── timeout ────────────────────────────────────────────────────────────────

pub fn timeout(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "vp", values: "sk", long: &[("signal", 's', true), ("kill-after", 'k', true), ("preserve-status", 'p', false), ("verbose", 'v', false), ("foreground", 'f', false)] };
    // Options end at the first operand: the command's own flags are its own.
    let first_operand = ctx.args.iter().enumerate().skip(1).find(|(i, a)| {
        !a.starts_with('-') && !matches!(ctx.args.get(i - 1).map(|s| s.as_str()), Some("-s" | "-k" | "--signal" | "--kill-after"))
    });
    let split = first_operand.map(|(i, _)| i).unwrap_or(ctx.args.len());
    let p = match parse_opts(&ctx.args[..split], &SPEC) {
        Ok(p) => p,
        Err(e) => {
            ctx.fail(e);
            return 125;
        }
    };
    let rest = ctx.args[split..].to_vec();
    if rest.len() < 2 {
        ctx.eprint("timeout: missing operand\nTry 'timeout --help' for more information.\n");
        return 125;
    }
    let Some(limit) = duration_ms(&rest[0]) else {
        ctx.fail(alloc::format!("invalid time interval '{}'", rest[0]));
        return 125;
    };
    let sig = match p.value('s') {
        Some(s) => match signal::parse(s) {
            Some(n) => n,
            None => {
                ctx.fail(alloc::format!("{s}: invalid signal"));
                return 125;
            }
        },
        None => signal::SIGTERM,
    };
    let kill_after = match p.value('k').map(duration_ms) {
        Some(Some(ms)) => Some(ms),
        Some(None) => {
            ctx.fail("invalid kill-after interval");
            return 125;
        }
        None => None,
    };
    let child = match start(ctx, rest[1..].to_vec()) {
        Ok(c) => c,
        Err(st) => return st,
    };
    let deadline = crate::time::now_ns() + limit * 1_000_000;
    let mut timed_out = false;
    let mut kill_deadline = None;
    loop {
        match proc::wait(&ctx.proc, WaitFor::Pid(child.pid), true) {
            Ok(Some((_, st))) => {
                if timed_out && !p.has('p') {
                    return 124;
                }
                return st.shell_code();
            }
            Ok(None) => {}
            Err(_) => return 125,
        }
        let now = crate::time::now_ns();
        if !timed_out && now >= deadline {
            timed_out = true;
            if p.has('v') {
                ctx.eprint(&alloc::format!("timeout: sending signal {} to command '{}'\n", signal::name(sig), rest[1]));
            }
            let _ = proc::kill(&ctx.proc, child.pid as i64, sig);
            kill_deadline = kill_after.map(|ms| now + ms * 1_000_000);
        }
        if let Some(kd) = kill_deadline {
            if now >= kd {
                let _ = proc::kill(&ctx.proc, child.pid as i64, signal::SIGKILL);
                kill_deadline = None;
            }
        }
        if !crate::sched::sleep_ms(10) && !proc::absorb_signals() {
            let _ = proc::kill(&ctx.proc, child.pid as i64, signal::SIGKILL);
        }
    }
}

// ── nohup ──────────────────────────────────────────────────────────────────

pub fn nohup(ctx: &mut Ctx) -> i32 {
    let argv: Vec<String> = ctx.args[1..].iter().skip_while(|a| *a == "--").cloned().collect();
    if argv.is_empty() {
        ctx.eprint("nohup: missing operand\nTry 'nohup --help' for more information.\n");
        return 125;
    }
    // Ignore SIGHUP here; the child inherits the disposition.
    ctx.proc.ignored.fetch_or(1 << (signal::SIGHUP - 1), Ordering::Relaxed);
    let stdout_tty = ctx.stdout_tty().is_some();
    let stdin_tty = ctx.stdin_tty().is_some();
    if stdin_tty {
        if let Ok(null) = crate::device::open_char(crate::fs::makedev(1, 3), flags::O_RDONLY) {
            ctx.proc.fds.lock().set(0, null, false);
        }
    }
    if stdout_tty {
        let fs = ctx.fs();
        let home = ctx.env("HOME").unwrap_or_default();
        let fl = flags::O_WRONLY | flags::O_CREAT | flags::O_APPEND;
        let (file, name) = match crate::fs::ops::open(&fs, "nohup.out", fl, 0o600) {
            Ok(f) => (f, String::from("nohup.out")),
            Err(_) => {
                let p = alloc::format!("{home}/nohup.out");
                match crate::fs::ops::open(&fs, &p, fl, 0o600) {
                    Ok(f) => (f, p),
                    Err(e) => {
                        ctx.fail(alloc::format!("failed to open 'nohup.out': {e}"));
                        return 125;
                    }
                }
            }
        };
        ctx.eprint(&alloc::format!("nohup: {}appending output to '{}'\n", if stdin_tty { "ignoring input and " } else { "" }, name));
        let mut fds = ctx.proc.fds.lock();
        fds.set(1, file.clone(), false);
        if ctx.stdout_tty().is_some() {
            fds.set(2, file, false);
        }
    } else if stdin_tty {
        ctx.eprint("nohup: ignoring input\n");
    }
    let child = match start(ctx, argv) {
        Ok(c) => c,
        Err(st) => return st,
    };
    match wait_child(ctx, &child) {
        Some(s) => s.shell_code(),
        None => 130,
    }
}

// ── watch ──────────────────────────────────────────────────────────────────

pub fn watch(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "tdegxbc",
        values: "n",
        long: &[("interval", 'n', true), ("no-title", 't', false), ("differences", 'd', false), ("errexit", 'e', false), ("chgexit", 'g', false), ("exec", 'x', false), ("beep", 'b', false), ("color", 'c', false)],
    };
    let first_operand = ctx.args.iter().enumerate().skip(1).find(|(i, a)| !a.starts_with('-') && !matches!(ctx.args.get(i - 1).map(|s| s.as_str()), Some("-n" | "--interval"))).map(|(i, _)| i).unwrap_or(ctx.args.len());
    let p = match parse_opts(&ctx.args[..first_operand], &SPEC) {
        Ok(p) => p,
        Err(e) => {
            ctx.fail(e);
            return 1;
        }
    };
    let cmd_words = ctx.args[first_operand..].to_vec();
    if cmd_words.is_empty() {
        ctx.eprint("Usage:\n watch [options] command\n");
        return 1;
    }
    let interval_ms = match p.value('n').map(duration_ms) {
        Some(Some(ms)) => ms.max(100),
        Some(None) => return ctx.fail("failed to parse argument"),
        None => 2000,
    };
    let command = if p.has('x') { cmd_words.iter().map(|w| fastros_sh::quote(w)).collect::<Vec<_>>().join(" ") } else { cmd_words.join(" ") };
    let Some(tty) = ctx.stdout_tty() else {
        return ctx.fail("watch needs a terminal");
    };
    let term = Terminal::open(tty, true);
    let mut screen = Screen::new();
    let mut prev_out: Option<String> = None;
    loop {
        let mut sh = Shell::new(ctx.proc.clone(), false);
        let output = sh.capture(&command).unwrap_or_else(|e| e);
        let status = sh.status;
        let (cols, rows) = term.size();
        let mut lines: Vec<String> = Vec::new();
        if !p.has('t') {
            let host = ctx.proc.uts.hostname.lock().clone();
            let now = crate::time::unix_now() as i64;
            let left = alloc::format!("Every {}.{}s: {}", interval_ms / 1000, interval_ms % 1000 / 100, command);
            let right = alloc::format!("{}: {}", host, super::sysutil::strftime("%a %b %e %H:%M:%S %Y", now, 0));
            let pad = cols.saturating_sub(left.chars().count() + right.chars().count());
            if pad >= 1 {
                lines.push(alloc::format!("{left}{}{right}", " ".repeat(pad)));
            } else {
                lines.push(tui::fit(&left, cols));
            }
            lines.push(String::new());
        }
        let old_lines: Vec<&str> = prev_out.as_deref().map(|o| o.lines().collect()).unwrap_or_default();
        for (n, l) in output.lines().enumerate() {
            if lines.len() >= rows {
                break;
            }
            let l = l.replace('\t', "        ");
            // -d: reverse-video the characters that changed.
            if p.has('d') && prev_out.is_some() {
                let old: Vec<char> = old_lines.get(n).map(|s| s.chars().collect()).unwrap_or_default();
                let mut s = String::new();
                for (k, ch) in l.chars().take(cols).enumerate() {
                    if old.get(k) != Some(&ch) {
                        s.push_str(&alloc::format!("\x1b[7m{ch}\x1b[0m"));
                    } else {
                        s.push(ch);
                    }
                }
                lines.push(s);
            } else {
                lines.push(tui::fit(&l, cols));
            }
        }
        screen.present(&term, &lines);
        if p.has('e') && status != 0 {
            drop(term);
            outln!(ctx, "\ncommand exit with a non-zero status, press a key to exit");
            return 8;
        }
        if p.has('g') && prev_out.as_ref().is_some_and(|o| *o != output) {
            return 0;
        }
        prev_out = Some(output);
        match term.read_key(interval_ms) {
            Ok(Some(Key::Char('q'))) | Ok(Some(Key::Ctrl('c'))) => return 0,
            Ok(_) => {}
            Err(_) => {
                if !proc::absorb_signals() || term.tty().is_hung_up() {
                    return 0;
                }
                return 0;
            }
        }
    }
}

// ── fexec: run a native (Linux-ABI) ELF binary as a user process ───────────

/// `fexec PATH [ARG...]` loads a static ELF64 program into a new user
/// address space and runs it to completion. The bridge to real binaries
/// until the shell resolves them automatically.
pub fn fexec(ctx: &mut Ctx) -> i32 {
    if ctx.args.len() < 2 {
        ctx.eprint("usage: fexec PATH [ARG]...\n");
        return 2;
    }
    let path = ctx.args[1].clone();
    let data = match ctx.read_input(&path) {
        Ok(d) => d,
        Err(e) => return ctx.fail_errno(&path, e),
    };
    let argv: Vec<String> = ctx.args[1..].to_vec();
    let envp: Vec<String> = ctx.proc.env.lock().iter().map(|(k, v)| alloc::format!("{k}={v}")).collect();
    let (space, frame) = match crate::proc::elf::load(&ctx.fs(), &data, &argv, &envp) {
        Ok(v) => v,
        Err(e) => return ctx.fail_errno(&path, e),
    };
    ctx.flush();
    let spawn = crate::proc::Spawn::from_parent(&ctx.proc, path.rsplit('/').next().unwrap_or(&path), argv);
    let child = match crate::proc::start_user(spawn, space, frame) {
        Ok(c) => c,
        Err(e) => return ctx.fail_errno("start_user", e),
    };
    let pid = child.pid;
    loop {
        match crate::proc::wait(&ctx.proc, crate::proc::WaitFor::Pid(pid), false) {
            Ok(Some((_, st))) => return st.shell_code(),
            Ok(None) => continue,
            Err(crate::errno::Errno::EINTR) if crate::proc::absorb_signals() => continue,
            Err(_) => return 1,
        }
    }
}
