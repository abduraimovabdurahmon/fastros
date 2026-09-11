//! Shell builtins: commands that must run inside the shell process because
//! they change its state (`cd`, `export`, `exit`...), plus a few frequent
//! ones run inline for speed (`echo`, `printf`, `test`).

use super::exec::Target;
use super::{Flow, Shell};
use crate::errno::Errno;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

#[derive(Clone, Copy)]
pub struct Builtin {
    pub name: &'static str,
    pub run: fn(&mut Shell, &[String]) -> i32,
    /// POSIX special builtins keep prefix assignments and abort scripts on error.
    pub special: bool,
}

const fn b(name: &'static str, run: fn(&mut Shell, &[String]) -> i32, special: bool) -> Builtin {
    Builtin { name, run, special }
}

pub const BUILTINS: &[Builtin] = &[
    b(".", source, true),
    b(":", colon, true),
    b("[", inline_native, false),
    b("alias", alias, false),
    b("bg", bg, false),
    b("break", brk, true),
    b("cd", cd, false),
    b("command", command, false),
    b("continue", cont, true),
    b("echo", inline_native, false),
    b("eval", eval, true),
    b("exec", exec, true),
    b("exit", exit, true),
    b("export", export, true),
    b("false", inline_native, false),
    b("fg", fg, false),
    b("hash", colon, false),
    b("help", help, false),
    b("history", history, false),
    b("jobs", jobs, false),
    b("kill", kill, false),
    b("local", local, false),
    b("logout", exit, true),
    b("printf", inline_native, false),
    b("pwd", pwd, false),
    b("read", read, false),
    b("readonly", readonly, true),
    b("return", ret, true),
    b("set", set, true),
    b("shift", shift, true),
    b("source", source, true),
    b("test", inline_native, false),
    b("trap", trap, true),
    b("true", inline_native, false),
    b("type", type_, false),
    b("umask", umask, false),
    b("unalias", unalias, false),
    b("unset", unset, true),
    b("wait", wait, false),
];

pub fn find(name: &str) -> Option<Builtin> {
    BUILTINS.iter().find(|b| b.name == name).copied()
}

pub fn names() -> impl Iterator<Item = &'static str> {
    BUILTINS.iter().map(|b| b.name)
}

fn err(sh: &Shell, cmd: &str, msg: &str) -> i32 {
    sh.error(&alloc::format!("{cmd}: {msg}"));
    1
}

/// Run a native command inside the shell process (no fork).
fn inline_native(sh: &mut Shell, argv: &[String]) -> i32 {
    let Some(def) = super::cmds::find(&argv[0]) else { return 127 };
    let mut ctx = super::ctx::Ctx::new(sh.proc.clone(), argv.to_vec());
    super::cmds::invoke(def, &mut ctx)
}

/// One-line synopsis of each builtin (for `help`).
fn builtin_synopsis(name: &str) -> &'static str {
    match name {
        "." | "source" => "source FILE [ARGS]          run commands from FILE in this shell",
        ":" => ":                           null command, always succeeds",
        "alias" => "alias [NAME[=VALUE] ...]    define or display aliases",
        "bg" => "bg [JOB]                    resume a job in the background",
        "break" => "break [N]                   exit N enclosing loops",
        "cd" => "cd [DIR]                    change the working directory",
        "command" => "command [-v] NAME [ARG...]  run a command, bypassing functions",
        "continue" => "continue [N]                resume the next loop iteration",
        "eval" => "eval [ARG ...]              run the arguments as shell code",
        "exec" => "exec COMMAND [ARG...]       replace the shell with a command",
        "exit" | "logout" => "exit [N]                    exit the shell with status N",
        "export" => "export [NAME[=VALUE] ...]   mark variables for the environment",
        "fg" => "fg [JOB]                    move a job to the foreground",
        "help" => "help [NAME ...]             show help on builtins and commands",
        "history" => "history [-c] [N]            show or clear the command history",
        "jobs" => "jobs                        list the shell's jobs",
        "kill" => "kill [-SIG] PID|%JOB ...    send a signal to processes or jobs",
        "local" => "local NAME[=VALUE] ...      define function-local variables",
        "read" => "read [-r] [-p PROMPT] NAME  read a line into variables",
        "readonly" => "readonly NAME[=VALUE] ...   make variables read-only",
        "return" => "return [N]                  return from a function",
        "set" => "set [-euxfC] [ARG ...]      set options and positional parameters",
        "shift" => "shift [N]                   shift positional parameters",
        "trap" => "trap [ACTION] [SIGNAL ...]  run ACTION when a signal arrives",
        "type" => "type NAME ...               describe how a name is interpreted",
        "umask" => "umask [-S] [MODE]           show or set the file creation mask",
        "unalias" => "unalias [-a] NAME ...       remove aliases",
        "unset" => "unset [-fv] NAME ...        remove variables or functions",
        "wait" => "wait [PID|%JOB ...]         wait for background jobs",
        "hash" => "hash                        (no-op: commands are not cached)",
        _ => "",
    }
}

fn help(sh: &mut Shell, argv: &[String]) -> i32 {
    if argv.len() > 1 {
        let mut st = 0;
        for topic in &argv[1..] {
            if find(topic).is_some() {
                let syn = builtin_synopsis(topic);
                sh.out(&alloc::format!("{topic}: {}\n", if syn.is_empty() { topic.as_str() } else { syn }));
            } else if let Some(def) = super::cmds::find(topic) {
                sh.out(&alloc::format!("{}: {} {}\n    {}\n", def.name, def.name, def.usage, def.about));
            } else {
                sh.err(&alloc::format!("fsh: help: no help topics match `{topic}'.  Try `help help'.\n"));
                st = 1;
            }
        }
        return st;
    }
    let mut s = alloc::format!("FastROS fsh, version {} (x86_64-fastros)\n", crate::VERSION);
    s.push_str("These shell commands are defined internally.  Type `help' to see this list.\n");
    s.push_str("Type `help name' to find out more about the function `name'.\n");
    s.push_str("Every program in /bin also accepts `--help'.\n\n");
    let mut names: Vec<&str> = names().collect();
    names.sort_unstable();
    names.dedup();
    for n in names {
        let syn = builtin_synopsis(n);
        if !syn.is_empty() {
            s.push_str(&alloc::format!(" {syn}\n"));
        }
    }
    s.push_str("\nPrograms in /bin:\n");
    let cols = sh.tty().map(|t| t.winsize().cols as usize).filter(|&c| c > 0).unwrap_or(80);
    let items: Vec<(String, usize)> = super::cmds::all().iter().map(|c| (String::from(c.name), c.name.len())).collect();
    for line in super::cmds::fmtutil::columns(&items, cols) {
        s.push_str(&line);
        s.push('\n');
    }
    sh.out(&s);
    0
}

/// `kill` as a builtin so job specs work: `%N`, `%%`, `%+`, `%-` become the
/// job's process group (`-PGID`), then the native `kill` does the rest.
fn kill(sh: &mut Shell, argv: &[String]) -> i32 {
    if argv.get(1).is_some_and(|a| a == "-l" || a == "-L" || a == "--list" || a == "--table") {
        return inline_native(sh, argv);
    }
    let mut args = alloc::vec![argv[0].clone()];
    let mut rest = argv[1..].iter();
    // Options first (`-9`, `-s TERM`, `-l`), then `--`, then the targets, so
    // a translated `-PGID` is never mistaken for a signal number.
    let mut targets: Vec<&String> = Vec::new();
    while let Some(a) = rest.next() {
        if a == "--" {
            targets.extend(rest.by_ref());
            break;
        }
        if a == "-s" || a == "-n" {
            args.push(a.clone());
            if let Some(v) = rest.next() {
                args.push(v.clone());
            }
        } else if a.starts_with('-') && targets.is_empty() && a.len() > 1 {
            args.push(a.clone());
        } else {
            targets.push(a);
            targets.extend(rest.by_ref());
            break;
        }
    }
    if !targets.is_empty() {
        args.push(String::from("--"));
    }
    for a in targets {
        let Some(spec) = a.strip_prefix('%') else {
            args.push(a.clone());
            continue;
        };
        let job = match spec {
            "" | "%" | "+" => sh.jobs.last(),
            "-" => sh.jobs.len().checked_sub(2).and_then(|i| sh.jobs.get(i)),
            n => n.parse::<usize>().ok().and_then(|id| sh.jobs.iter().find(|j| j.id == id)),
        };
        match job {
            Some(j) => args.push(alloc::format!("-{}", j.pgid)),
            None => return err(sh, "kill", &alloc::format!("{a}: no such job")),
        }
    }
    inline_native(sh, &args)
}

fn colon(_: &mut Shell, _: &[String]) -> i32 {
    0
}

fn cd(sh: &mut Shell, argv: &[String]) -> i32 {
    let args: Vec<&String> = argv[1..].iter().filter(|a| *a != "-L" && *a != "-P").collect();
    if args.len() > 1 {
        return err(sh, "cd", "too many arguments");
    }
    let mut print = false;
    let target = match args.first().map(|s| s.as_str()) {
        None | Some("~") => match sh.var("HOME") {
            Some(h) if !h.is_empty() => h,
            _ => return err(sh, "cd", "HOME not set"),
        },
        Some("-") => match sh.var("OLDPWD") {
            Some(o) => {
                print = true;
                o
            }
            None => return err(sh, "cd", "OLDPWD not set"),
        },
        Some(p) => p.to_string(),
    };
    // Logical `..` handling like bash: resolve against $PWD textually when
    // the result exists, so `cd link/..` returns to where you came from.
    let pwd = sh.var("PWD").unwrap_or_else(|| sh.proc.fs.lock().cwd.path());
    let logical = if target.starts_with('/') { normalize(&target) } else { normalize(&alloc::format!("{pwd}/{target}")) };
    let (dest, shown) = match crate::fs::ops::chdir(&sh.proc, &logical) {
        Ok(_) => (logical.clone(), logical),
        Err(_) => match crate::fs::ops::chdir(&sh.proc, &target) {
            Ok(node) => (node.path(), node.path()),
            Err(e) => return err(sh, "cd", &alloc::format!("{target}: {e}")),
        },
    };
    let _ = sh.set_var("OLDPWD", &pwd, true);
    let _ = sh.set_var("PWD", &dest, true);
    if print {
        sh.out(&alloc::format!("{shown}\n"));
    }
    0
}

/// Lexically normalise an absolute path (`/a/./b/../c` → `/a/c`).
pub fn normalize(p: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for c in p.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            x => parts.push(x),
        }
    }
    let mut s = String::from("/");
    s.push_str(&parts.join("/"));
    s
}

fn pwd(sh: &mut Shell, argv: &[String]) -> i32 {
    let physical = argv.iter().any(|a| a == "-P");
    let real = sh.proc.fs.lock().cwd.path();
    let p = if physical { real } else { sh.var("PWD").filter(|p| p.starts_with('/')).unwrap_or(real) };
    sh.out(&alloc::format!("{p}\n"));
    0
}

fn export(sh: &mut Shell, argv: &[String]) -> i32 {
    let args: Vec<&String> = argv[1..].iter().filter(|a| *a != "-p").collect();
    if args.is_empty() {
        let lines: Vec<String> = sh
            .vars
            .iter()
            .filter(|(_, v)| v.exported)
            .map(|(k, v)| alloc::format!("export {}={}\n", k, fastros_sh::quote(&v.value)))
            .collect();
        for l in lines {
            sh.out(&l);
        }
        return 0;
    }
    let mut st = 0;
    for a in args {
        let (k, v) = match a.split_once('=') {
            Some((k, v)) => (k, Some(v)),
            None => (a.as_str(), None),
        };
        if !fastros_sh::parser::is_name(k) {
            st = err(sh, "export", &alloc::format!("`{a}': not a valid identifier"));
            continue;
        }
        match v {
            Some(v) => {
                if let Err(m) = sh.set_var(k, v, true) {
                    st = err(sh, "export", &m);
                }
            }
            None => {
                let cur = sh.var(k).unwrap_or_default();
                let _ = sh.set_var(k, &cur, true);
            }
        }
    }
    sh.sync_env();
    st
}

fn readonly(sh: &mut Shell, argv: &[String]) -> i32 {
    for a in &argv[1..] {
        let (k, v) = match a.split_once('=') {
            Some((k, v)) => (k, Some(v)),
            None => (a.as_str(), None),
        };
        if let Some(v) = v {
            if let Err(m) = sh.set_var(k, v, false) {
                return err(sh, "readonly", &m);
            }
        }
        let e = sh.vars.entry(k.to_string()).or_insert(super::Var { value: String::new(), exported: false, readonly: false });
        e.readonly = true;
    }
    0
}

fn local(sh: &mut Shell, argv: &[String]) -> i32 {
    if sh.locals.is_empty() {
        return err(sh, "local", "can only be used in a function");
    }
    for a in &argv[1..] {
        let (k, v) = match a.split_once('=') {
            Some((k, v)) => (k.to_string(), Some(v.to_string())),
            None => (a.clone(), None),
        };
        let old = sh.vars.get(&k).cloned();
        if let Some(scope) = sh.locals.last_mut() {
            if !scope.iter().any(|(n, _)| *n == k) {
                scope.push((k.clone(), old));
            }
        }
        let _ = sh.set_var(&k, &v.unwrap_or_default(), false);
    }
    0
}

fn unset(sh: &mut Shell, argv: &[String]) -> i32 {
    let mut funcs = false;
    let mut st = 0;
    for a in &argv[1..] {
        match a.as_str() {
            "-f" => funcs = true,
            "-v" => funcs = false,
            name => {
                if funcs {
                    sh.funcs.remove(name);
                } else if let Err(m) = sh.unset_var(name) {
                    st = err(sh, "unset", &m);
                }
            }
        }
    }
    st
}

fn set(sh: &mut Shell, argv: &[String]) -> i32 {
    if argv.len() == 1 {
        let lines: Vec<String> = sh.vars.iter().map(|(k, v)| alloc::format!("{}={}\n", k, fastros_sh::quote(&v.value))).collect();
        for l in lines {
            sh.out(&l);
        }
        return 0;
    }
    let mut i = 1;
    while i < argv.len() {
        let a = &argv[i];
        if a == "--" {
            sh.args = argv[i + 1..].to_vec();
            return 0;
        }
        let (on, flags) = match a.chars().next() {
            Some('-') => (true, &a[1..]),
            Some('+') => (false, &a[1..]),
            _ => {
                sh.args = argv[i..].to_vec();
                return 0;
            }
        };
        if flags == "o" {
            i += 1;
            let Some(name) = argv.get(i) else {
                let o = sh.opts;
                for (n, v) in [("errexit", o.errexit), ("noclobber", o.noclobber), ("noglob", o.noglob), ("nounset", o.nounset), ("xtrace", o.xtrace)] {
                    sh.out(&alloc::format!("{:<15}{}\n", n, if v { "on" } else { "off" }));
                }
                return 0;
            };
            match name.as_str() {
                "errexit" => sh.opts.errexit = on,
                "nounset" => sh.opts.nounset = on,
                "xtrace" => sh.opts.xtrace = on,
                "noclobber" => sh.opts.noclobber = on,
                "noglob" => sh.opts.noglob = on,
                "pipefail" | "emacs" | "vi" => {}
                _ => return err(sh, "set", &alloc::format!("{name}: invalid option name")),
            }
        } else {
            for c in flags.chars() {
                match c {
                    'e' => sh.opts.errexit = on,
                    'u' => sh.opts.nounset = on,
                    'x' => sh.opts.xtrace = on,
                    'C' => sh.opts.noclobber = on,
                    'f' => sh.opts.noglob = on,
                    _ => return err(sh, "set", &alloc::format!("-{c}: invalid option")),
                }
            }
        }
        i += 1;
    }
    0
}

fn shift(sh: &mut Shell, argv: &[String]) -> i32 {
    let n: usize = match argv.get(1).map(|s| s.parse()) {
        None => 1,
        Some(Ok(n)) => n,
        Some(Err(_)) => return err(sh, "shift", "numeric argument required"),
    };
    if n > sh.args.len() {
        return 1;
    }
    sh.args.drain(..n);
    0
}

fn numeric_arg(sh: &Shell, cmd: &str, argv: &[String], default: i32) -> Option<i32> {
    match argv.get(1) {
        None => Some(default),
        Some(s) => match s.parse::<i64>() {
            Ok(n) => Some((n & 0xFF) as i32),
            Err(_) => {
                sh.error(&alloc::format!("{cmd}: {s}: numeric argument required"));
                None
            }
        },
    }
}

fn exit(sh: &mut Shell, argv: &[String]) -> i32 {
    let code = numeric_arg(sh, "exit", argv, sh.status).unwrap_or(2);
    if sh.interactive && argv[0] == "exit" {
        sh.out("exit\n");
    }
    sh.exit_code = code;
    sh.flow = Flow::Exit;
    code
}

fn ret(sh: &mut Shell, argv: &[String]) -> i32 {
    if sh.func_depth == 0 {
        return err(sh, "return", "can only `return' from a function or sourced script");
    }
    let code = numeric_arg(sh, "return", argv, sh.status).unwrap_or(2);
    sh.status = code;
    sh.flow = Flow::Return;
    code
}

fn brk(sh: &mut Shell, argv: &[String]) -> i32 {
    if sh.loop_depth == 0 {
        return 0;
    }
    let n = argv.get(1).and_then(|s| s.parse::<u32>().ok()).unwrap_or(1).clamp(1, sh.loop_depth);
    sh.flow = Flow::Break(n);
    0
}

fn cont(sh: &mut Shell, argv: &[String]) -> i32 {
    if sh.loop_depth == 0 {
        return 0;
    }
    let n = argv.get(1).and_then(|s| s.parse::<u32>().ok()).unwrap_or(1).clamp(1, sh.loop_depth);
    sh.flow = Flow::Continue(n);
    0
}

fn alias(sh: &mut Shell, argv: &[String]) -> i32 {
    if argv.len() == 1 {
        let lines: Vec<String> = sh.aliases.iter().map(|(k, v)| alloc::format!("alias {}={}\n", k, fastros_sh::quote(v))).collect();
        for l in lines {
            sh.out(&l);
        }
        return 0;
    }
    let mut st = 0;
    for a in &argv[1..] {
        match a.split_once('=') {
            Some((k, v)) => {
                sh.aliases.insert(k.to_string(), v.to_string());
            }
            None => match sh.aliases.get(a) {
                Some(v) => {
                    let l = alloc::format!("alias {}={}\n", a, fastros_sh::quote(v));
                    sh.out(&l);
                }
                None => st = err(sh, "alias", &alloc::format!("{a}: not found")),
            },
        }
    }
    st
}

fn unalias(sh: &mut Shell, argv: &[String]) -> i32 {
    if argv.get(1).map(|s| s.as_str()) == Some("-a") {
        sh.aliases.clear();
        return 0;
    }
    let mut st = 0;
    for a in &argv[1..] {
        if sh.aliases.remove(a).is_none() {
            st = err(sh, "unalias", &alloc::format!("{a}: not found"));
        }
    }
    st
}

fn source(sh: &mut Shell, argv: &[String]) -> i32 {
    let Some(path) = argv.get(1) else { return err(sh, &argv[0], "filename argument required") };
    let ctx = crate::fs::ops::Ctx::of(&sh.proc);
    let data = match crate::fs::ops::read_file(&ctx, path) {
        Ok(d) => d,
        Err(e) => return err(sh, &argv[0], &alloc::format!("{path}: {e}")),
    };
    let src = String::from_utf8_lossy(&data).into_owned();
    let saved = if argv.len() > 2 { Some(core::mem::replace(&mut sh.args, argv[2..].to_vec())) } else { None };
    sh.func_depth += 1;
    let st = sh.run_source(&src);
    sh.func_depth -= 1;
    if sh.flow == Flow::Return {
        sh.flow = Flow::Normal;
    }
    if let Some(a) = saved {
        sh.args = a;
    }
    st
}

fn eval(sh: &mut Shell, argv: &[String]) -> i32 {
    let src = argv[1..].join(" ");
    sh.run_source(&src)
}

fn exec(sh: &mut Shell, argv: &[String]) -> i32 {
    if argv.len() == 1 {
        sh.keep_redirs = true;
        return 0;
    }
    let rest = argv[1..].iter().map(|a| fastros_sh::quote(a)).collect::<Vec<_>>().join(" ");
    let st = sh.run_source(&rest);
    sh.exit_code = st;
    sh.flow = Flow::Exit;
    st
}

fn read(sh: &mut Shell, argv: &[String]) -> i32 {
    let mut raw = false;
    let mut silent = false;
    let mut prompt = None;
    let mut nchars: Option<usize> = None;
    let mut timeout: Option<u64> = None;
    let mut names = Vec::new();
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "-r" => raw = true,
            "-s" => silent = true,
            "-p" => {
                i += 1;
                prompt = argv.get(i).cloned();
            }
            "-n" => {
                i += 1;
                nchars = argv.get(i).and_then(|s| s.parse().ok());
            }
            "-t" => {
                i += 1;
                timeout = argv.get(i).and_then(|s| s.parse::<u64>().ok());
            }
            n => names.push(n.to_string()),
        }
        i += 1;
    }
    if names.is_empty() {
        names.push(String::from("REPLY"));
    }
    let Ok(stdin) = sh.proc.fds.lock().get(0) else { return 1 };
    if let Some(p) = &prompt {
        sh.err(p);
    }
    let tty = stdin.tty();
    let saved = tty.as_ref().map(|t| t.termios());
    if let (Some(t), Some(mut tio)) = (&tty, saved) {
        if silent {
            tio.lflag &= !crate::tty::consts::ECHO;
        }
        if nchars.is_some() {
            tio.lflag &= !crate::tty::consts::ICANON;
        }
        t.set_termios(tio);
    }
    let deadline = timeout.map(|t| crate::time::now_ns() + t * 1_000_000_000);
    let mut line = Vec::new();
    let mut got_eof = false;
    let mut timed_out = false;
    loop {
        if let Some(d) = deadline {
            if crate::time::now_ns() >= d {
                timed_out = true;
                break;
            }
            if let Some(t) = &tty {
                if !t.input_ready() {
                    crate::sched::sleep_ms(10);
                    continue;
                }
            }
        }
        let mut b = [0u8; 1];
        match stdin.read(&mut b) {
            Ok(0) => {
                got_eof = true;
                break;
            }
            Ok(_) => {
                if b[0] == b'\n' {
                    break;
                }
                if !raw && b[0] == b'\\' {
                    let mut n = [0u8; 1];
                    match stdin.read(&mut n) {
                        Ok(1) if n[0] == b'\n' => continue,
                        Ok(1) => line.push(n[0]),
                        _ => {}
                    }
                    continue;
                }
                line.push(b[0]);
                if nchars.is_some_and(|n| line.len() >= n) {
                    break;
                }
            }
            Err(Errno::EINTR) => {
                if let (Some(t), Some(s)) = (&tty, saved) {
                    t.set_termios(s);
                }
                return 130;
            }
            Err(_) => {
                got_eof = true;
                break;
            }
        }
    }
    if let (Some(t), Some(s)) = (&tty, saved) {
        t.set_termios(s);
        if silent {
            let _ = t.write(b"\n");
        }
    }
    let text = String::from_utf8_lossy(&line).into_owned();
    let ifs = sh.var("IFS").unwrap_or_else(|| String::from(" \t\n"));
    let mut fields: Vec<String> = Vec::new();
    let mut rest = text.trim_matches(|c| ifs.contains(c) && (c == ' ' || c == '\t' || c == '\n'));
    for (idx, name) in names.iter().enumerate() {
        if idx + 1 == names.len() {
            fields.push(rest.to_string());
            let _ = name;
            break;
        }
        match rest.find(|c| ifs.contains(c)) {
            Some(p) => {
                fields.push(rest[..p].to_string());
                rest = rest[p..].trim_start_matches(|c| ifs.contains(c) && (c == ' ' || c == '\t'));
            }
            None => {
                fields.push(rest.to_string());
                rest = "";
            }
        }
    }
    for (idx, name) in names.iter().enumerate() {
        let v = fields.get(idx).cloned().unwrap_or_default();
        let _ = sh.set_var(name, &v, false);
    }
    if timed_out {
        return 142;
    }
    if got_eof && line.is_empty() {
        1
    } else {
        0
    }
}

fn describe(sh: &Shell, name: &str, verbose: bool) -> Option<String> {
    if let Some(a) = sh.aliases.get(name) {
        return Some(if verbose { alloc::format!("{name} is aliased to `{a}'") } else { alloc::format!("alias {name}={}", fastros_sh::quote(a)) });
    }
    if ["if", "then", "else", "elif", "fi", "case", "esac", "for", "while", "until", "do", "done", "in", "function", "{", "}", "!"].contains(&name) {
        return Some(if verbose { alloc::format!("{name} is a shell keyword") } else { name.to_string() });
    }
    match sh.resolve(name) {
        Target::Function(_) => Some(if verbose { alloc::format!("{name} is a function") } else { name.to_string() }),
        Target::Builtin(_) => Some(if verbose { alloc::format!("{name} is a shell builtin") } else { name.to_string() }),
        Target::Native(def) => {
            let p = alloc::format!("/bin/{}", def.name);
            Some(if verbose { alloc::format!("{name} is {p}") } else { p })
        }
        Target::Script(p) => Some(if verbose { alloc::format!("{name} is {p}") } else { p }),
        _ => None,
    }
}

fn type_(sh: &mut Shell, argv: &[String]) -> i32 {
    let mut st = 0;
    for n in &argv[1..] {
        match describe(sh, n, true) {
            Some(d) => sh.out(&alloc::format!("{d}\n")),
            None => {
                sh.error(&alloc::format!("type: {n}: not found"));
                st = 1;
            }
        }
    }
    st
}

fn command(sh: &mut Shell, argv: &[String]) -> i32 {
    match argv.get(1).map(|s| s.as_str()) {
        Some("-v") | Some("-V") => {
            let verbose = argv[1] == "-V";
            let mut st = 0;
            for n in &argv[2..] {
                match describe(sh, n, verbose) {
                    Some(d) => sh.out(&alloc::format!("{d}\n")),
                    None => st = 1,
                }
            }
            st
        }
        Some(_) => {
            // Bypass functions and aliases.
            let saved = core::mem::take(&mut sh.funcs);
            let rest = argv[1..].iter().map(|a| fastros_sh::quote(a)).collect::<Vec<_>>().join(" ");
            let aliases = core::mem::take(&mut sh.aliases);
            let st = sh.run_source(&rest);
            sh.funcs = saved;
            sh.aliases = aliases;
            st
        }
        None => 0,
    }
}

fn history(sh: &mut Shell, argv: &[String]) -> i32 {
    match argv.get(1).map(|s| s.as_str()) {
        Some("-c") => {
            sh.history.clear();
            let _ = sh.history.save(&sh.proc);
            0
        }
        Some(n) => match n.parse::<usize>() {
            Ok(n) => {
                let text = sh.history.render(Some(n));
                sh.out(&text);
                0
            }
            Err(_) => err(sh, "history", &alloc::format!("{n}: numeric argument required")),
        },
        None => {
            let text = sh.history.render(None);
            sh.out(&text);
            0
        }
    }
}

fn jobs(sh: &mut Shell, _argv: &[String]) -> i32 {
    sh.report_jobs();
    let lines: Vec<String> = sh
        .jobs
        .iter()
        .map(|j| {
            let running = j.pids.iter().any(|&p| crate::proc::find(p).is_some_and(|pr| !pr.is_zombie()));
            alloc::format!("[{}]+  {:<24}{}\n", j.id, if running { "Running" } else { "Done" }, j.cmd)
        })
        .collect();
    for l in lines {
        sh.out(&l);
    }
    0
}

fn job_arg(sh: &Shell, arg: Option<&String>) -> Option<usize> {
    match arg {
        None => sh.jobs.len().checked_sub(1),
        Some(a) => {
            let id: usize = a.trim_start_matches('%').parse().ok()?;
            sh.jobs.iter().position(|j| j.id == id)
        }
    }
}

fn fg(sh: &mut Shell, argv: &[String]) -> i32 {
    let Some(idx) = job_arg(sh, argv.get(1)) else { return err(sh, "fg", "no such job") };
    let job = sh.jobs.remove(idx);
    sh.out(&alloc::format!("{}\n", job.cmd));
    let tty = sh.tty();
    if let Some(t) = &tty {
        t.set_fg_pgrp(job.pgid);
    }
    let mut last = 0;
    for pid in job.pids {
        loop {
            match crate::proc::wait(&sh.proc, crate::proc::WaitFor::Pid(pid), false) {
                Ok(Some((_, s))) => {
                    last = s.shell_code();
                    break;
                }
                Err(Errno::EINTR) if crate::proc::absorb_signals() => continue,
                _ => break,
            }
        }
    }
    if let Some(t) = &tty {
        t.set_fg_pgrp(sh.proc.pgid.load(Ordering::Relaxed));
    }
    last
}

fn bg(sh: &mut Shell, argv: &[String]) -> i32 {
    // Background jobs never stop in fsh (no SIGTSTP), so bg only reports.
    match job_arg(sh, argv.get(1)) {
        Some(i) => {
            let l = alloc::format!("[{}]+ {} &\n", sh.jobs[i].id, sh.jobs[i].cmd);
            sh.out(&l);
            0
        }
        None => err(sh, "bg", "no such job"),
    }
}

fn wait(sh: &mut Shell, argv: &[String]) -> i32 {
    let mut last = 0;
    let pids: Vec<u32> = if argv.len() > 1 {
        argv[1..].iter().filter_map(|a| if let Some(j) = a.strip_prefix('%') { sh.jobs.iter().find(|x| x.id.to_string() == j).map(|x| x.pgid) } else { a.parse().ok() }).collect()
    } else {
        sh.jobs.iter().flat_map(|j| j.pids.clone()).collect()
    };
    for pid in pids {
        loop {
            match crate::proc::wait(&sh.proc, crate::proc::WaitFor::Pid(pid), false) {
                Ok(Some((_, s))) => {
                    last = s.shell_code();
                    break;
                }
                // A signal ends `wait` at once; the trap runs before the next command.
                Err(Errno::EINTR) => return 128 + crate::sched::with_current(|t| t.pending_signals()).trailing_zeros() as i32 + 1,
                _ => {
                    last = 127;
                    break;
                }
            }
        }
    }
    sh.jobs.retain(|j| j.pids.iter().any(|&p| crate::proc::find(p).is_some()));
    last
}

fn umask(sh: &mut Shell, argv: &[String]) -> i32 {
    match argv.get(1) {
        None => {
            let m = sh.proc.fs.lock().umask;
            sh.out(&alloc::format!("{m:04o}\n"));
            0
        }
        Some(s) if s == "-S" => {
            let m = !sh.proc.fs.lock().umask & 0o777;
            let part = |shift: u32| {
                let b = (m >> shift) & 7;
                let mut s = String::new();
                if b & 4 != 0 {
                    s.push('r');
                }
                if b & 2 != 0 {
                    s.push('w');
                }
                if b & 1 != 0 {
                    s.push('x');
                }
                s
            };
            sh.out(&alloc::format!("u={},g={},o={}\n", part(6), part(3), part(0)));
            0
        }
        Some(s) => match u16::from_str_radix(s, 8) {
            Ok(m) if m <= 0o777 => {
                sh.proc.fs.lock().umask = m;
                0
            }
            _ => err(sh, "umask", &alloc::format!("{s}: octal number out of range")),
        },
    }
}

fn trap(sh: &mut Shell, argv: &[String]) -> i32 {
    if argv.len() == 1 {
        let lines: Vec<String> = sh.traps.iter().map(|(k, v)| alloc::format!("trap -- {} {}\n", fastros_sh::quote(v), k)).collect();
        for l in lines {
            sh.out(&l);
        }
        return 0;
    }
    let action = &argv[1];
    for sig in &argv[2..] {
        let name = match sig.as_str() {
            "0" | "EXIT" => "EXIT".to_string(),
            s => crate::proc::signal::parse(s).map(crate::proc::signal::name).unwrap_or_else(|| s.to_string()),
        };
        // `trap '' SIG` is SIG_IGN: the process ignores it, and so do the
        // commands it starts (the disposition is inherited).
        if let Some(n) = crate::proc::signal::parse(&name).filter(|&n| (1..=64).contains(&n)) {
            let bit = 1u64 << (n - 1);
            if action.is_empty() {
                sh.proc.ignored.fetch_or(bit, Ordering::Relaxed);
            } else {
                sh.proc.ignored.fetch_and(!bit, Ordering::Relaxed);
            }
        }
        if action == "-" {
            sh.traps.remove(&name);
        } else {
            sh.traps.insert(name, action.clone());
        }
    }
    0
}
