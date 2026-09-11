//! Accounts and privilege: passwd, su, sudo, useradd, adduser, userdel,
//! usermod, groupadd, groupdel, gpasswd, chpasswd.
//!
//! Hardening beyond a stock Linux install:
//! * `su` to root is limited to members of `wheel`/`sudo` (pam_wheel);
//! * non-root passwords must be at least 8 characters and differ from the
//!   user name (pam_pwquality's minimum);
//! * every failure costs a fixed delay, and every privileged action is
//!   written to the kernel log (`dmesg`), which only root can read;
//! * sudo credentials are cached per terminal session, for 5 minutes.

use crate::errno::Errno;
use crate::shell::ctx::{parse_opts, Ctx, OptSpec};
use crate::sync::SpinLock;
use crate::users::{self, User};
use crate::outln;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Delay after a failed authentication (as pam_faildelay).
const FAIL_DELAY_MS: u64 = 2000;
const MIN_PASSWORD: usize = 8;
const SUDO_TIMEOUT_NS: u64 = 5 * 60 * 1_000_000_000;

/// Read a line without echo from the terminal (or a plain line from stdin
/// when there is none). `None` on EOF or interrupt.
fn read_secret(ctx: &mut Ctx, prompt: &str) -> Option<String> {
    ctx.flush();
    let Some(tty) = ctx.stdin_tty() else {
        ctx.eprint(prompt);
        let mut line = Vec::new();
        let mut b = [0u8; 1];
        loop {
            match ctx.read_stdin(&mut b) {
                Ok(1) if b[0] == b'\n' => break,
                Ok(1) => line.push(b[0]),
                Ok(_) if !line.is_empty() => break,
                _ => return None,
            }
        }
        return Some(String::from_utf8_lossy(&line).trim_end_matches('\r').to_string());
    };
    let saved = tty.termios();
    let mut t = saved;
    t.lflag &= !(crate::tty::consts::ECHO | crate::tty::consts::ECHONL);
    t.lflag |= crate::tty::consts::ICANON;
    tty.set_termios(t);
    let _ = tty.write(prompt.as_bytes());
    let mut line = Vec::new();
    let mut buf = [0u8; 256];
    let ok = loop {
        match tty.read(&mut buf, false) {
            Ok(0) => break !line.is_empty(),
            Ok(n) => {
                line.extend_from_slice(&buf[..n]);
                if line.last() == Some(&b'\n') {
                    break true;
                }
                if line.len() > 4096 {
                    break false;
                }
            }
            Err(_) => break false,
        }
    };
    tty.set_termios(saved);
    let _ = tty.write(b"\n");
    if !ok {
        return None;
    }
    let s = String::from_utf8_lossy(&line).trim_end_matches(['\n', '\r']).to_string();
    Some(s)
}

fn tty_name(ctx: &Ctx) -> String {
    ctx.proc.ctty.lock().as_ref().map(|t| t.name.clone()).unwrap_or_else(|| String::from("unknown"))
}

fn caller(ctx: &Ctx) -> Option<User> {
    users::by_uid(ctx.cred().uid)
}

/// Password quality for non-root users. `Err` carries the pam-style reason.
fn check_quality(user: &str, pw: &str) -> Result<(), &'static str> {
    if pw.chars().count() < MIN_PASSWORD {
        return Err("The password is shorter than 8 characters");
    }
    if pw.eq_ignore_ascii_case(user) || pw.to_lowercase().contains(&user.to_lowercase()) {
        return Err("The password contains the user name in some form");
    }
    if pw.chars().all(|c| c.is_ascii_digit()) {
        return Err("The password contains only digits");
    }
    Ok(())
}

fn usage(ctx: &mut Ctx, msg: &str, usage: &str) -> i32 {
    if !msg.is_empty() {
        let m = alloc::format!("{}: {}\n", ctx.name(), msg);
        ctx.eprint(&m);
    }
    let u = alloc::format!("Usage: {} {}\n", ctx.name(), usage);
    ctx.eprint(&u);
    2
}

// ── passwd ─────────────────────────────────────────────────────────────────

pub fn passwd(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "luSde",
        values: "",
        long: &[("lock", 'l', false), ("unlock", 'u', false), ("status", 'S', false), ("delete", 'd', false), ("expire", 'e', false), ("stdin", 'i', false)],
    };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(e) => return usage(ctx, &e, "[-l|-u|-S] [--stdin] [LOGIN]"),
    };
    let me = ctx.cred();
    let Some(self_user) = caller(ctx) else { return ctx.fail("You don't exist. Go away!") };
    let target_name = p.operands.first().cloned().unwrap_or_else(|| self_user.name.clone());
    let Some(target) = users::by_name(&target_name) else {
        ctx.eprint(&alloc::format!("passwd: user '{target_name}' does not exist\n"));
        return 1;
    };
    let root = me.is_root();
    if !root && target.uid != me.uid {
        ctx.eprint(&alloc::format!("passwd: You may not view or modify password information for {}.\n", target.name));
        return 1;
    }
    if p.has('S') {
        let st = users::password_status(&target.name).unwrap_or("NP");
        let tm = crate::time::civil::from_unix(crate::time::unix_now() as i64);
        outln!(ctx, "{} {} {:02}/{:02}/{} 0 99999 7 -1", target.name, st, tm.month, tm.day, tm.year);
        return 0;
    }
    if p.has('l') || p.has('u') || p.has('d') || p.has('e') {
        if !root {
            return ctx.fail("Permission denied.");
        }
        if p.has('d') {
            // An empty password would allow login without one: refuse.
            return ctx.fail("deleting passwords is disabled on FastROS; use -l to lock the account");
        }
        if p.has('e') {
            return ctx.fail("password expiry is not supported");
        }
        let lock = p.has('l');
        return match users::lock_password(&target.name, lock) {
            Ok(()) => {
                crate::knotice!("auth", "passwd: {} {} by uid {}", if lock { "locked" } else { "unlocked" }, target.name, me.uid);
                outln!(ctx, "passwd: password changed.");
                0
            }
            Err(e) => ctx.fail(alloc::format!("{e}")),
        };
    }
    let from_stdin = ctx.args.iter().any(|a| a == "--stdin");
    if from_stdin && !root {
        return ctx.fail("Only root can use --stdin.");
    }
    if !from_stdin && ctx.stdin_tty().is_none() && !root {
        return ctx.fail("a terminal is required to change passwords");
    }
    if from_stdin {
        let Some(pw) = read_secret(ctx, "") else { return ctx.fail("no password on standard input") };
        if pw.is_empty() {
            return ctx.fail("empty password");
        }
        return match users::set_password(&target.name, &pw) {
            Ok(()) => {
                crate::knotice!("auth", "passwd: password changed for {} by uid {}", target.name, me.uid);
                outln!(ctx, "passwd: password updated successfully");
                0
            }
            Err(e) => ctx.fail(alloc::format!("{e}")),
        };
    }
    if !root {
        outln!(ctx, "Changing password for {}.", target.name);
        let Some(cur) = read_secret(ctx, "Current password: ") else { return 1 };
        if users::authenticate(&target.name, &cur).is_err() {
            crate::sched::sleep_ms(FAIL_DELAY_MS);
            crate::kwarn!("auth", "passwd: authentication failure for {} on {}", target.name, tty_name(ctx));
            ctx.eprint("passwd: Authentication token manipulation error\npasswd: password unchanged\n");
            return 10;
        }
    }
    for _attempt in 0..3 {
        let Some(new) = read_secret(ctx, "New password: ") else { return 10 };
        if new.is_empty() {
            ctx.eprint("No password has been supplied.\n");
            continue;
        }
        if let Err(why) = check_quality(&target.name, &new) {
            ctx.eprint(&alloc::format!("BAD PASSWORD: {why}\n"));
            if !root {
                continue;
            }
        }
        let Some(again) = read_secret(ctx, "Retype new password: ") else { return 10 };
        if again != new {
            ctx.eprint("Sorry, passwords do not match.\n");
            continue;
        }
        return match users::set_password(&target.name, &new) {
            Ok(()) => {
                crate::knotice!("auth", "passwd: password changed for {} by uid {}", target.name, me.uid);
                outln!(ctx, "passwd: password updated successfully");
                0
            }
            Err(e) => {
                ctx.eprint(&alloc::format!("passwd: Authentication token manipulation error ({e})\npasswd: password unchanged\n"));
                10
            }
        };
    }
    ctx.eprint("passwd: Have exhausted maximum number of retries for service\npasswd: password unchanged\n");
    10
}

// ── su ─────────────────────────────────────────────────────────────────────

fn shell_usable(u: &User) -> bool {
    !matches!(u.shell.rsplit('/').next(), Some("false" | "nologin"))
}

/// Give the current process `target`'s identity and a session environment.
fn become_user(ctx: &Ctx, target: &User, login: bool, keep_env: bool) {
    *ctx.proc.cred.lock() = users::cred_for(target);
    let mut env = ctx.proc.env.lock();
    let term = env.iter().find(|(k, _)| k == "TERM").map(|(_, v)| v.clone());
    let set = |env: &mut Vec<(String, String)>, k: &str, v: &str| {
        env.retain(|(ek, _)| ek != k);
        env.push((String::from(k), String::from(v)));
    };
    if login {
        env.clear();
        set(&mut env, "PATH", "/bin:/usr/local/bin");
        if let Some(t) = term {
            set(&mut env, "TERM", &t);
        }
    }
    if !keep_env || login {
        set(&mut env, "HOME", &target.home);
        set(&mut env, "SHELL", "/bin/sh");
        if target.uid != 0 || login {
            set(&mut env, "USER", &target.name);
            set(&mut env, "LOGNAME", &target.name);
        }
    }
}

pub fn su(ctx: &mut Ctx) -> i32 {
    let mut login = false;
    let mut command: Option<String> = None;
    let mut keep_env = false;
    let mut name: Option<String> = None;
    let args = ctx.args[1..].to_vec();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "-" | "-l" | "--login" => login = true,
            "-m" | "-p" | "--preserve-environment" => keep_env = true,
            "-c" | "--command" => {
                i += 1;
                match args.get(i) {
                    Some(c) => command = Some(c.clone()),
                    None => return usage(ctx, "option requires an argument -- 'c'", "[options] [-] [<user> [<argument>...]]"),
                }
            }
            "-s" | "--shell" => {
                i += 1; // only /bin/sh exists
            }
            s if s.starts_with("--command=") => command = Some(s["--command=".len()..].to_string()),
            s if s.starts_with('-') => return usage(ctx, &alloc::format!("invalid option -- '{}'", &s[1..]), "[options] [-] [<user> [<argument>...]]"),
            s => {
                if name.is_none() {
                    name = Some(s.to_string());
                } else {
                    return usage(ctx, "too many arguments", "[options] [-] [<user> [<argument>...]]");
                }
            }
        }
        i += 1;
    }
    let target_name = name.unwrap_or_else(|| String::from("root"));
    let Some(target) = users::by_name(&target_name) else {
        ctx.eprint(&alloc::format!("su: user {target_name} does not exist or the user entry does not contain all the required fields\n"));
        return 1;
    };
    let me = ctx.cred();
    let who = caller(ctx).map(|u| u.name).unwrap_or_else(|| me.uid.to_string());
    if !me.is_root() {
        if target.uid == 0 && !caller(ctx).is_some_and(|u| users::is_admin(&u)) {
            crate::kwarn!("auth", "su: {} is not in wheel/sudo: denied (to root) on {}", who, tty_name(ctx));
            ctx.eprint("su: Permission denied\n");
            return 1;
        }
        let Some(pw) = read_secret(ctx, "Password: ") else { return 1 };
        if users::authenticate(&target.name, &pw).is_err() {
            crate::sched::sleep_ms(FAIL_DELAY_MS);
            crate::kwarn!("auth", "su: FAILED SU (to {}) {} on {}", target.name, who, tty_name(ctx));
            ctx.eprint("su: Authentication failure\n");
            return 1;
        }
    }
    if !shell_usable(&target) {
        ctx.eprint("This account is currently not available.\n");
        return 1;
    }
    crate::knotice!("auth", "su: (to {}) {} on {}", target.name, who, tty_name(ctx));
    become_user(ctx, &target, login, keep_env);
    ctx.flush();
    crate::shell::user_shell(&target, login, command)
}

// ── sudo ───────────────────────────────────────────────────────────────────

/// Cached sudo authentications: (uid, session id) → expiry.
static SUDO_CACHE: SpinLock<Vec<(u32, u32, u64)>> = SpinLock::new(Vec::new());

fn sudo_cached(uid: u32, sid: u32) -> bool {
    let now = crate::time::now_ns();
    let mut c = SUDO_CACHE.lock();
    c.retain(|&(_, _, exp)| exp > now);
    c.iter().any(|&(u, s, _)| u == uid && s == sid)
}

fn sudo_remember(uid: u32, sid: u32) {
    let exp = crate::time::now_ns() + SUDO_TIMEOUT_NS;
    let mut c = SUDO_CACHE.lock();
    c.retain(|&(u, s, _)| !(u == uid && s == sid));
    c.push((uid, sid, exp));
}

fn sudo_forget(uid: u32, sid: Option<u32>) {
    SUDO_CACHE.lock().retain(|&(u, s, _)| !(u == uid && sid.is_none_or(|x| x == s)));
}

pub fn sudo(ctx: &mut Ctx) -> i32 {
    let args = ctx.args[1..].to_vec();
    let mut target_name = String::from("root");
    let (mut login, mut shell, mut list, mut validate, mut non_interactive, mut stdin_pw, mut keep_env) = (false, false, false, false, false, false, false);
    let (mut kill_ts, mut remove_ts) = (false, false);
    let mut i = 0;
    while i < args.len() && args[i].starts_with('-') && args[i] != "-" {
        let a = args[i].clone();
        if a == "--" {
            i += 1;
            break;
        }
        let mut chars: Vec<char> = a[1..].chars().collect();
        if a.starts_with("--") {
            chars = match &a[2..] {
                "login" => alloc::vec!['i'],
                "shell" => alloc::vec!['s'],
                "list" => alloc::vec!['l'],
                "validate" => alloc::vec!['v'],
                "non-interactive" => alloc::vec!['n'],
                "stdin" => alloc::vec!['S'],
                "preserve-env" => alloc::vec!['E'],
                "reset-timestamp" => alloc::vec!['k'],
                "remove-timestamp" => alloc::vec!['K'],
                "user" => alloc::vec!['u'],
                other => return usage(ctx, &alloc::format!("unrecognized option '--{other}'"), "[-iklnsSvEK] [-u user] [command [arg ...]]"),
            };
        }
        let mut j = 0;
        while j < chars.len() {
            match chars[j] {
                'i' => login = true,
                's' => shell = true,
                'l' => list = true,
                'v' => validate = true,
                'n' => non_interactive = true,
                'S' => stdin_pw = true,
                'E' => keep_env = true,
                'k' => kill_ts = true,
                'K' => remove_ts = true,
                'u' => {
                    let rest: String = chars[j + 1..].iter().collect();
                    if !rest.is_empty() {
                        target_name = rest;
                    } else {
                        i += 1;
                        match args.get(i) {
                            Some(u) => target_name = u.clone(),
                            None => return usage(ctx, "option requires an argument -- 'u'", "[-u user] [command [arg ...]]"),
                        }
                    }
                    j = chars.len();
                    continue;
                }
                c => return usage(ctx, &alloc::format!("invalid option -- '{c}'"), "[-iklnsSvEK] [-u user] [command [arg ...]]"),
            }
            j += 1;
        }
        i += 1;
    }
    let cmd: Vec<String> = args[i..].to_vec();
    let me = ctx.cred();
    let sid = ctx.proc.sid.load(core::sync::atomic::Ordering::Relaxed);
    let Some(user) = caller(ctx) else { return ctx.fail("you do not exist in the passwd database") };
    if remove_ts {
        sudo_forget(me.uid, None);
        return 0;
    }
    if kill_ts {
        sudo_forget(me.uid, Some(sid));
        if cmd.is_empty() && !validate && !list && !login && !shell {
            return 0;
        }
    }
    let tty = tty_name(ctx);
    let pwd = ctx.cwd();
    if !me.is_root() && !users::is_admin(&user) {
        crate::kwarn!("sudo", "{} : user NOT in sudoers ; TTY={} ; PWD={} ; USER={} ; COMMAND={}", user.name, tty, pwd, target_name, cmd.join(" "));
        ctx.eprint(&alloc::format!("{} is not in the sudoers file.  This incident will be reported.\n", user.name));
        return 1;
    }
    if list {
        let host = ctx.proc.uts.hostname.lock().clone();
        outln!(ctx, "User {} may run the following commands on {}:", user.name, host);
        outln!(ctx, "    (ALL : ALL) ALL");
        return 0;
    }
    // Authenticate (the caller's own password), unless root or cached.
    if !me.is_root() && !sudo_cached(me.uid, sid) {
        if non_interactive {
            ctx.eprint("sudo: a password is required\n");
            return 1;
        }
        let mut ok = false;
        for attempt in 0..3 {
            let pw = if stdin_pw {
                let mut b = Vec::new();
                let mut c = [0u8; 1];
                let _ = ctx.flush();
                ctx.eprint(&alloc::format!("[sudo] password for {}: ", user.name));
                while let Ok(1) = ctx.read_stdin(&mut c) {
                    if c[0] == b'\n' {
                        break;
                    }
                    b.push(c[0]);
                }
                Some(String::from_utf8_lossy(&b).into_owned())
            } else {
                read_secret(ctx, &alloc::format!("[sudo] password for {}: ", user.name))
            };
            let Some(pw) = pw else { return 1 };
            if users::authenticate(&user.name, &pw).is_ok() {
                ok = true;
                break;
            }
            crate::sched::sleep_ms(FAIL_DELAY_MS);
            if attempt < 2 && !stdin_pw {
                ctx.eprint("Sorry, try again.\n");
            } else if stdin_pw {
                break;
            }
        }
        if !ok {
            crate::kwarn!("sudo", "{} : 3 incorrect password attempts ; TTY={} ; PWD={} ; USER={} ; COMMAND={}", user.name, tty, pwd, target_name, cmd.join(" "));
            ctx.eprint("sudo: 3 incorrect password attempts\n");
            return 1;
        }
        sudo_remember(me.uid, sid);
    }
    if validate && cmd.is_empty() {
        return 0;
    }
    let Some(target) = users::by_name(&target_name).or_else(|| target_name.strip_prefix('#').and_then(|n| n.parse().ok()).and_then(users::by_uid)) else {
        ctx.eprint(&alloc::format!("sudo: unknown user {target_name}\n"));
        return 1;
    };
    if cmd.is_empty() && !login && !shell {
        return usage(ctx, "", "-h | -K | -k | -V\nusage: sudo -v [-u user]\nusage: sudo -l [-u user]\nusage: sudo [-iEnS] [-u user] [command [arg ...]]");
    }
    crate::knotice!("sudo", "{} : TTY={} ; PWD={} ; USER={} ; COMMAND={}", user.name, tty, pwd, target.name, if cmd.is_empty() { String::from("/bin/sh") } else { cmd.join(" ") });
    // The environment the command gets (env_reset, plus SUDO_* markers).
    let mut env: Vec<(String, String)> = if keep_env { ctx.proc.env.lock().clone() } else { Vec::new() };
    let old_env = ctx.proc.env.lock().clone();
    let mut set = |k: &str, v: &str| {
        env.retain(|(ek, _)| ek != k);
        env.push((String::from(k), String::from(v)));
    };
    for keep in ["TERM", "COLUMNS", "LINES", "LANG", "DISPLAY"] {
        if let Some((_, v)) = old_env.iter().find(|(k, _)| k == keep) {
            set(keep, v);
        }
    }
    set("PATH", "/bin:/usr/local/bin");
    set("HOME", &target.home);
    set("SHELL", "/bin/sh");
    set("USER", &target.name);
    set("LOGNAME", &target.name);
    set("SUDO_USER", &user.name);
    set("SUDO_UID", &me.uid.to_string());
    set("SUDO_GID", &me.gid.to_string());
    set("SUDO_COMMAND", &if cmd.is_empty() { String::from("/bin/sh") } else { cmd.join(" ") });
    if login || shell {
        *ctx.proc.cred.lock() = users::cred_for(&target);
        *ctx.proc.env.lock() = env;
        ctx.flush();
        let command = if cmd.is_empty() { None } else { Some(cmd.join(" ")) };
        return crate::shell::user_shell(&target, login, command);
    }
    ctx.flush();
    crate::shell::run_argv(&ctx.proc, cmd, Some(env), Some(users::cred_for(&target)))
}

// ── useradd / adduser / userdel / usermod ──────────────────────────────────

fn require_root(ctx: &mut Ctx) -> bool {
    if ctx.cred().is_root() {
        return true;
    }
    let m = alloc::format!("{}: Permission denied.\n{}: cannot lock /etc/passwd; try again later.\n", ctx.name(), ctx.name());
    ctx.eprint(&m);
    false
}

pub fn useradd(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "mMrNUD",
        values: "dsugGcek",
        long: &[
            ("create-home", 'm', false),
            ("no-create-home", 'M', false),
            ("system", 'r', false),
            ("home-dir", 'd', true),
            ("shell", 's', true),
            ("uid", 'u', true),
            ("gid", 'g', true),
            ("groups", 'G', true),
            ("comment", 'c', true),
        ],
    };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(e) => return usage(ctx, &e, "[options] LOGIN"),
    };
    if !require_root(ctx) {
        return 1;
    }
    let [name] = p.operands.as_slice() else { return usage(ctx, "", "[options] LOGIN") };
    let uid = match p.value('u').map(|u| u.parse::<u32>()) {
        Some(Ok(u)) if users::by_uid(u).is_some() && users::by_name(name).is_none() => {
            ctx.eprint(&alloc::format!("useradd: UID {u} is not unique\n"));
            return 4;
        }
        Some(Ok(u)) => Some(u),
        Some(Err(_)) => {
            ctx.eprint(&alloc::format!("useradd: invalid user ID '{}'\n", p.value('u').unwrap_or("")));
            return 3;
        }
        None => None,
    };
    let group = match p.value('g') {
        Some(g) => match g.parse::<u32>().ok().or_else(|| users::group_by_name(g).map(|x| x.gid)) {
            Some(gid) => Some(gid),
            None => {
                ctx.eprint(&alloc::format!("useradd: group '{g}' does not exist\n"));
                return 6;
            }
        },
        None => None,
    };
    let extra: Vec<String> = p.value('G').map(|g| g.split(',').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect()).unwrap_or_default();
    for g in &extra {
        if users::group_by_name(g).is_none() {
            ctx.eprint(&alloc::format!("useradd: group '{g}' does not exist\n"));
            return 6;
        }
    }
    let shell = p.value('s').unwrap_or("/bin/sh").to_string();
    let gecos = p.value('c').unwrap_or("").to_string();
    let home = p.value('d').map(|s| s.to_string());
    let n = users::NewUser {
        name,
        uid,
        group,
        gecos: &gecos,
        home: home.as_deref(),
        shell: &shell,
        create_home: p.has('m') || ctx.name() == "adduser",
        extra_groups: extra,
    };
    match users::add_user(&n) {
        Ok(u) => {
            crate::knotice!("auth", "useradd: new user: name={}, UID={}, GID={}, home={}, shell={}, by uid {}", u.name, u.uid, u.gid, u.home, u.shell, ctx.cred().uid);
            0
        }
        Err(Errno::EEXIST) => {
            ctx.eprint(&alloc::format!("{}: user '{}' already exists\n", ctx.name(), name));
            9
        }
        Err(Errno::EINVAL) => {
            ctx.eprint(&alloc::format!("{}: invalid user name '{}'\n", ctx.name(), name));
            3
        }
        Err(e) => {
            ctx.eprint(&alloc::format!("{}: cannot create user: {}\n", ctx.name(), e));
            1
        }
    }
}

/// `adduser NAME`: useradd -m, then set the password interactively.
pub fn adduser(ctx: &mut Ctx) -> i32 {
    let name = match ctx.args.iter().skip(1).find(|a| !a.starts_with('-')) {
        Some(n) => n.clone(),
        None => return usage(ctx, "", "[--gecos GECOS] [--ingroup GROUP] USER"),
    };
    let code = useradd(ctx);
    if code != 0 {
        return code;
    }
    let u = users::by_name(&name).expect("just created");
    outln!(ctx, "Adding user `{}' ...", u.name);
    outln!(ctx, "Adding new group `{}' ({}) ...", users::group_name(u.gid), u.gid);
    outln!(ctx, "Adding new user `{}' ({}) with group `{}' ...", u.name, u.uid, users::group_name(u.gid));
    outln!(ctx, "Creating home directory `{}' ...", u.home);
    for _ in 0..3 {
        let Some(pw) = read_secret(ctx, "New password: ") else { break };
        if let Err(why) = check_quality(&u.name, &pw) {
            ctx.eprint(&alloc::format!("BAD PASSWORD: {why}\n"));
            continue;
        }
        let Some(again) = read_secret(ctx, "Retype new password: ") else { break };
        if again != pw {
            ctx.eprint("Sorry, passwords do not match.\n");
            continue;
        }
        if users::set_password(&u.name, &pw).is_ok() {
            outln!(ctx, "passwd: password updated successfully");
            return 0;
        }
    }
    outln!(ctx, "The account is locked until a password is set with `passwd {}'.", u.name);
    0
}

pub fn userdel(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "rf", values: "", long: &[("remove", 'r', false), ("force", 'f', false)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(e) => return usage(ctx, &e, "[options] LOGIN"),
    };
    if !require_root(ctx) {
        return 1;
    }
    let [name] = p.operands.as_slice() else { return usage(ctx, "", "[options] LOGIN") };
    let Some(u) = users::by_name(name) else {
        ctx.eprint(&alloc::format!("userdel: user '{name}' does not exist\n"));
        return 6;
    };
    if !p.has('f') {
        if let Some(busy) = crate::proc::all().into_iter().find(|pr| !pr.is_zombie() && pr.cred().uid == u.uid) {
            ctx.eprint(&alloc::format!("userdel: user {} is currently used by process {}\n", u.name, busy.pid));
            return 8;
        }
    }
    match users::del_user(name, p.has('r')) {
        Ok(()) => {
            crate::knotice!("auth", "userdel: delete user '{}' by uid {}", name, ctx.cred().uid);
            0
        }
        Err(Errno::EPERM) => {
            ctx.eprint("userdel: refusing to delete the superuser\n");
            1
        }
        Err(e) => {
            ctx.eprint(&alloc::format!("userdel: {e}\n"));
            1
        }
    }
}

pub fn usermod(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "aLUm",
        values: "sdcgGl",
        long: &[("append", 'a', false), ("lock", 'L', false), ("unlock", 'U', false), ("move-home", 'm', false), ("shell", 's', true), ("home", 'd', true), ("comment", 'c', true), ("gid", 'g', true), ("groups", 'G', true), ("login", 'l', true)],
    };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(e) => return usage(ctx, &e, "[options] LOGIN"),
    };
    if !require_root(ctx) {
        return 1;
    }
    let [name] = p.operands.as_slice() else { return usage(ctx, "", "[options] LOGIN") };
    let name = name.clone();
    if users::by_name(&name).is_none() {
        ctx.eprint(&alloc::format!("usermod: user '{name}' does not exist\n"));
        return 6;
    }
    let gid = match p.value('g') {
        Some(g) => match g.parse::<u32>().ok().or_else(|| users::group_by_name(g).map(|x| x.gid)) {
            Some(v) => Some(v),
            None => {
                ctx.eprint(&alloc::format!("usermod: group '{g}' does not exist\n"));
                return 6;
            }
        },
        None => None,
    };
    let new_login = p.value('l').map(|s| s.to_string());
    if let Some(l) = &new_login {
        if !users::valid_name(l) {
            ctx.eprint(&alloc::format!("usermod: invalid user name '{l}'\n"));
            return 3;
        }
    }
    if new_login.is_some() && users::by_name(&name).is_some_and(|u| u.uid == 0) {
        return ctx.fail("renaming root is not allowed");
    }
    let (shell, home, comment) = (p.value('s').map(String::from), p.value('d').map(String::from), p.value('c').map(String::from));
    let changed = users::modify_user(&name, |u| {
        if let Some(s) = &shell {
            u.shell = s.clone();
        }
        if let Some(h) = &home {
            u.home = h.clone();
        }
        if let Some(c) = &comment {
            u.gecos = c.clone();
        }
        if let Some(g) = gid {
            u.gid = g;
        }
        if let Some(l) = &new_login {
            u.name = l.clone();
        }
        Ok(())
    });
    if let Err(e) = changed {
        ctx.eprint(&alloc::format!("usermod: {e}\n"));
        return 1;
    }
    if let Some(groups) = p.value('G') {
        let list: Vec<String> = groups.split(',').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect();
        for g in &list {
            if users::group_by_name(g).is_none() {
                ctx.eprint(&alloc::format!("usermod: group '{g}' does not exist\n"));
                return 6;
            }
        }
        let r = if p.has('a') {
            list.iter().try_for_each(|g| users::add_to_group(&name, g))
        } else {
            users::set_groups(&name, &list)
        };
        if let Err(e) = r {
            ctx.eprint(&alloc::format!("usermod: {e}\n"));
            return 1;
        }
    }
    if p.has('L') || p.has('U') {
        if let Err(e) = users::lock_password(&name, p.has('L')) {
            ctx.eprint(&alloc::format!("usermod: {e}\n"));
            return 1;
        }
    }
    crate::knotice!("auth", "usermod: change user '{}' by uid {}", name, ctx.cred().uid);
    0
}

// ── groups ─────────────────────────────────────────────────────────────────

pub fn groupadd(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "rf", values: "g", long: &[("gid", 'g', true), ("system", 'r', false), ("force", 'f', false)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(e) => return usage(ctx, &e, "[options] GROUP"),
    };
    if !require_root(ctx) {
        return 1;
    }
    let [name] = p.operands.as_slice() else { return usage(ctx, "", "[options] GROUP") };
    let gid = match p.value('g').map(|g| g.parse::<u32>()) {
        Some(Ok(g)) => Some(g),
        Some(Err(_)) => {
            ctx.eprint(&alloc::format!("groupadd: invalid group ID '{}'\n", p.value('g').unwrap_or("")));
            return 3;
        }
        None => None,
    };
    match users::add_group(name, gid) {
        Ok(_) => 0,
        Err(Errno::EEXIST) if p.has('f') => 0,
        Err(Errno::EEXIST) => {
            if users::group_by_name(name).is_some() {
                ctx.eprint(&alloc::format!("groupadd: group '{name}' already exists\n"));
            } else {
                ctx.eprint(&alloc::format!("groupadd: GID '{}' already exists\n", gid.unwrap_or(0)));
            }
            if users::group_by_name(name).is_some() {
                9
            } else {
                4
            }
        }
        Err(Errno::EINVAL) => {
            ctx.eprint(&alloc::format!("groupadd: '{name}' is not a valid group name\n"));
            3
        }
        Err(e) => {
            ctx.eprint(&alloc::format!("groupadd: {e}\n"));
            10
        }
    }
}

pub fn groupdel(ctx: &mut Ctx) -> i32 {
    if !require_root(ctx) {
        return 1;
    }
    let Some(name) = ctx.args.get(1).cloned() else { return usage(ctx, "", "GROUP") };
    match users::del_group(&name) {
        Ok(()) => 0,
        Err(Errno::ENOENT) => {
            ctx.eprint(&alloc::format!("groupdel: group '{name}' does not exist\n"));
            6
        }
        Err(Errno::EBUSY) => {
            let owner = users::users().into_iter().find(|u| users::group_by_name(&name).is_some_and(|g| g.gid == u.gid)).map(|u| u.name).unwrap_or_default();
            ctx.eprint(&alloc::format!("groupdel: cannot remove the primary group of user '{owner}'\n"));
            8
        }
        Err(e) => {
            ctx.eprint(&alloc::format!("groupdel: {e}\n"));
            10
        }
    }
}

pub fn gpasswd(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "", values: "adM", long: &[("add", 'a', true), ("delete", 'd', true), ("members", 'M', true)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(e) => return usage(ctx, &e, "[-a USER | -d USER | -M USER,...] GROUP"),
    };
    if !require_root(ctx) {
        return 1;
    }
    let [group] = p.operands.as_slice() else { return usage(ctx, "", "[-a USER | -d USER | -M USER,...] GROUP") };
    if users::group_by_name(group).is_none() {
        ctx.eprint(&alloc::format!("gpasswd: group '{group}' does not exist in /etc/group\n"));
        return 3;
    }
    if let Some(u) = p.value('a') {
        if users::by_name(u).is_none() {
            ctx.eprint(&alloc::format!("gpasswd: user '{u}' does not exist\n"));
            return 3;
        }
        outln!(ctx, "Adding user {} to group {}", u, group);
        return match users::add_to_group(u, group) {
            Ok(()) => 0,
            Err(e) => ctx.fail(e),
        };
    }
    if let Some(u) = p.value('d') {
        outln!(ctx, "Removing user {} from group {}", u, group);
        return match users::remove_from_group(u, group) {
            Ok(()) => 0,
            Err(Errno::ESRCH) => {
                ctx.eprint(&alloc::format!("gpasswd: user '{u}' is not a member of '{group}'\n"));
                3
            }
            Err(e) => ctx.fail(e),
        };
    }
    if let Some(list) = p.value('M') {
        for u in list.split(',').filter(|s| !s.is_empty()) {
            if let Err(e) = users::add_to_group(u, group) {
                return ctx.fail(e);
            }
        }
        return 0;
    }
    usage(ctx, "", "[-a USER | -d USER | -M USER,...] GROUP")
}

pub fn chpasswd(ctx: &mut Ctx) -> i32 {
    if !require_root(ctx) {
        return 1;
    }
    let data = match ctx.read_input("-") {
        Ok(d) => d,
        Err(e) => return ctx.fail_errno("stdin", e),
    };
    let text = String::from_utf8_lossy(&data).into_owned();
    let mut st = 0;
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let Some((user, pw)) = line.split_once(':') else {
            ctx.eprint(&alloc::format!("chpasswd: line {}: missing new password\n", n + 1));
            st = 1;
            continue;
        };
        match users::set_password(user, pw) {
            Ok(()) => crate::knotice!("auth", "chpasswd: password changed for {}", user),
            Err(_) => {
                ctx.eprint(&alloc::format!("chpasswd: line {}: user '{}' does not exist\n", n + 1, user));
                st = 1;
            }
        }
    }
    st
}
