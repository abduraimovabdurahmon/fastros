//! `fsh` — the FastROS shell.
//!
//! A POSIX-style shell (see `fastros_sh` for the language) whose external
//! commands are native kernel programs (`/bin`, see [`cmds`]). Every
//! command runs as its own process with its own descriptor table, so pipes,
//! redirections, `kill`, `ps` and job control behave as on Linux.

pub mod binfs;
pub mod builtins;
pub mod cmds;
pub mod ctx;
pub mod exec;
pub mod history;
pub mod readline;
pub mod tui;

use crate::fs::file::File;
use crate::proc::{Pid, Process};
use crate::tty::Tty;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use fastros_sh::ast;

#[derive(Clone, Debug)]
pub struct Var {
    pub value: String,
    pub exported: bool,
    pub readonly: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Opts {
    pub errexit: bool,
    pub nounset: bool,
    pub xtrace: bool,
    pub noclobber: bool,
    pub noglob: bool,
}

#[derive(Clone, Debug)]
pub struct Job {
    pub id: usize,
    pub pgid: Pid,
    pub pids: Vec<Pid>,
    pub cmd: String,
    pub done: Option<i32>,
}

/// Loop control / function return requested by `break`, `continue`, `return`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    Normal,
    Break(u32),
    Continue(u32),
    Return,
    Exit,
    /// ^C killed a foreground job of an interactive shell: abandon the rest
    /// of the command line and go back to the prompt.
    Interrupt,
}

#[derive(Clone)]
pub struct Shell {
    pub vars: BTreeMap<String, Var>,
    pub funcs: BTreeMap<String, Arc<ast::Command>>,
    pub aliases: BTreeMap<String, String>,
    pub args: Vec<String>,
    pub arg0: String,
    pub status: i32,
    pub last_bg: Option<Pid>,
    pub opts: Opts,
    pub interactive: bool,
    pub login: bool,
    pub jobs: Vec<Job>,
    pub proc: Arc<Process>,
    pub flow: Flow,
    pub loop_depth: u32,
    pub func_depth: u32,
    /// Saved variables of enclosing function scopes (`local`).
    pub locals: Vec<Vec<(String, Option<Var>)>>,
    pub exit_code: i32,
    pub history: history::History,
    pub traps: BTreeMap<String, String>,
    /// Signals that arrived while waiting for a foreground child; acted on
    /// (trap or default action) once the child is gone, as bash does.
    pub deferred_signals: u64,
    /// Set by `exec` without a command: keep the current redirections.
    pub keep_redirs: bool,
}

impl Shell {
    /// A shell running in `proc`, seeded from the process environment.
    pub fn new(proc: Arc<Process>, interactive: bool) -> Shell {
        let mut vars = BTreeMap::new();
        for (k, v) in proc.env.lock().iter() {
            vars.insert(k.clone(), Var { value: v.clone(), exported: true, readonly: false });
        }
        let mut sh = Shell {
            vars,
            funcs: BTreeMap::new(),
            aliases: BTreeMap::new(),
            args: Vec::new(),
            arg0: String::from("fsh"),
            status: 0,
            last_bg: None,
            opts: Opts::default(),
            interactive,
            login: false,
            jobs: Vec::new(),
            proc,
            flow: Flow::Normal,
            loop_depth: 0,
            func_depth: 0,
            locals: Vec::new(),
            exit_code: 0,
            history: history::History::new(),
            traps: BTreeMap::new(),
            deferred_signals: 0,
            keep_redirs: false,
        };
        sh.set_default("PATH", "/bin:/usr/local/bin", true);
        sh.set_default("IFS", " \t\n", false);
        sh.set_default("PS2", "> ", false);
        let pwd = sh.proc.fs.lock().cwd.path();
        sh.set_var("PWD", &pwd, true);
        sh.set_default("SHELL", "/bin/sh", true);
        sh
    }

    fn set_default(&mut self, k: &str, v: &str, export: bool) {
        if !self.vars.contains_key(k) {
            self.vars.insert(k.to_string(), Var { value: v.to_string(), exported: export, readonly: false });
        }
    }

    pub fn var(&self, k: &str) -> Option<String> {
        self.vars.get(k).map(|v| v.value.clone())
    }

    pub fn set_var(&mut self, k: &str, v: &str, export: bool) -> Result<(), String> {
        if let Some(old) = self.vars.get_mut(k) {
            if old.readonly {
                return Err(alloc::format!("{k}: readonly variable"));
            }
            old.value = v.to_string();
            old.exported |= export;
        } else {
            self.vars.insert(k.to_string(), Var { value: v.to_string(), exported: export, readonly: false });
        }
        if old_is_exported(self, k) {
            self.sync_env();
        }
        Ok(())
    }

    pub fn unset_var(&mut self, k: &str) -> Result<(), String> {
        if self.vars.get(k).is_some_and(|v| v.readonly) {
            return Err(alloc::format!("{k}: cannot unset: readonly variable"));
        }
        self.vars.remove(k);
        self.sync_env();
        Ok(())
    }

    /// Exported variables, as the environment of child processes.
    pub fn environ(&self) -> Vec<(String, String)> {
        self.vars.iter().filter(|(_, v)| v.exported).map(|(k, v)| (k.clone(), v.value.clone())).collect()
    }

    /// Keep the process environment (what /proc/<pid>/environ and children
    /// see) equal to the exported variables.
    pub fn sync_env(&self) {
        *self.proc.env.lock() = self.environ();
    }

    pub fn tty(&self) -> Option<Arc<Tty>> {
        self.proc.ctty.lock().clone()
    }

    fn stdout(&self) -> Option<Arc<dyn File>> {
        self.proc.fds.lock().get(1).ok()
    }

    /// Write to the shell's own stdout / stderr.
    pub fn out(&self, s: &str) {
        if let Some(f) = self.stdout() {
            let _ = f.write_all(s.as_bytes());
        }
    }
    pub fn err(&self, s: &str) {
        if let Ok(f) = self.proc.fds.lock().get(2) {
            let _ = f.write_all(s.as_bytes());
        }
    }
    /// `fsh: msg`
    pub fn error(&self, msg: &str) {
        let prefix = if self.interactive { String::from("fsh") } else { self.arg0.clone() };
        self.err(&alloc::format!("{prefix}: {msg}\n"));
    }

    pub fn pgid(&self) -> Pid {
        self.proc.pgid.load(Ordering::Relaxed)
    }

    /// Expand the prompt string (`PS1` escapes like bash).
    pub fn prompt(&self, ps: &str) -> String {
        let mut out = String::new();
        let mut it = ps.chars().peekable();
        let cred = self.proc.cred();
        while let Some(c) = it.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            match it.next() {
                Some('u') => out.push_str(&crate::users::user_name(cred.euid)),
                Some('h') => {
                    let h = self.proc.uts.hostname.lock().clone();
                    out.push_str(h.split('.').next().unwrap_or(&h));
                }
                Some('H') => out.push_str(&self.proc.uts.hostname.lock()),
                Some(w @ ('w' | 'W')) => {
                    let pwd = self.var("PWD").unwrap_or_else(|| self.proc.fs.lock().cwd.path());
                    let home = self.var("HOME").unwrap_or_default();
                    let shown = if !home.is_empty() && home != "/" && (pwd == home || pwd.starts_with(&(home.clone() + "/"))) {
                        alloc::format!("~{}", &pwd[home.len()..])
                    } else {
                        pwd
                    };
                    if w == 'W' && shown != "~" && shown != "/" {
                        // \W: last component only.
                        out.push_str(shown.rsplit('/').next().unwrap_or(&shown));
                    } else {
                        out.push_str(&shown);
                    }
                }
                Some('$') => out.push(if cred.euid == 0 { '#' } else { '$' }),
                Some('n') => out.push('\n'),
                Some('e') => out.push('\x1b'),
                Some('[') => out.push('\x01'),
                Some(']') => out.push('\x02'),
                Some('\\') => out.push('\\'),
                Some('t') => {
                    let tm = crate::time::civil::from_unix(crate::time::unix_now() as i64);
                    out.push_str(&alloc::format!("{:02}:{:02}:{:02}", tm.hour, tm.min, tm.sec));
                }
                Some('s') => out.push_str("fsh"),
                Some('v') => out.push_str(crate::VERSION),
                Some(o) => {
                    out.push('\\');
                    out.push(o);
                }
                None => out.push('\\'),
            }
        }
        out
    }

    /// Source a file if it exists (profile scripts).
    pub fn source_if_exists(&mut self, path: &str) {
        let ctx = crate::fs::ops::Ctx::of(&self.proc);
        if let Ok(data) = crate::fs::ops::read_file(&ctx, path) {
            let src = String::from_utf8_lossy(&data).into_owned();
            self.run_source(&src);
        }
    }

    /// Parse and run a complete program text.
    pub fn run_source(&mut self, src: &str) -> i32 {
        match fastros_sh::parse(src) {
            Ok(list) => self.run_list(&list),
            Err(e) => {
                self.error(&e.msg);
                self.status = 2;
                2
            }
        }
    }
}

impl Shell {
    /// The exit status of a shell process that ran `st` last: settle
    /// deferred signals, run the EXIT trap, honour `exit N`.
    pub fn finish(&mut self, st: i32) -> i32 {
        if self.flow == Flow::Normal {
            self.handle_signals();
        }
        self.run_exit_trap();
        if self.flow == Flow::Exit {
            self.exit_code
        } else {
            st
        }
    }

    /// A signal interrupted a non-interactive shell waiting for a child.
    /// Trapped signals and SIGINT/SIGQUIT (cooperative exit) are deferred
    /// until the child is done; any other fatal signal ends the shell now
    /// (flow = Exit) and this returns true.
    pub fn fatal_while_waiting(&mut self) -> bool {
        use crate::proc::signal::{ignored_by_default, name, SIGINT, SIGKILL, SIGQUIT};
        let pending = crate::sched::with_current(|t| t.pending_signals());
        for sig in 1..=64u32 {
            if pending & (1 << (sig - 1)) == 0 || ignored_by_default(sig) {
                continue;
            }
            if sig != SIGKILL && (sig == SIGINT || sig == SIGQUIT || self.traps.contains_key(&name(sig))) {
                self.deferred_signals |= 1 << (sig - 1);
                continue;
            }
            self.flow = Flow::Exit;
            self.exit_code = 128 + sig as i32;
            return true;
        }
        false
    }

    /// Act on signals sent to the shell itself: run the trap if one is set;
    /// otherwise a non-interactive shell takes the default action (exit with
    /// 128+sig) while an interactive one ignores them, like bash.
    pub fn handle_signals(&mut self) {
        let pending = crate::sched::with_current(|t| t.pending_signals()) | core::mem::take(&mut self.deferred_signals);
        if pending == 0 {
            return;
        }
        for sig in 1..=64u32 {
            if pending & (1 << (sig - 1)) == 0 || sig == crate::proc::signal::SIGKILL {
                continue;
            }
            crate::sched::with_current(|t| t.clear_signal(sig));
            if let Some(action) = self.traps.get(&crate::proc::signal::name(sig)).cloned() {
                if !action.is_empty() {
                    let saved = self.status;
                    self.run_source(&action);
                    self.status = saved;
                }
                continue;
            }
            if crate::proc::signal::ignored_by_default(sig) || self.interactive || matches!(sig, crate::proc::signal::SIGTSTP | crate::proc::signal::SIGTTIN | crate::proc::signal::SIGTTOU | crate::proc::signal::SIGSTOP) {
                continue;
            }
            self.flow = Flow::Exit;
            self.exit_code = 128 + sig as i32;
            return;
        }
    }
}

fn old_is_exported(sh: &Shell, k: &str) -> bool {
    sh.vars.get(k).is_some_and(|v| v.exported)
}

/// Run `argv` (resolved through `PATH`) as a child of `proc` and wait for
/// it. Used by commands that start other commands: `env`, `sudo`, `xargs`,
/// `watch`, `timeout`...
pub fn run_argv(
    proc: &Arc<Process>,
    argv: Vec<String>,
    env: Option<Vec<(String, String)>>,
    cred: Option<crate::fs::perm::Cred>,
) -> i32 {
    let mut sh = Shell::new(proc.clone(), false);
    if let Some(env) = env {
        sh.vars = env.into_iter().map(|(k, v)| (k, Var { value: v, exported: true, readonly: false })).collect();
        sh.set_default("IFS", " \t\n", false);
        if !sh.vars.contains_key("PATH") {
            // `env -i cmd` still finds commands through the default path.
            sh.vars.insert(String::from("PATH"), Var { value: String::from("/bin:/usr/local/bin"), exported: false, readonly: false });
        }
    }
    sh.run_argv_with(argv, cred)
}

/// Entry point of a login shell process (SSH session, console).
pub fn login_shell_main(user: crate::users::User) -> i32 {
    user_shell(&user, true, None)
}

/// A shell for `user` in the current process: interactive, or running
/// `command` (`su -c`, `sudo -s CMD`). A login shell (`login`) starts in the
/// home directory and reads the profiles. The caller has already given the
/// process `user`'s credentials and environment (login, `su`, `sudo -i`).
pub fn user_shell(user: &crate::users::User, login: bool, command: Option<String>) -> i32 {
    let proc = crate::proc::current();
    let interactive = command.is_none();
    let mut sh = Shell::new(proc, interactive);
    sh.login = login;
    if login {
        sh.arg0 = String::from("-fsh");
    }
    let _ = sh.set_var("HOME", &user.home, true);
    let _ = sh.set_var("USER", &user.name, true);
    let _ = sh.set_var("LOGNAME", &user.name, true);
    let _ = sh.set_var("SHELL", "/bin/sh", true);
    if interactive && sh.var("TERM").is_none() {
        let _ = sh.set_var("TERM", "xterm-256color", true);
    }
    let hostname = sh.proc.uts.hostname.lock().clone();
    let _ = sh.set_var("HOSTNAME", &hostname, false);
    let ps1 = if user.uid == 0 {
        "\\[\\e[1;31m\\]\\u@\\h\\[\\e[0m\\]:\\[\\e[1;34m\\]\\w\\[\\e[0m\\]\\$ "
    } else {
        "\\[\\e[1;32m\\]\\u@\\h\\[\\e[0m\\]:\\[\\e[1;34m\\]\\w\\[\\e[0m\\]\\$ "
    };
    sh.set_default("PS1", ps1, false);
    if login && crate::fs::ops::chdir(&sh.proc, &user.home).is_err() {
        let _ = crate::fs::ops::chdir(&sh.proc, "/");
    }
    let pwd = sh.proc.fs.lock().cwd.path();
    let _ = sh.set_var("PWD", &pwd, true);
    sh.sync_env();
    if login {
        sh.source_if_exists("/etc/profile");
        let home_profile = alloc::format!("{}/.profile", user.home);
        sh.source_if_exists(&home_profile);
    }
    match command {
        Some(src) => {
            let code = sh.run_source(&src);
            sh.finish(code)
        }
        None => {
            sh.history.load(&sh.proc, &alloc::format!("{}/.fsh_history", user.home));
            sh.interactive_loop()
        }
    }
}

/// `sh` / `fsh`: the shell as a command.
///
/// `sh -c CMD [NAME [ARG...]]`, `sh FILE [ARG...]`, `sh -s [ARG...]` (script
/// on stdin), or an interactive shell when stdin is a terminal. Options
/// `-e -u -x -f -C` as in POSIX, `-i` forces interactive, `-l` login.
pub fn sh_main(ctx: &mut ctx::Ctx) -> i32 {
    let args = ctx.args.clone();
    let mut opts = Opts::default();
    let (mut command, mut from_stdin, mut force_i, mut login) = (None::<String>, false, false, false);
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            i += 1;
            break;
        }
        if !(a.starts_with('-') || a.starts_with('+')) || a.len() < 2 {
            break;
        }
        let on = a.starts_with('-');
        for c in a[1..].chars() {
            match c {
                'c' => {
                    i += 1;
                    match args.get(i) {
                        Some(src) => command = Some(src.clone()),
                        None => {
                            ctx.eprint("sh: -c: option requires an argument\n");
                            return 2;
                        }
                    }
                }
                's' => from_stdin = true,
                'i' => force_i = true,
                'l' => login = true,
                'e' => opts.errexit = on,
                'u' => opts.nounset = on,
                'x' => opts.xtrace = on,
                'f' => opts.noglob = on,
                'C' => opts.noclobber = on,
                _ => {
                    ctx.eprint(&alloc::format!("sh: -{c}: invalid option\nUsage: sh [-eux] [-c command [name [arg...]]] [file [arg...]]\n"));
                    return 2;
                }
            }
        }
        i += 1;
    }
    ctx.flush();
    let rest: Vec<String> = args[i.min(args.len())..].to_vec();
    let proc = crate::proc::current();
    let user = crate::users::by_uid(proc.cred().euid);
    if let Some(src) = command {
        let mut sh = Shell::new(proc, false);
        sh.opts = opts;
        sh.arg0 = rest.first().cloned().unwrap_or_else(|| String::from("sh"));
        sh.args = rest.get(1..).map(|v| v.to_vec()).unwrap_or_default();
        let st = sh.run_source(&src);
        return sh.finish(st);
    }
    if !from_stdin {
        if let Some(file) = rest.first() {
            let fs = crate::fs::ops::Ctx::of(&proc);
            let data = match crate::fs::ops::read_file(&fs, file) {
                Ok(d) => d,
                Err(e) => {
                    ctx.eprint(&alloc::format!("sh: {file}: {e}\n"));
                    return if e == crate::errno::Errno::ENOENT { 127 } else { 126 };
                }
            };
            let mut sh = Shell::new(proc, false);
            sh.opts = opts;
            sh.arg0 = file.clone();
            sh.args = rest[1..].to_vec();
            let st = sh.run_source(&String::from_utf8_lossy(&data));
            return sh.finish(st);
        }
    }
    let tty = ctx.stdin_tty().is_some();
    if (tty && !from_stdin) || force_i {
        let Some(u) = user else { return 1 };
        return user_shell(&u, login, None);
    }
    let data = match ctx.read_input("-") {
        Ok(d) => d,
        Err(e) => {
            ctx.eprint(&alloc::format!("sh: stdin: {e}\n"));
            return 2;
        }
    };
    let mut sh = Shell::new(proc, false);
    sh.opts = opts;
    sh.arg0 = String::from("sh");
    sh.args = rest;
    let st = sh.run_source(&String::from_utf8_lossy(&data));
    sh.finish(st)
}

/// Run one command string (SSH `exec`, `sh -c`).
pub fn command_main(src: String, user: crate::users::User) -> i32 {
    let proc = crate::proc::current();
    let mut sh = Shell::new(proc, false);
    let _ = sh.set_var("HOME", &user.home, true);
    let _ = sh.set_var("USER", &user.name, true);
    let _ = sh.set_var("LOGNAME", &user.name, true);
    if crate::fs::ops::chdir(&sh.proc, &user.home).is_err() {
        let _ = crate::fs::ops::chdir(&sh.proc, "/");
    }
    let pwd = sh.proc.fs.lock().cwd.path();
    let _ = sh.set_var("PWD", &pwd, true);
    sh.sync_env();
    sh.source_if_exists("/etc/profile");
    let code = sh.run_source(&src);
    sh.finish(code)
}

impl Shell {
    pub(crate) fn interactive_loop(&mut self) -> i32 {
        let mut editor = readline::Editor::new();
        loop {
            self.report_jobs();
            let ps1 = self.var("PS1").unwrap_or_else(|| String::from("\\u@\\h:\\w\\$ "));
            let prompt = self.prompt(&ps1);
            let Some(mut line) = editor.read_line(self, &prompt) else {
                // ^D on an empty line.
                self.out("logout\n");
                break;
            };
            // Multi-line constructs: keep reading with PS2 while incomplete.
            loop {
                match fastros_sh::parse(&line) {
                    Err(e) if e.incomplete => {
                        let ps2 = self.var("PS2").unwrap_or_else(|| String::from("> "));
                        match editor.read_line(self, &ps2) {
                            Some(more) => {
                                line.push('\n');
                                line.push_str(&more);
                            }
                            None => {
                                self.error(&e.msg);
                                line.clear();
                                break;
                            }
                        }
                    }
                    _ => break,
                }
            }
            if line.trim().is_empty() {
                continue;
            }
            let expanded = match self.history.expand_bang(&line) {
                Ok(Some(l)) => {
                    self.out(&alloc::format!("{l}\n"));
                    l
                }
                Ok(None) => line.clone(),
                Err(msg) => {
                    self.error(&msg);
                    continue;
                }
            };
            self.history.push(&expanded);
            let _ = self.history.save(&self.proc);
            if !crate::proc::absorb_signals() {
                break;
            }
            self.run_source(&expanded);
            if self.flow == Flow::Exit {
                break;
            }
            // Break/Continue outside loops, Interrupt: back to the prompt.
            self.flow = Flow::Normal;
        }
        self.run_exit_trap();
        let _ = self.history.save(&self.proc);
        self.exit_code
    }

    pub fn run_exit_trap(&mut self) {
        if let Some(cmd) = self.traps.remove("EXIT") {
            let saved = self.flow;
            self.flow = Flow::Normal;
            self.run_source(&cmd);
            self.flow = saved;
        }
    }

    /// Print finished background jobs (before each prompt, like bash).
    pub fn report_jobs(&mut self) {
        let mut finished = Vec::new();
        for job in self.jobs.iter_mut() {
            if job.done.is_some() {
                continue;
            }
            let mut all_done = true;
            let mut last = 0;
            for &pid in &job.pids {
                match crate::proc::wait(&self.proc, crate::proc::WaitFor::Pid(pid), true) {
                    Ok(Some((_, st))) => last = st.shell_code(),
                    Ok(None) => all_done = false,
                    Err(_) => {}
                }
            }
            if all_done {
                job.done = Some(last);
                finished.push((job.id, last, job.cmd.clone()));
            }
        }
        for (id, code, cmd) in finished {
            let state = if code == 0 { String::from("Done") } else { alloc::format!("Exit {code}") };
            self.out(&alloc::format!("[{id}]+  {state:<24}{cmd}\n"));
        }
        self.jobs.retain(|j| j.done.is_none());
    }
}
