//! Executing the shell AST.

use super::{builtins, cmds, Flow, Job, Shell};
use crate::errno::Errno;
use crate::fs::file::{flags, File, Poll, Whence};
use crate::fs::pipe;
use crate::fs::{FileType, Metadata, Timespec};
use crate::proc::fdtable::FdTable;
use crate::proc::{self, ExitStatus, Pid, Process, Spawn, WaitFor};
use crate::sync::SpinLock;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU32, Ordering};
use fastros_sh::ast::{self, Command, Connector, RedirOp, Word};
use fastros_sh::expand::{self, Env, ExpandError};

/// What a simple command's name resolved to.
pub enum Target {
    Function(Arc<Command>),
    Builtin(builtins::Builtin),
    Native(&'static super::ctx::CommandDef),
    Script(String),
    NotFound,
    NotExecutable(String, Errno),
}

/// Adapter giving the expander access to the shell.
struct ExpEnv<'a> {
    sh: &'a mut Shell,
}

impl Env for ExpEnv<'_> {
    fn var(&self, name: &str) -> Option<String> {
        self.sh.var(name)
    }
    fn set_var(&mut self, name: &str, value: &str) -> Result<(), String> {
        self.sh.set_var(name, value, false)
    }
    fn special(&self, name: &str) -> Option<String> {
        Some(match name {
            "?" => self.sh.status.to_string(),
            "$" => self.sh.proc.pid.to_string(),
            "!" => return self.sh.last_bg.map(|p| p.to_string()),
            "#" => self.sh.args.len().to_string(),
            "0" => self.sh.arg0.clone(),
            "-" => {
                let mut s = String::new();
                if self.sh.opts.errexit {
                    s.push('e');
                }
                if self.sh.opts.nounset {
                    s.push('u');
                }
                if self.sh.opts.xtrace {
                    s.push('x');
                }
                if self.sh.interactive {
                    s.push('i');
                }
                s
            }
            _ => return None,
        })
    }
    fn positional(&self) -> Vec<String> {
        self.sh.args.clone()
    }
    fn command_output(&mut self, src: &str) -> Result<String, String> {
        self.sh.capture(src)
    }
    fn home(&self, user: &str) -> Option<String> {
        crate::users::by_name(user).map(|u| u.home)
    }
    fn list_dir(&mut self, dir: &str) -> Option<Vec<String>> {
        let ctx = crate::fs::ops::Ctx::of(&self.sh.proc);
        crate::fs::ops::list_dir(&ctx, dir).ok().map(|v| v.into_iter().map(|e| e.name).collect())
    }
    fn nounset(&self) -> bool {
        self.sh.opts.nounset
    }
}

/// Here-documents and here-strings: an in-memory readable file.
struct MemFile {
    data: Vec<u8>,
    off: SpinLock<usize>,
    flags: AtomicU32,
}

impl File for MemFile {
    fn read(&self, buf: &mut [u8]) -> crate::errno::KResult<usize> {
        let mut off = self.off.lock();
        let n = buf.len().min(self.data.len() - *off);
        buf[..n].copy_from_slice(&self.data[*off..*off + n]);
        *off += n;
        Ok(n)
    }
    fn seek(&self, w: Whence) -> crate::errno::KResult<u64> {
        let mut off = self.off.lock();
        let new = match w {
            Whence::Set(p) => p,
            Whence::Cur(d) => *off as i64 + d,
            Whence::End(d) => self.data.len() as i64 + d,
        };
        if new < 0 || new as usize > self.data.len() {
            return Err(Errno::EINVAL);
        }
        *off = new as usize;
        Ok(new as u64)
    }
    fn stat(&self) -> crate::errno::KResult<Metadata> {
        let now = Timespec::now();
        Ok(Metadata {
            dev: 0,
            ino: 0,
            kind: FileType::Fifo,
            perm: 0o600,
            nlink: 1,
            uid: 0,
            gid: 0,
            size: self.data.len() as u64,
            blocks: 0,
            blksize: 4096,
            rdev: 0,
            atime: now,
            mtime: now,
            ctime: now,
        })
    }
    fn poll(&self) -> Poll {
        Poll::IN
    }
    fn flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn mem_file(data: Vec<u8>) -> Arc<dyn File> {
    Arc::new(MemFile { data, off: SpinLock::new(0), flags: AtomicU32::new(flags::O_RDONLY) })
}

impl Shell {
    // ── expansion helpers ───────────────────────────────────────────────

    pub fn expand_words(&mut self, words: &[Word]) -> Result<Vec<String>, ExpandError> {
        if self.opts.noglob {
            let mut out = Vec::new();
            for w in words {
                out.push(expand::expand_string(w, &mut ExpEnv { sh: self })?);
            }
            return Ok(out);
        }
        expand::expand_fields(words, &mut ExpEnv { sh: self })
    }

    pub fn expand_one(&mut self, w: &Word) -> Result<String, ExpandError> {
        expand::expand_string(w, &mut ExpEnv { sh: self })
    }

    fn expand_pattern(&mut self, w: &Word) -> Result<String, ExpandError> {
        expand::expand_pattern(w, &mut ExpEnv { sh: self })
    }

    fn expand_error(&mut self, e: ExpandError) -> i32 {
        self.error(&e.message());
        // An expansion error aborts a non-interactive shell (POSIX).
        if matches!(e, ExpandError::Unset(..)) && !self.interactive {
            self.flow = Flow::Exit;
            self.exit_code = 1;
        }
        1
    }

    /// `$(...)`: run `src` in a subshell and return its output.
    pub fn capture(&mut self, src: &str) -> Result<String, String> {
        let list = fastros_sh::parse(src).map_err(|e| e.msg)?;
        let (r, w) = pipe::pipe();
        let mut fds = self.proc.fds.lock().clone();
        fds.set(1, w, false);
        let child = self.spawn_subshell(Command::Group { body: alloc::boxed::Box::new(list), redirs: Vec::new() }, fds, Some(self.pgid()), "fsh")
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        let mut buf = alloc::vec![0u8; 4096];
        loop {
            match r.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(Errno::EINTR) => {
                    let _ = proc::kill(&self.proc, child.pid as i64, proc::signal::SIGTERM);
                    break;
                }
                Err(_) => break,
            }
        }
        drop(r);
        if let Ok(Some((_, st))) = proc::wait(&self.proc, WaitFor::Pid(child.pid), false) {
            self.status = st.shell_code();
        }
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    // ── lists ───────────────────────────────────────────────────────────

    pub fn run_list(&mut self, list: &ast::List) -> i32 {
        for item in &list.0 {
            if self.flow != Flow::Normal {
                break;
            }
            if item.background {
                self.run_background(&item.and_or);
            } else {
                self.run_and_or(&item.and_or);
                if self.opts.errexit && self.status != 0 && self.flow == Flow::Normal {
                    self.flow = Flow::Exit;
                    self.exit_code = self.status;
                }
            }
        }
        self.status
    }

    fn run_and_or(&mut self, ao: &ast::AndOr) -> i32 {
        let mut st = self.run_pipeline(&ao.first);
        for (conn, p) in &ao.rest {
            if self.flow != Flow::Normal {
                break;
            }
            let run = match conn {
                Connector::And => st == 0,
                Connector::Or => st != 0,
            };
            if run {
                st = self.run_pipeline(p);
            }
        }
        st
    }

    fn run_background(&mut self, ao: &ast::AndOr) {
        let text = describe_and_or(ao);
        let fds = self.proc.fds.lock().clone();
        let item = ast::Item { and_or: ao.clone(), background: false };
        let cmd = Command::Group { body: alloc::boxed::Box::new(ast::List(alloc::vec![item])), redirs: Vec::new() };
        match self.spawn_subshell(cmd, fds, None, "fsh") {
            Ok(child) => {
                let id = self.jobs.iter().map(|j| j.id).max().unwrap_or(0) + 1;
                if self.interactive {
                    self.out(&alloc::format!("[{id}] {}\n", child.pid));
                }
                self.last_bg = Some(child.pid);
                self.jobs.push(Job { id, pgid: child.pid, pids: alloc::vec![child.pid], cmd: text, done: None });
                self.status = 0;
            }
            Err(e) => {
                self.error(&alloc::format!("fork: {e}"));
                self.status = 1;
            }
        }
    }

    fn run_pipeline(&mut self, p: &ast::Pipeline) -> i32 {
        let st = if p.cmds.len() == 1 {
            self.run_command(&p.cmds[0])
        } else {
            self.run_multi(&p.cmds)
        };
        let st = if p.negate { (st == 0) as i32 } else { st };
        self.status = st;
        st
    }

    /// A pipeline of several commands: one process per stage, one process group.
    fn run_multi(&mut self, cmds: &[Command]) -> i32 {
        let mut children: Vec<Arc<Process>> = Vec::new();
        let mut prev: Option<Arc<dyn File>> = None;
        let mut pgid: Option<Pid> = None;
        let n = cmds.len();
        for (i, c) in cmds.iter().enumerate() {
            let mut fds = self.proc.fds.lock().clone();
            if let Some(r) = prev.take() {
                fds.set(0, r, false);
            }
            let mut next = None;
            if i + 1 < n {
                let (r, w) = pipe::pipe();
                fds.set(1, w, false);
                next = Some(r as Arc<dyn File>);
            }
            match self.spawn_stage(c, fds, pgid) {
                Ok(child) => {
                    pgid.get_or_insert(child.pid);
                    children.push(child);
                }
                Err(msg) => {
                    self.error(&msg);
                    self.status = 1;
                }
            }
            prev = next;
        }
        drop(prev);
        self.wait_foreground(&children, pgid)
    }

    /// Give the terminal to `pgid`, wait for every child, take it back.
    fn wait_foreground(&mut self, children: &[Arc<Process>], pgid: Option<Pid>) -> i32 {
        let tty = if self.interactive { self.tty() } else { None };
        if let (Some(t), Some(pg)) = (&tty, pgid) {
            t.set_fg_pgrp(pg);
        }
        let mut last = 0;
        for c in children {
            loop {
                match proc::wait(&self.proc, WaitFor::Pid(c.pid), false) {
                    Ok(Some((_, st))) => {
                        last = st.shell_code();
                        // bash's "cooperative exit": ^C that killed a
                        // foreground job abandons the whole command line.
                        if let ExitStatus::Signaled(proc::signal::SIGINT | proc::signal::SIGQUIT) = st {
                            if self.interactive && self.flow == Flow::Normal {
                                self.flow = Flow::Interrupt;
                            }
                        }
                        if let ExitStatus::Signaled(sig) = st {
                            if sig != proc::signal::SIGINT && sig != proc::signal::SIGPIPE && core::ptr::eq(c.as_ref(), children.last().map(|x| x.as_ref()).unwrap_or(c)) {
                                self.err(&alloc::format!("{}\n", proc::signal::describe(sig)));
                            }
                        }
                        break;
                    }
                    Ok(None) => continue,
                    // ^C reaches the whole foreground group: keep waiting for
                    // the child; a script acts on the signal afterwards.
                    Err(Errno::EINTR) => {
                        if !self.interactive && self.fatal_while_waiting() {
                            // Default disposition: the shell dies now; the
                            // child keeps running, as on Linux.
                            return self.exit_code;
                        }
                        if crate::proc::absorb_signals() {
                            continue;
                        }
                        break;
                    }
                    Err(_) => break,
                }
            }
        }
        if let Some(t) = &tty {
            t.set_fg_pgrp(self.pgid());
            if last == 130 {
                // Leave the cursor on a fresh line after ^C.
                let _ = t.write(b"\n");
            }
        }
        last
    }

    // ── single commands ─────────────────────────────────────────────────

    pub fn run_command(&mut self, c: &Command) -> i32 {
        if crate::proc::killed() {
            // SIGKILL: stop at the next command, whatever the script does.
            self.flow = Flow::Exit;
            self.exit_code = 128 + crate::proc::signal::SIGKILL as i32;
        }
        if self.flow == Flow::Normal {
            self.handle_signals();
        }
        if self.flow != Flow::Normal {
            return self.status;
        }
        let st = match c {
            Command::Simple { assigns, words, redirs } => self.run_simple(assigns, words, redirs),
            Command::Subshell { .. } => {
                let fds = self.proc.fds.lock().clone();
                match self.spawn_subshell(c.clone(), fds, None, "fsh") {
                    Ok(child) => {
                        let pg = child.pid;
                        self.wait_foreground(&[child], Some(pg))
                    }
                    Err(e) => {
                        self.error(&alloc::format!("fork: {e}"));
                        1
                    }
                }
            }
            Command::FuncDef { name, body } => {
                self.funcs.insert(name.clone(), Arc::new((**body).clone()));
                0
            }
            _ => self.with_redirs(redirs_of(c), |sh| sh.run_compound(c)),
        };
        self.status = st;
        st
    }

    fn run_compound(&mut self, c: &Command) -> i32 {
        match c {
            Command::Group { body, .. } => self.run_list(body),
            Command::If { branches, else_body, .. } => {
                for (cond, body) in branches {
                    let st = self.run_list_noerr(cond);
                    if self.flow != Flow::Normal {
                        return st;
                    }
                    if st == 0 {
                        return self.run_list(body);
                    }
                }
                match else_body {
                    Some(b) => self.run_list(b),
                    None => 0,
                }
            }
            Command::While { cond, body, until, .. } => {
                let mut st = 0;
                self.loop_depth += 1;
                loop {
                    let c = self.run_list_noerr(cond);
                    if self.flow != Flow::Normal || (c == 0) == *until {
                        break;
                    }
                    st = self.run_list(body);
                    if crate::proc::interrupted() {
                        break;
                    }
                    match self.flow {
                        Flow::Break(n) => {
                            self.flow = if n > 1 { Flow::Break(n - 1) } else { Flow::Normal };
                            break;
                        }
                        Flow::Continue(n) => {
                            self.flow = if n > 1 { Flow::Continue(n - 1) } else { Flow::Normal };
                            if n > 1 {
                                break;
                            }
                        }
                        Flow::Normal => {}
                        _ => break,
                    }
                }
                self.loop_depth -= 1;
                st
            }
            Command::For { var, items, body, .. } => {
                let values = match items {
                    Some(ws) => match self.expand_words(ws) {
                        Ok(v) => v,
                        Err(e) => return self.expand_error(e),
                    },
                    None => self.args.clone(),
                };
                let mut st = 0;
                self.loop_depth += 1;
                for v in values {
                    if let Err(m) = self.set_var(var, &v, false) {
                        self.error(&m);
                        st = 1;
                        break;
                    }
                    st = self.run_list(body);
                    if crate::proc::interrupted() {
                        break;
                    }
                    match self.flow {
                        Flow::Break(n) => {
                            self.flow = if n > 1 { Flow::Break(n - 1) } else { Flow::Normal };
                            break;
                        }
                        Flow::Continue(n) => {
                            self.flow = if n > 1 { Flow::Continue(n - 1) } else { Flow::Normal };
                            if n > 1 {
                                break;
                            }
                        }
                        Flow::Normal => {}
                        _ => break,
                    }
                }
                self.loop_depth -= 1;
                st
            }
            Command::Case { word, arms, .. } => {
                let subject = match self.expand_one(word) {
                    Ok(s) => s,
                    Err(e) => return self.expand_error(e),
                };
                for (pats, body) in arms {
                    for p in pats {
                        let pat = match self.expand_pattern(p) {
                            Ok(s) => s,
                            Err(e) => return self.expand_error(e),
                        };
                        if fastros_sh::pattern::matches(&pat, &subject) {
                            return self.run_list(body);
                        }
                    }
                }
                0
            }
            _ => self.run_command(c),
        }
    }

    /// Conditions of `if`/`while` do not trigger `set -e`.
    fn run_list_noerr(&mut self, l: &ast::List) -> i32 {
        let saved = self.opts.errexit;
        self.opts.errexit = false;
        let st = self.run_list(l);
        self.opts.errexit = saved;
        st
    }

    /// Resolve a command name the way the shell will run it.
    pub fn resolve(&self, name: &str) -> Target {
        if name.contains('/') {
            return self.resolve_path(name);
        }
        if let Some(f) = self.funcs.get(name) {
            return Target::Function(f.clone());
        }
        if let Some(b) = builtins::find(name) {
            return Target::Builtin(b);
        }
        let path = self.var("PATH").unwrap_or_default();
        for dir in path.split(':') {
            let dir = if dir.is_empty() { "." } else { dir };
            let cand = alloc::format!("{}/{}", dir.trim_end_matches('/'), name);
            match self.resolve_path(&cand) {
                Target::NotFound => continue,
                t => return t,
            }
        }
        Target::NotFound
    }

    fn resolve_path(&self, path: &str) -> Target {
        let ctx = crate::fs::ops::Ctx::of(&self.proc);
        let node = match ctx.resolve(path, true) {
            Ok(n) => n,
            Err(Errno::ENOENT) | Err(Errno::ENOTDIR) => return Target::NotFound,
            Err(e) => return Target::NotExecutable(path.to_string(), e),
        };
        if node.mount.fs.fs_type() == "binfs" {
            let base = path.rsplit('/').next().unwrap_or(path);
            if let Some(def) = cmds::find(base) {
                return Target::Native(def);
            }
        }
        let meta = match node.inode.metadata() {
            Ok(m) => m,
            Err(e) => return Target::NotExecutable(path.to_string(), e),
        };
        if meta.kind == FileType::Directory {
            return Target::NotExecutable(path.to_string(), Errno::EISDIR);
        }
        if let Err(e) = crate::fs::perm::check(&ctx.cred, &meta, crate::fs::perm::MAY_EXEC) {
            return Target::NotExecutable(path.to_string(), e);
        }
        if node.mount.flags.lock().noexec {
            return Target::NotExecutable(path.to_string(), Errno::EACCES);
        }
        Target::Script(node.path())
    }

    fn run_simple(&mut self, assigns: &[(String, Word)], words: &[Word], redirs: &[ast::Redir]) -> i32 {
        let argv = match self.expand_words(words) {
            Ok(v) => v,
            Err(e) => return self.expand_error(e),
        };
        let mut values = Vec::new();
        for (k, w) in assigns {
            match self.expand_one(w) {
                Ok(v) => values.push((k.clone(), v)),
                Err(e) => return self.expand_error(e),
            }
        }
        if self.opts.xtrace && !argv.is_empty() {
            let line: Vec<String> = argv.iter().map(|a| fastros_sh::quote(a)).collect();
            self.err(&alloc::format!("+ {}\n", line.join(" ")));
        }
        if argv.is_empty() {
            // Only assignments (and maybe redirections).
            for (k, v) in &values {
                if let Err(m) = self.set_var(k, v, false) {
                    self.error(&m);
                    return 1;
                }
            }
            if redirs.is_empty() {
                return self.status_after_assign();
            }
            return self.with_redirs(redirs, |_| 0);
        }
        // Aliases (interactive shells only), expanded once.
        if self.interactive && words.first().is_some_and(|w| w.as_plain().is_some()) {
            if let Some(alias) = self.aliases.get(&argv[0]).cloned() {
                let rest: Vec<String> = argv[1..].iter().map(|a| fastros_sh::quote(a)).collect();
                let src = alloc::format!("{} {}", alias, rest.join(" "));
                let saved = core::mem::take(&mut self.aliases);
                let st = self.with_redirs(redirs, |sh| sh.run_source(&src));
                self.aliases = saved;
                return st;
            }
        }
        match self.resolve(&argv[0]) {
            Target::Builtin(b) => {
                // Prefix assignments are temporary for regular builtins.
                let saved: Vec<(String, Option<super::Var>)> = values.iter().map(|(k, _)| (k.clone(), self.vars.get(k).cloned())).collect();
                for (k, v) in &values {
                    let _ = self.set_var(k, v, false);
                }
                let st = self.with_redirs(redirs, |sh| (b.run)(sh, &argv));
                if !b.special {
                    for (k, old) in saved {
                        match old {
                            Some(v) => {
                                self.vars.insert(k, v);
                            }
                            None => {
                                self.vars.remove(&k);
                            }
                        }
                    }
                    self.sync_env();
                }
                st
            }
            Target::Function(body) => self.with_redirs(redirs, |sh| sh.call_function(&body, &argv)),
            Target::Native(def) => {
                let mut fds = self.proc.fds.lock().clone();
                if let Err(m) = self.apply_redirs(redirs, &mut fds) {
                    self.error(&m);
                    return 1;
                }
                match self.spawn_native(def, argv, &values, fds, None) {
                    Ok(child) => {
                        let pg = child.pid;
                        self.wait_foreground(&[child], Some(pg))
                    }
                    Err(e) => {
                        self.error(&alloc::format!("{}: {e}", def.name));
                        126
                    }
                }
            }
            Target::Script(path) => {
                let mut fds = self.proc.fds.lock().clone();
                if let Err(m) = self.apply_redirs(redirs, &mut fds) {
                    self.error(&m);
                    return 1;
                }
                match self.spawn_script(&path, argv, &values, fds, None) {
                    Ok(child) => {
                        let pg = child.pid;
                        self.wait_foreground(&[child], Some(pg))
                    }
                    Err(m) => {
                        self.error(&m);
                        126
                    }
                }
            }
            Target::NotFound => {
                self.error(&alloc::format!("{}: command not found", argv[0]));
                127
            }
            Target::NotExecutable(p, e) => {
                self.error(&alloc::format!("{p}: {e}"));
                126
            }
        }
    }

    /// Start an already-expanded command line as a child of this shell's
    /// process without waiting: natives and scripts run directly, builtins
    /// and functions in a subshell. `Err((status, message))` when nothing
    /// could be started (127 not found, 126 not executable).
    pub fn spawn_argv(&mut self, argv: Vec<String>, fds: FdTable, pgid: Option<Pid>, cred: Option<crate::fs::perm::Cred>) -> Result<Arc<Process>, (i32, String)> {
        let Some(name) = argv.first().cloned() else { return Err((0, String::new())) };
        let with_cred = |mut s: Spawn| {
            if let Some(c) = &cred {
                s.cred = c.clone();
            }
            s
        };
        match self.resolve(&name) {
            Target::Native(def) => {
                let s = with_cred(self.spawn_opts(def.name, argv.clone(), &[], fds, pgid));
                proc::spawn(s, move || {
                    let mut ctx = super::ctx::Ctx::new(proc::current(), argv);
                    cmds::invoke(def, &mut ctx)
                })
                .map_err(|e| (126, alloc::format!("{name}: {e}")))
            }
            Target::Script(path) => {
                let saved = self.proc.cred();
                if let Some(c) = &cred {
                    // Scripts inherit the credentials through the spawn below.
                    *self.proc.cred.lock() = c.clone();
                }
                let r = self.spawn_script(&path, argv, &[], fds, pgid);
                *self.proc.cred.lock() = saved;
                r.map_err(|m| (126, m))
            }
            Target::Builtin(_) | Target::Function(_) => {
                let words = argv.iter().map(|a| fastros_sh::quote(a)).collect::<Vec<_>>().join(" ");
                let list = fastros_sh::parse(&words).map_err(|e| (2, e.msg))?;
                let saved = self.proc.cred();
                if let Some(c) = &cred {
                    *self.proc.cred.lock() = c.clone();
                }
                let r = self.spawn_subshell(Command::Group { body: alloc::boxed::Box::new(list), redirs: Vec::new() }, fds, pgid, &name);
                *self.proc.cred.lock() = saved;
                r.map_err(|e| (126, alloc::format!("fork: {e}")))
            }
            Target::NotFound => Err((127, alloc::format!("{name}: command not found"))),
            Target::NotExecutable(p, e) => Err((126, alloc::format!("{p}: {e}"))),
        }
    }

    /// Run an already-expanded command line as a foreground child of this
    /// shell's process, optionally with different credentials (`sudo`).
    pub fn run_argv_with(&mut self, argv: Vec<String>, cred: Option<crate::fs::perm::Cred>) -> i32 {
        let Some(name) = argv.first().cloned() else { return 0 };
        if cred.is_none() {
            match self.resolve(&name) {
                Target::Builtin(b) => return (b.run)(self, &argv),
                Target::Function(f) => return self.call_function(&f, &argv),
                _ => {}
            }
        }
        let fds = self.proc.fds.lock().clone();
        // Only an interactive shell puts children in their own job group;
        // commands run by `find -exec`, `xargs`, `env` stay in the caller's
        // group so terminal ^C reaches them too.
        let pgid = if self.interactive { None } else { Some(self.pgid()) };
        match self.spawn_argv(argv, fds, pgid, cred) {
            Ok(child) => {
                let pg = child.pgid.load(core::sync::atomic::Ordering::Relaxed);
                self.wait_foreground(&[child], Some(pg))
            }
            Err((st, m)) => {
                self.err(&alloc::format!("{m}\n"));
                st
            }
        }
    }

    fn status_after_assign(&self) -> i32 {
        // `x=$(false)` reports the substitution's status.
        self.status
    }

    pub fn call_function(&mut self, body: &Command, argv: &[String]) -> i32 {
        if self.func_depth >= 256 {
            self.error(&alloc::format!("{}: maximum function nesting level exceeded", argv[0]));
            return 1;
        }
        let saved_args = core::mem::replace(&mut self.args, argv[1..].to_vec());
        self.func_depth += 1;
        self.locals.push(Vec::new());
        let st = self.run_command(body);
        let st = if self.flow == Flow::Return {
            self.flow = Flow::Normal;
            self.status
        } else {
            st
        };
        if let Some(scope) = self.locals.pop() {
            for (k, old) in scope.into_iter().rev() {
                match old {
                    Some(v) => {
                        self.vars.insert(k, v);
                    }
                    None => {
                        self.vars.remove(&k);
                    }
                }
            }
            self.sync_env();
        }
        self.func_depth -= 1;
        self.args = saved_args;
        st
    }

    // ── redirections ────────────────────────────────────────────────────

    /// Apply redirections to a descriptor table.
    pub fn apply_redirs(&mut self, redirs: &[ast::Redir], fds: &mut FdTable) -> Result<(), String> {
        for r in redirs {
            let fd = r.fd() as usize;
            let target = match r.op {
                RedirOp::HereDoc => None,
                _ => {
                    let v = self.expand_words(core::slice::from_ref(&r.target)).map_err(|e| e.message())?;
                    if v.len() != 1 {
                        return Err(alloc::format!("{}: ambiguous redirect", v.join(" ")));
                    }
                    Some(v.into_iter().next().expect("len checked"))
                }
            };
            let ctx = crate::fs::ops::Ctx::of(&self.proc);
            let open = |path: &str, fl: u32| -> Result<Arc<dyn File>, String> {
                crate::fs::ops::open(&ctx, path, fl, 0o666).map_err(|e| alloc::format!("{path}: {e}"))
            };
            match r.op {
                RedirOp::In => fds.set(fd, open(target.as_deref().unwrap_or(""), flags::O_RDONLY)?, false),
                RedirOp::Out | RedirOp::Clobber => {
                    let t = target.unwrap_or_default();
                    if r.op == RedirOp::Out && self.opts.noclobber && crate::fs::ops::stat(&ctx, &t, true).is_ok_and(|m| m.kind == FileType::Regular) {
                        return Err(alloc::format!("{t}: cannot overwrite existing file"));
                    }
                    fds.set(fd, open(&t, flags::O_WRONLY | flags::O_CREAT | flags::O_TRUNC)?, false);
                }
                RedirOp::Append => fds.set(fd, open(target.as_deref().unwrap_or(""), flags::O_WRONLY | flags::O_CREAT | flags::O_APPEND)?, false),
                RedirOp::ReadWrite => fds.set(fd, open(target.as_deref().unwrap_or(""), flags::O_RDWR | flags::O_CREAT)?, false),
                RedirOp::OutErr | RedirOp::AppendErr => {
                    let fl = if r.op == RedirOp::OutErr { flags::O_TRUNC } else { flags::O_APPEND };
                    let f = open(target.as_deref().unwrap_or(""), flags::O_WRONLY | flags::O_CREAT | fl)?;
                    fds.set(1, f.clone(), false);
                    fds.set(2, f, false);
                }
                RedirOp::DupIn | RedirOp::DupOut => {
                    let t = target.unwrap_or_default();
                    if t == "-" {
                        let _ = fds.close(fd as i32);
                    } else {
                        let src: i32 = t.parse().map_err(|_| alloc::format!("{t}: ambiguous redirect"))?;
                        let f = fds.get(src).map_err(|_| alloc::format!("{src}: Bad file descriptor"))?;
                        fds.set(fd, f, false);
                    }
                }
                RedirOp::HereDoc => {
                    let (body, expand_it) = r.heredoc.clone().unwrap_or_default();
                    let text = if expand_it {
                        let w = fastros_sh::parser::parse_heredoc(&body);
                        self.expand_one(&w).map_err(|e| e.message())?
                    } else {
                        body
                    };
                    fds.set(fd, mem_file(text.into_bytes()), false);
                }
                RedirOp::HereString => {
                    let mut t = target.unwrap_or_default();
                    t.push('\n');
                    fds.set(fd, mem_file(t.into_bytes()), false);
                }
            }
        }
        Ok(())
    }

    /// Run `f` with `redirs` applied to the shell's own descriptors.
    pub fn with_redirs(&mut self, redirs: &[ast::Redir], f: impl FnOnce(&mut Shell) -> i32) -> i32 {
        if redirs.is_empty() {
            return f(self);
        }
        let saved = self.proc.fds.lock().clone();
        let mut fds = saved.clone();
        if let Err(m) = self.apply_redirs(redirs, &mut fds) {
            self.error(&m);
            return 1;
        }
        *self.proc.fds.lock() = fds;
        let st = f(self);
        // `exec >file` makes redirections permanent.
        if !self.keep_redirs {
            *self.proc.fds.lock() = saved;
        }
        self.keep_redirs = false;
        st
    }

    // ── processes ───────────────────────────────────────────────────────

    fn spawn_opts(&self, name: &str, argv: Vec<String>, assigns: &[(String, String)], fds: FdTable, pgid: Option<Pid>) -> Spawn {
        let mut s = Spawn::from_parent(&self.proc, name, argv);
        let mut env = self.environ();
        for (k, v) in assigns {
            env.retain(|(ek, _)| ek != k);
            env.push((k.clone(), v.clone()));
        }
        s.env = env;
        s.fds = fds;
        s.pgid = pgid;
        s
    }

    pub fn spawn_native(
        &self,
        def: &'static super::ctx::CommandDef,
        argv: Vec<String>,
        assigns: &[(String, String)],
        fds: FdTable,
        pgid: Option<Pid>,
    ) -> Result<Arc<Process>, Errno> {
        let s = self.spawn_opts(def.name, argv.clone(), assigns, fds, pgid);
        proc::spawn(s, move || {
            let mut ctx = super::ctx::Ctx::new(proc::current(), argv);
            cmds::invoke(def, &mut ctx)
        })
    }

    fn spawn_script(&self, path: &str, argv: Vec<String>, assigns: &[(String, String)], fds: FdTable, pgid: Option<Pid>) -> Result<Arc<Process>, String> {
        let ctx = crate::fs::ops::Ctx::of(&self.proc);
        let data = crate::fs::ops::read_file(&ctx, path).map_err(|e| alloc::format!("{path}: {e}"))?;
        if data.len() >= 4 && &data[..4] == b"\x7fELF" {
            return Err(alloc::format!("{path}: cannot execute binary file: Linux programs run in containers (fastman run)"));
        }
        let text = String::from_utf8_lossy(&data).into_owned();
        if let Some(first) = text.lines().next().filter(|l| l.starts_with("#!")) {
            let interp = first[2..].trim().split_whitespace().next().unwrap_or("");
            let base = interp.rsplit('/').next().unwrap_or("");
            if !matches!(base, "sh" | "fsh" | "bash" | "ash" | "dash") && !(base == "env" && first.contains(" sh")) {
                return Err(alloc::format!("{path}: {interp}: bad interpreter: No such file or directory"));
            }
        }
        let name = path.rsplit('/').next().unwrap_or("sh").to_string();
        let s = self.spawn_opts(&name, argv.clone(), assigns, fds, pgid);
        let mut sub = self.subshell_state();
        let script_path = path.to_string();
        proc::spawn(s, move || {
            sub.proc = proc::current();
            sub.interactive = false;
            sub.arg0 = script_path;
            sub.args = argv[1..].to_vec();
            sub.funcs.clear();
            sub.aliases.clear();
            let st = sub.run_source(&text);
            sub.finish(st)
        })
        .map_err(|e| alloc::format!("fork: {e}"))
    }

    /// A copy of the shell for a subshell/child process.
    fn subshell_state(&self) -> Shell {
        let mut s = self.clone();
        s.jobs.clear();
        s.flow = Flow::Normal;
        s.history = super::history::History::new();
        s.traps.clear();
        s.deferred_signals = 0;
        s
    }

    pub fn spawn_subshell(&self, cmd: Command, fds: FdTable, pgid: Option<Pid>, name: &str) -> Result<Arc<Process>, Errno> {
        let s = self.spawn_opts(name, alloc::vec![String::from(name)], &[], fds, pgid);
        let mut sub = self.subshell_state();
        proc::spawn(s, move || {
            sub.proc = proc::current();
            sub.interactive = false;
            let st = match &cmd {
                Command::Subshell { body, redirs } => sub.with_redirs(redirs, |sh| sh.run_list(body)),
                other => sub.run_command(other),
            };
            sub.finish(st)
        })
    }

    /// One pipeline stage as its own process.
    fn spawn_stage(&mut self, c: &Command, mut fds: FdTable, pgid: Option<Pid>) -> Result<Arc<Process>, String> {
        if let Command::Simple { assigns, words, redirs } = c {
            let argv = self.expand_words(words).map_err(|e| e.message())?;
            let mut values = Vec::new();
            for (k, w) in assigns {
                values.push((k.clone(), self.expand_one(w).map_err(|e| e.message())?));
            }
            if let Some(name) = argv.first() {
                match self.resolve(name) {
                    Target::Native(def) => {
                        self.apply_redirs(redirs, &mut fds)?;
                        return self.spawn_native(def, argv, &values, fds, pgid).map_err(|e| alloc::format!("fork: {e}"));
                    }
                    Target::Script(path) => {
                        self.apply_redirs(redirs, &mut fds)?;
                        return self.spawn_script(&path, argv, &values, fds, pgid);
                    }
                    Target::NotFound => {
                        // Report from the stage itself so the pipeline keeps its shape.
                        let msg = alloc::format!("fsh: {name}: command not found\n");
                        let err = fds.get(2).ok();
                        let s = self.spawn_opts("fsh", alloc::vec![name.clone()], &[], fds, pgid);
                        return proc::spawn(s, move || {
                            if let Some(e) = err {
                                let _ = e.write_all(msg.as_bytes());
                            }
                            127
                        })
                        .map_err(|e| alloc::format!("fork: {e}"));
                    }
                    _ => {}
                }
            }
        }
        self.spawn_subshell(c.clone(), fds, pgid, "fsh").map_err(|e| alloc::format!("fork: {e}"))
    }
}

fn redirs_of(c: &Command) -> &[ast::Redir] {
    match c {
        Command::Simple { redirs, .. }
        | Command::Subshell { redirs, .. }
        | Command::Group { redirs, .. }
        | Command::If { redirs, .. }
        | Command::While { redirs, .. }
        | Command::For { redirs, .. }
        | Command::Case { redirs, .. } => redirs,
        Command::FuncDef { .. } => &[],
    }
}

/// Short text of a command for `jobs` / job notifications.
fn describe_and_or(ao: &ast::AndOr) -> String {
    fn word(w: &Word) -> String {
        let mut s = String::new();
        for p in &w.0 {
            match p {
                ast::WordPart::Lit(t) | ast::WordPart::Quoted(t) => s.push_str(t),
                ast::WordPart::Param(pp) => {
                    s.push('$');
                    s.push_str(&pp.name);
                }
                _ => s.push('…'),
            }
        }
        s
    }
    fn cmd(c: &Command) -> String {
        match c {
            Command::Simple { words, .. } => words.iter().map(word).collect::<Vec<_>>().join(" "),
            Command::Subshell { .. } => String::from("( ... )"),
            _ => String::from("{ ... }"),
        }
    }
    let mut s = ao.first.cmds.iter().map(cmd).collect::<Vec<_>>().join(" | ");
    for (c, p) in &ao.rest {
        s.push_str(if *c == Connector::And { " && " } else { " || " });
        s.push_str(&p.cmds.iter().map(cmd).collect::<Vec<_>>().join(" | "));
    }
    s
}
