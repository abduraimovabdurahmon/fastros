//! Processes.
//!
//! A process owns credentials, a filesystem context (namespace, root, cwd,
//! umask), a descriptor table, an environment, a controlling terminal and one
//! or more tasks. PIDs share the task-id space (pid = tid of the first task),
//! as on Linux, so `ps`, `kill` and `/proc` agree on numbers.
//!
//! Kernel threads have no process of their own; they run in the context of
//! the kernel pseudo-process (pid 0) and are listed as `[name]` by `ps`.

pub mod elf;
pub mod fdtable;
pub mod signal;

use crate::errno::{Errno, KResult};
use crate::fs::mount::MountNamespace;
use crate::fs::path::{PathRef, Resolver};
use crate::fs::perm::Cred;
use crate::sched::{self, Task, Tid};
use crate::sync::{Once, SpinLock, WaitQueue};
use crate::tty::Tty;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use crate::arch::x86_64::syscall::{enter_user, UserFrame};
use crate::mm::aspace::AddressSpace;
use fdtable::FdTable;

pub type Pid = u32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitStatus {
    Exited(i32),
    Signaled(u32),
}

impl ExitStatus {
    /// Encoding of `wait(2)` status.
    pub fn wait_status(self) -> i32 {
        match self {
            ExitStatus::Exited(c) => (c & 0xFF) << 8,
            ExitStatus::Signaled(s) => s as i32 & 0x7F,
        }
    }
    /// Shell `$?` value.
    pub fn shell_code(self) -> i32 {
        match self {
            ExitStatus::Exited(c) => c & 0xFF,
            ExitStatus::Signaled(s) => 128 + s as i32,
        }
    }
}

pub struct FsContext {
    pub ns: Arc<MountNamespace>,
    pub root: PathRef,
    pub cwd: PathRef,
    pub umask: u16,
}

impl Clone for FsContext {
    fn clone(&self) -> Self {
        FsContext { ns: self.ns.clone(), root: self.root.clone(), cwd: self.cwd.clone(), umask: self.umask }
    }
}

/// UTS namespace: host and domain name.
pub struct Uts {
    pub hostname: SpinLock<String>,
    pub domainname: SpinLock<String>,
}

pub struct Process {
    pub pid: Pid,
    pub ppid: AtomicU32,
    pub pgid: AtomicU32,
    pub sid: AtomicU32,
    comm: SpinLock<String>,
    cmdline: SpinLock<Vec<String>>,
    pub cred: SpinLock<Cred>,
    pub fs: SpinLock<FsContext>,
    pub fds: SpinLock<FdTable>,
    pub env: SpinLock<Vec<(String, String)>>,
    pub uts: Arc<Uts>,
    tasks: SpinLock<Vec<Arc<Task>>>,
    children: SpinLock<Vec<Arc<Process>>>,
    exit: SpinLock<Option<ExitStatus>>,
    /// Woken when a child of this process changes state.
    pub child_wq: WaitQueue,
    pub ctty: SpinLock<Option<Arc<Tty>>>,
    pub start_ns: u64,
    /// Container this process belongs to (None = host).
    pub container: SpinLock<Option<String>>,
    /// User address space (None for kernel/native processes).
    pub aspace: SpinLock<Option<Arc<AddressSpace>>>,
    /// Signals set to SIG_IGN (bit n-1 for signal n); inherited by children,
    /// as ignored dispositions survive fork and exec on Linux.
    pub ignored: AtomicU64,
    /// CPU time of the process when it exited.
    pub cpu_at_exit: AtomicU64,
    /// CPU time of reaped children and their descendants (cutime).
    pub children_cpu: AtomicU64,
    /// A `vfork`/`posix_spawn` parent blocks on this until the child execs or
    /// exits; the child then releases it. Set at birth for a vfork child.
    pub vfork_wq: WaitQueue,
    pub vfork_pending: AtomicBool,
}

static PROCS: SpinLock<BTreeMap<Pid, Arc<Process>>> = SpinLock::new(BTreeMap::new());
static KERNEL: Once<Arc<Process>> = Once::new();
static HOST_UTS: Once<Arc<Uts>> = Once::new();

impl Process {
    pub fn comm(&self) -> String {
        self.comm.lock().clone()
    }
    pub fn set_comm(&self, name: &str) {
        let mut c = self.comm.lock();
        c.clear();
        c.push_str(&name[..name.len().min(15)]);
    }
    pub fn cmdline(&self) -> Vec<String> {
        self.cmdline.lock().clone()
    }
    /// Release a `vfork`/`posix_spawn` parent blocked on this child (called when
    /// the child execs — its address space has diverged — or exits).
    pub fn vfork_release(&self) {
        if self.vfork_pending.swap(false, Ordering::AcqRel) {
            self.vfork_wq.wake_all();
        }
    }
    pub fn set_cmdline(&self, args: Vec<String>) {
        *self.cmdline.lock() = args;
    }
    pub fn cred(&self) -> Cred {
        self.cred.lock().clone()
    }
    pub fn exit_status(&self) -> Option<ExitStatus> {
        *self.exit.lock()
    }
    pub fn is_zombie(&self) -> bool {
        self.exit.lock().is_some()
    }
    pub fn tasks(&self) -> Vec<Arc<Task>> {
        self.tasks.lock().clone()
    }
    pub fn children(&self) -> Vec<Arc<Process>> {
        self.children.lock().clone()
    }
    pub fn cpu_ns(&self) -> u64 {
        self.tasks.lock().iter().map(|t| t.cpu_ns()).sum()
    }
    pub fn env_var(&self, key: &str) -> Option<String> {
        self.env.lock().iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
    }

    /// Resolve a path in this process's filesystem context.
    pub fn with_resolver<R>(&self, f: impl FnOnce(&Resolver) -> R) -> R {
        let fs = self.fs.lock().clone();
        let cred = self.cred();
        let r = Resolver { ns: &fs.ns, root: &fs.root, cwd: &fs.cwd, cred: &cred };
        f(&r)
    }

    /// Send a signal to every task of the process.
    pub fn signal(&self, sig: u32) {
        if signal::ignored_by_default(sig) {
            return;
        }
        if sig != signal::SIGKILL && sig != signal::SIGSTOP && (1..=64).contains(&sig) && self.ignored.load(Ordering::Relaxed) & (1 << (sig - 1)) != 0 {
            return;
        }
        for t in self.tasks.lock().iter() {
            t.send_signal(sig);
        }
    }
}

/// The kernel pseudo-process (pid 0): context of kernel threads.
pub fn kernel() -> Arc<Process> {
    KERNEL.expect_init().clone()
}

pub fn host_uts() -> Arc<Uts> {
    HOST_UTS.expect_init().clone()
}

/// Create the kernel pseudo-process once the root filesystem is mounted.
pub fn init(ns: Arc<MountNamespace>) {
    let root = ns.root();
    let uts = HOST_UTS.call_once(|| {
        Arc::new(Uts { hostname: SpinLock::new(String::from("fastros")), domainname: SpinLock::new(String::from("(none)")) })
    });
    KERNEL.call_once(|| {
        Arc::new(Process {
            pid: 0,
            ppid: AtomicU32::new(0),
            pgid: AtomicU32::new(0),
            sid: AtomicU32::new(0),
            comm: SpinLock::new(String::from("kernel")),
            cmdline: SpinLock::new(Vec::new()),
            cred: SpinLock::new(Cred::root()),
            fs: SpinLock::new(FsContext { ns, root: root.clone(), cwd: root, umask: 0o022 }),
            fds: SpinLock::new(FdTable::new()),
            env: SpinLock::new(Vec::new()),
            uts: uts.clone(),
            tasks: SpinLock::new(Vec::new()),
            children: SpinLock::new(Vec::new()),
            exit: SpinLock::new(None),
            child_wq: WaitQueue::new(),
            ctty: SpinLock::new(None),
            start_ns: 0,
            container: SpinLock::new(None),
            aspace: SpinLock::new(None),
            ignored: AtomicU64::new(0),
            cpu_at_exit: AtomicU64::new(0),
            children_cpu: AtomicU64::new(0),
            vfork_wq: WaitQueue::new(),
            vfork_pending: AtomicBool::new(false),
        })
    });
}

/// Set the current task's user thread pointer (FS base).
pub fn set_current_fs_base(v: u64) {
    sched::with_current(|t| t.fs_base.store(v, core::sync::atomic::Ordering::Relaxed));
}

/// Set the CR3 the current task runs under (execve into a new address space).
pub fn set_current_cr3(cr3: u64) {
    sched::with_current(|t| t.cr3.store(cr3, core::sync::atomic::Ordering::Release));
}

/// The address space of the current process, if it is a user process.
pub fn current_aspace() -> Option<Arc<AddressSpace>> {
    let pid = sched::with_current(|t| t.owner.load(Ordering::Acquire));
    if pid == 0 {
        return None;
    }
    PROCS.lock().get(&pid).and_then(|p| p.aspace.lock().clone())
}

/// The process the current task belongs to (the kernel for kernel threads).
pub fn current() -> Arc<Process> {
    let pid = sched::with_current(|t| t.owner.load(Ordering::Acquire));
    if pid == 0 {
        return kernel();
    }
    PROCS.lock().get(&pid).cloned().unwrap_or_else(kernel)
}

pub fn find(pid: Pid) -> Option<Arc<Process>> {
    if pid == 0 {
        return KERNEL.get().cloned();
    }
    PROCS.lock().get(&pid).cloned()
}

pub fn all() -> Vec<Arc<Process>> {
    PROCS.lock().values().cloned().collect()
}

/// Everything a new process inherits or is given.
pub struct Spawn {
    pub name: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cred: Cred,
    pub fs: FsContext,
    pub fds: FdTable,
    pub parent: Arc<Process>,
    /// Process group to join (None = start a new group led by the child).
    pub pgid: Option<Pid>,
    /// Start a new session (login shells, daemons).
    pub new_session: bool,
    pub ctty: Option<Arc<Tty>>,
    pub uts: Arc<Uts>,
    pub container: Option<String>,
    /// User address space for the child (None = a kernel/native process).
    pub aspace: Option<Arc<AddressSpace>>,
    /// Ignored signals (SIG_IGN), normally the parent's.
    pub ignored: u64,
    /// This child is a `vfork`/`posix_spawn` child: it must release the blocked
    /// parent when it execs or exits.
    pub vfork: bool,
}

impl Spawn {
    /// Inherit everything from `parent`.
    pub fn from_parent(parent: &Arc<Process>, name: &str, args: Vec<String>) -> Spawn {
        Spawn {
            name: String::from(name),
            args,
            env: parent.env.lock().clone(),
            cred: parent.cred(),
            fs: parent.fs.lock().clone(),
            fds: parent.fds.lock().clone(),
            parent: parent.clone(),
            pgid: Some(parent.pgid.load(Ordering::Relaxed)),
            new_session: false,
            ctty: parent.ctty.lock().clone(),
            uts: parent.uts.clone(),
            container: parent.container.lock().clone(),
            aspace: None,
            ignored: parent.ignored.load(Ordering::Relaxed),
            vfork: false,
        }
    }
}

/// Start a new process whose single task runs `entry`; the value it returns
/// is the exit code.
pub fn spawn(s: Spawn, entry: impl FnOnce() -> i32 + Send + 'static) -> KResult<Arc<Process>> {
    let task = sched::try_spawn(&s.name, move || {
        let code = entry();
        exit_current(ExitStatus::Exited(code));
    })
    .ok_or(Errno::ENOMEM)?;
    // The task cannot run before we yield, so registering now is race-free.
    let pid = task.tid;
    let pgid = if s.new_session { pid } else { s.pgid.unwrap_or(pid) };
    let sid = if s.new_session { pid } else { s.parent.sid.load(Ordering::Relaxed) };
    let mut comm = s.name.clone();
    comm.truncate(15);
    let p = Arc::new(Process {
        pid,
        ppid: AtomicU32::new(s.parent.pid),
        pgid: AtomicU32::new(pgid),
        sid: AtomicU32::new(sid),
        comm: SpinLock::new(comm),
        cmdline: SpinLock::new(s.args),
        cred: SpinLock::new(s.cred),
        fs: SpinLock::new(s.fs),
        fds: SpinLock::new(s.fds),
        env: SpinLock::new(s.env),
        uts: s.uts,
        tasks: SpinLock::new(alloc::vec![task.clone()]),
        children: SpinLock::new(Vec::new()),
        exit: SpinLock::new(None),
        child_wq: WaitQueue::new(),
        ctty: SpinLock::new(s.ctty),
        start_ns: crate::time::now_ns(),
        container: SpinLock::new(s.container),
        aspace: SpinLock::new(s.aspace),
        ignored: AtomicU64::new(s.ignored),
        cpu_at_exit: AtomicU64::new(0),
        children_cpu: AtomicU64::new(0),
        vfork_wq: WaitQueue::new(),
        vfork_pending: AtomicBool::new(s.vfork),
    });
    PROCS.lock().insert(pid, p.clone());
    s.parent.children.lock().push(p.clone());
    task.owner.store(pid, Ordering::Release);
    Ok(p)
}

/// Start a user process: spawn a task that enters ring 3 at `frame` under
/// `aspace`. The task's CR3 is set before it can be scheduled.
pub fn start_user(s: Spawn, aspace: Arc<AddressSpace>, frame: UserFrame) -> KResult<Arc<Process>> {
    start_user_with(s, aspace, frame, 0)
}

/// Like [`start_user`], but the initial task inherits `fs_base` (the thread
/// pointer). `fork` uses this so the child keeps the parent's TLS; a fresh
/// `execve`/exec passes 0 (the new program sets it up via `arch_prctl`).
pub fn start_user_with(mut s: Spawn, aspace: Arc<AddressSpace>, frame: UserFrame, fs_base: u64) -> KResult<Arc<Process>> {
    s.aspace = Some(aspace.clone());
    let p = spawn(s, move || unsafe { enter_user(&frame) })?;
    if let Some(t) = p.tasks().into_iter().next() {
        t.cr3.store(aspace.pml4(), core::sync::atomic::Ordering::Release);
        t.fs_base.store(fs_base, core::sync::atomic::Ordering::Release);
    }
    Ok(p)
}

/// Terminate the current process. Never returns.
pub fn exit_current(status: ExitStatus) -> ! {
    let me = current();
    assert!(me.pid != 0, "kernel threads exit through sched::exit_current");
    // A fatal signal that interrupted the work decides how we "died".
    let status = match (status, sched::with_current(|t| t.pending_signals())) {
        (ExitStatus::Exited(_), pending) if pending != 0 => {
            let sig = pending.trailing_zeros() + 1;
            if signal::ignored_by_default(sig) {
                status
            } else {
                ExitStatus::Signaled(sig)
            }
        }
        _ => status,
    };
    me.cpu_at_exit.store(me.cpu_ns(), Ordering::Relaxed);
    // A vfork/posix_spawn child that exits without exec'ing still frees its
    // parent.
    me.vfork_release();
    me.fds.lock().clear();
    *me.ctty.lock() = None;
    *me.exit.lock() = Some(status);
    // Orphans are re-parented to the kernel, which reaps them automatically.
    let orphans = core::mem::take(&mut *me.children.lock());
    for c in orphans {
        c.ppid.store(0, Ordering::Relaxed);
        if c.is_zombie() {
            PROCS.lock().remove(&c.pid);
        } else {
            kernel().children.lock().push(c);
        }
    }
    let parent = find(me.ppid.load(Ordering::Relaxed)).unwrap_or_else(kernel);
    if parent.pid == 0 {
        // Nobody will wait(): reap immediately.
        PROCS.lock().remove(&me.pid);
        parent.children.lock().retain(|c| c.pid != me.pid);
    } else {
        parent.signal(signal::SIGCHLD);
    }
    parent.child_wq.wake_all();
    me.tasks.lock().clear();
    drop(parent);
    drop(me);
    sched::exit_current(status.shell_code());
}

/// Selector for [`wait`].
#[derive(Clone, Copy)]
pub enum WaitFor {
    Any,
    Pid(Pid),
    Group(Pid),
}

/// Wait for a child of `parent` to exit and reap it.
/// `Ok(None)` with `nohang` when no child has exited yet.
pub fn wait(parent: &Arc<Process>, which: WaitFor, nohang: bool) -> KResult<Option<(Pid, ExitStatus)>> {
    let matches = |c: &Arc<Process>| match which {
        WaitFor::Any => true,
        WaitFor::Pid(p) => c.pid == p,
        WaitFor::Group(g) => c.pgid.load(Ordering::Relaxed) == g,
    };
    let reap = || -> KResult<Option<(Pid, ExitStatus)>> {
        let mut kids = parent.children.lock();
        if !kids.iter().any(|c| matches(c)) {
            return Err(Errno::ECHILD);
        }
        if let Some(i) = kids.iter().position(|c| matches(c) && c.is_zombie()) {
            let c = kids.remove(i);
            drop(kids);
            PROCS.lock().remove(&c.pid);
            let spent = c.cpu_at_exit.load(Ordering::Relaxed) + c.children_cpu.load(Ordering::Relaxed);
            parent.children_cpu.fetch_add(spent, Ordering::Relaxed);
            return Ok(Some((c.pid, c.exit_status().expect("zombie"))));
        }
        Ok(None)
    };
    if nohang {
        return reap();
    }
    let r = parent.child_wq.wait_until_interruptible(
        || match reap() {
            Ok(None) => None,
            other => Some(other),
        },
        None,
    );
    match r {
        Ok(v) => v,
        Err(_) => Err(Errno::EINTR),
    }
}

/// `kill(2)`: `pid > 0` one process, `pid == 0` caller's group, `pid < -1` group `-pid`.
pub fn kill(sender: &Process, pid: i64, sig: u32) -> KResult<()> {
    if sig > signal::NSIG {
        return Err(Errno::EINVAL);
    }
    let cred = sender.cred();
    let targets: Vec<Arc<Process>> = if pid > 0 {
        alloc::vec![find(pid as Pid).filter(|p| !p.is_zombie() || sig == 0).ok_or(Errno::ESRCH)?]
    } else {
        let g = if pid == 0 { sender.pgid.load(Ordering::Relaxed) } else { (-pid) as Pid };
        let v: Vec<_> = all().into_iter().filter(|p| p.pgid.load(Ordering::Relaxed) == g && !p.is_zombie()).collect();
        if v.is_empty() {
            return Err(Errno::ESRCH);
        }
        v
    };
    let mut sent = 0;
    for t in targets {
        if t.pid == 0 {
            continue;
        }
        let tc = t.cred();
        if !cred.is_root() && cred.euid != tc.uid && cred.uid != tc.uid {
            continue;
        }
        if sig != 0 {
            t.signal(sig);
        }
        sent += 1;
    }
    if sent == 0 {
        return Err(Errno::EPERM);
    }
    Ok(())
}

/// Signal the current process (e.g. SIGPIPE on a broken pipe).
pub fn signal_current(sig: u32) {
    let me = current();
    if me.pid != 0 {
        me.signal(sig);
    }
}

/// On the way back to ring 3, act on a pending signal that has no user
/// handler: a fatal default action terminates the process. (User-installed
/// handlers are not supported yet, so every non-ignored signal is fatal.)
/// Called from the syscall and interrupt return paths.
pub fn deliver_user_signals() {
    // Only meaningful for user processes.
    if current_aspace().is_none() {
        return;
    }
    let pending = sched::with_current(|t| t.pending_signals());
    if pending == 0 {
        return;
    }
    for sig in 1..=64u32 {
        if pending & (1 << (sig - 1)) == 0 {
            continue;
        }
        if signal::terminates_by_default(sig) {
            exit_current(ExitStatus::Signaled(sig));
        }
        // Ignored / stop signals: consume them so they don't spin.
        sched::with_current(|t| t.clear_signal(sig));
    }
}

/// Did the current task receive a signal that should stop its work?
pub fn interrupted() -> bool {
    sched::with_current(|t| t.signal_pending())
}

/// Discard the signals that interrupted a wait the caller wants to resume
/// (^C aimed at a foreground child, SIGCHLD...). Returns false when SIGKILL
/// is pending: it cannot be absorbed and the caller must unwind.
pub fn absorb_signals() -> bool {
    sched::with_current(|t| {
        t.clear_signals();
        !t.kill_pending()
    })
}

/// SIGKILL is pending for the current task.
pub fn killed() -> bool {
    sched::with_current(|t| t.kill_pending())
}

/// Kernel-thread tids (tasks with no process), for `ps`.
pub fn kernel_threads() -> Vec<Arc<Task>> {
    sched::all_tasks().into_iter().filter(|t| t.owner.load(Ordering::Relaxed) == 0).collect()
}

pub fn task_count() -> usize {
    sched::all_tasks().len()
}

pub fn current_tid() -> Tid {
    sched::current_tid()
}
