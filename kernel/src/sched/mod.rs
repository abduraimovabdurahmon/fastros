//! Task scheduler.
//!
//! Model (the classic non-preemptive-kernel design):
//! * every task has its own kernel stack (with an unmapped guard page) and
//!   switches with `switch_stacks`, which saves only callee-saved registers;
//! * kernel code runs until it blocks, sleeps or calls [`yield_now`] /
//!   [`cond_resched`]; long computations call `cond_resched` so the timer's
//!   time-slice accounting still gives other tasks the CPU;
//! * user-mode code (containers) is preempted by the timer interrupt;
//! * when nothing is runnable the boot context — the idle task — executes
//!   `sti; hlt` until the next interrupt.
//!
//! Round-robin over one run queue; sleeping tasks sit in a deadline list that
//! the timer interrupt scans every tick.

use crate::arch::context::{prepare_stack, switch_stacks};
use crate::arch::{cpu, gdt};
use crate::mm::KernelStack;
use crate::sync::{SpinLock, WaitQueue};
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU32, AtomicU64, AtomicU8, Ordering};

pub type Tid = u32;

/// Pending-signal bit of SIGKILL.
const KILL_BIT: u64 = 1 << (crate::proc::signal::SIGKILL - 1);

/// Kernel stack size per task.
pub const KSTACK_PAGES: usize = 16;
/// Time slice before `cond_resched` / user preemption hands the CPU on.
pub const TIME_SLICE_NS: u64 = 10_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TaskState {
    Ready = 0,
    Running = 1,
    Blocked = 2,
    Dead = 3,
}

impl TaskState {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Ready,
            1 => Self::Running,
            2 => Self::Blocked,
            _ => Self::Dead,
        }
    }
}

type Entry = Box<dyn FnOnce() + Send + 'static>;

pub struct Task {
    pub tid: Tid,
    name: SpinLock<String>,
    state: AtomicU8,
    saved_rsp: UnsafeCell<usize>,
    stack: SpinLock<Option<KernelStack>>,
    stack_top: usize,
    entry: SpinLock<Option<Entry>>,
    /// Deadline (monotonic ns) of the current timed block, 0 if none.
    wake_at: AtomicU64,
    /// Pending signals, one bit per signal number (1..=64 → bit n-1).
    signals: AtomicU64,
    pub exit_code: AtomicI32,
    exited: AtomicBool,
    /// Woken when the task exits (join).
    pub exit_wq: WaitQueue,
    /// Nanoseconds spent running.
    cpu_ns: AtomicU64,
    /// Opaque owner cookie: the process this task belongs to (0 = kernel).
    pub owner: AtomicU32,
    pub created_ns: u64,
}

// `saved_rsp` is only touched by the scheduler with interrupts disabled.
unsafe impl Sync for Task {}
unsafe impl Send for Task {}

impl Task {
    pub fn state(&self) -> TaskState {
        TaskState::from_u8(self.state.load(Ordering::Acquire))
    }
    fn set_state(&self, s: TaskState) {
        self.state.store(s as u8, Ordering::Release);
    }
    pub fn name(&self) -> String {
        self.name.lock().clone()
    }
    pub fn set_name(&self, n: &str) {
        let mut g = self.name.lock();
        g.clear();
        g.push_str(n);
    }
    pub fn cpu_ns(&self) -> u64 {
        self.cpu_ns.load(Ordering::Relaxed)
    }
    pub fn is_idle(&self) -> bool {
        self.tid == 0
    }

    /// Mark signal `sig` pending and wake the task out of an interruptible wait.
    pub fn send_signal(self: &Arc<Self>, sig: u32) {
        if sig == 0 || sig > 64 {
            return;
        }
        self.signals.fetch_or(1 << (sig - 1), Ordering::AcqRel);
        wake(self);
    }
    pub fn signal_pending(&self) -> bool {
        self.signals.load(Ordering::Acquire) != 0
    }
    pub fn pending_signals(&self) -> u64 {
        self.signals.load(Ordering::Acquire)
    }
    /// Take (clear) one pending signal, lowest number first.
    pub fn take_signal(&self) -> Option<u32> {
        loop {
            let cur = self.signals.load(Ordering::Acquire);
            if cur == 0 {
                return None;
            }
            let bit = cur.trailing_zeros();
            if self
                .signals
                .compare_exchange(cur, cur & !(1 << bit), Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(bit + 1);
            }
        }
    }
    /// Discard pending signals, except SIGKILL, which can never be discarded.
    pub fn clear_signals(&self) {
        self.signals.fetch_and(KILL_BIT, Ordering::AcqRel);
    }
    /// Discard one pending signal (SIGKILL cannot be discarded).
    pub fn clear_signal(&self, sig: u32) {
        if (1..=64).contains(&sig) && sig != crate::proc::signal::SIGKILL {
            self.signals.fetch_and(!(1 << (sig - 1)), Ordering::AcqRel);
        }
    }
    /// SIGKILL is pending: whatever the task is doing must unwind and exit.
    pub fn kill_pending(&self) -> bool {
        self.signals.load(Ordering::Acquire) & KILL_BIT != 0
    }
    pub fn has_exited(&self) -> bool {
        self.exited.load(Ordering::Acquire)
    }
    /// Block until the task has exited; returns its exit code.
    pub fn join(&self) -> i32 {
        self.exit_wq.wait_until(|| self.has_exited().then_some(()));
        self.exit_code.load(Ordering::Acquire)
    }
    pub fn stack_bounds(&self) -> (usize, usize) {
        (self.stack_top - KSTACK_PAGES * crate::mm::PAGE_SIZE, self.stack_top)
    }
}

struct RunQueue {
    ready: VecDeque<Arc<Task>>,
    /// (deadline, task) of timed blocks; stale entries are dropped lazily.
    sleepers: Vec<(u64, Arc<Task>)>,
    zombies: Vec<Arc<Task>>,
    current: Option<Arc<Task>>,
    idle: Option<Arc<Task>>,
    slice_start_ns: u64,
    last_switch_ns: u64,
    switches: u64,
}

static RQ: SpinLock<RunQueue> = SpinLock::new(RunQueue {
    ready: VecDeque::new(),
    sleepers: Vec::new(),
    zombies: Vec::new(),
    current: None,
    idle: None,
    slice_start_ns: 0,
    last_switch_ns: 0,
    switches: 0,
});

/// Raw pointer to the running task (kept alive by `RQ.current`).
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(core::ptr::null_mut());
static TASKS: SpinLock<BTreeMap<Tid, Arc<Task>>> = SpinLock::new(BTreeMap::new());
static NEXT_TID: AtomicU32 = AtomicU32::new(1);
static NEED_RESCHED: AtomicBool = AtomicBool::new(false);
static IDLE_NS: AtomicU64 = AtomicU64::new(0);
/// CPU time of process tasks ("user" work, even when native) and kernel threads.
static USER_NS: AtomicU64 = AtomicU64::new(0);
static SYSTEM_NS: AtomicU64 = AtomicU64::new(0);
/// Load averages (1, 5, 15 min) in Linux fixed point (FSHIFT = 11).
static LOADAVG: [AtomicU64; 3] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];
static LOAD_NEXT_NS: AtomicU64 = AtomicU64::new(5_000_000_000);
const FSHIFT: u64 = 11;
const FIXED_1: u64 = 1 << FSHIFT;
const EXP: [u64; 3] = [1884, 2014, 2037];

fn new_task(tid: Tid, name: &str, stack: Option<KernelStack>, stack_top: usize, rsp: usize, entry: Option<Entry>) -> Arc<Task> {
    Arc::new(Task {
        tid,
        name: SpinLock::new(String::from(name)),
        state: AtomicU8::new(TaskState::Ready as u8),
        saved_rsp: UnsafeCell::new(rsp),
        stack: SpinLock::new(stack),
        stack_top,
        entry: SpinLock::new(entry),
        wake_at: AtomicU64::new(0),
        signals: AtomicU64::new(0),
        exit_code: AtomicI32::new(0),
        exited: AtomicBool::new(false),
        exit_wq: WaitQueue::new(),
        cpu_ns: AtomicU64::new(0),
        owner: AtomicU32::new(0),
        created_ns: crate::time::now_ns(),
    })
}

/// Turn the boot context into the idle task (tid 0). Call once, early.
pub fn init() {
    let (_, top) = crate::arch::boot::boot_stack();
    let idle = new_task(0, "idle", None, top, 0, None);
    idle.set_state(TaskState::Running);
    CURRENT.store(Arc::as_ptr(&idle) as *mut Task, Ordering::Release);
    let mut rq = RQ.lock();
    rq.current = Some(idle.clone());
    rq.idle = Some(idle.clone());
    rq.last_switch_ns = crate::time::now_ns();
    drop(rq);
    TASKS.lock().insert(0, idle);
}

/// Start a kernel task running `f`.
pub fn spawn(name: &str, f: impl FnOnce() + Send + 'static) -> Arc<Task> {
    try_spawn(name, f).expect("spawn: out of memory for a kernel stack")
}

pub fn try_spawn(name: &str, f: impl FnOnce() + Send + 'static) -> Option<Arc<Task>> {
    let stack = KernelStack::new(KSTACK_PAGES)?;
    let top = stack.top();
    let rsp = prepare_stack(top);
    let tid = NEXT_TID.fetch_add(1, Ordering::Relaxed);
    let t = new_task(tid, name, Some(stack), top, rsp, Some(Box::new(f)));
    TASKS.lock().insert(tid, t.clone());
    RQ.lock().ready.push_back(t.clone());
    Some(t)
}

/// The running task.
pub fn current() -> Arc<Task> {
    let _irq = cpu::IrqGuard::new();
    RQ.lock().current.clone().expect("sched::init not called")
}

/// Cheap access to the running task without touching reference counts.
pub fn with_current<R>(f: impl FnOnce(&Task) -> R) -> R {
    let p = CURRENT.load(Ordering::Acquire);
    assert!(!p.is_null(), "sched::init not called");
    f(unsafe { &*p })
}

pub fn current_tid() -> Tid {
    let p = CURRENT.load(Ordering::Acquire);
    if p.is_null() {
        0
    } else {
        unsafe { (*p).tid }
    }
}

pub fn find(tid: Tid) -> Option<Arc<Task>> {
    TASKS.lock().get(&tid).cloned()
}

/// Snapshot of every live task.
pub fn all_tasks() -> Vec<Arc<Task>> {
    TASKS.lock().values().cloned().collect()
}

/// Make a blocked task runnable. Harmless on tasks that are not blocked.
pub fn wake(t: &Arc<Task>) {
    let mut rq = RQ.lock();
    if t.state() == TaskState::Blocked {
        t.set_state(TaskState::Ready);
        t.wake_at.store(0, Ordering::Relaxed);
        rq.ready.push_back(t.clone());
    }
}

/// Block the current task until woken (or until `deadline_ns`). The caller
/// must have registered the task somewhere a waker will find it, with
/// interrupts disabled since checking its condition.
pub fn block_current(deadline_ns: Option<u64>) {
    let _irq = cpu::IrqGuard::new();
    {
        let mut rq = RQ.lock();
        let cur = rq.current.clone().expect("no current task");
        assert!(!cur.is_idle(), "the idle task must never block");
        cur.set_state(TaskState::Blocked);
        if let Some(d) = deadline_ns {
            cur.wake_at.store(d, Ordering::Relaxed);
            rq.sleepers.push((d, cur));
        }
    }
    schedule();
}

/// Sleep for at least `ns` nanoseconds. Returns early (false) if a signal
/// arrives; the signal stays pending for the caller to act on.
pub fn sleep_ns(ns: u64) -> bool {
    let deadline = crate::time::now_ns().saturating_add(ns);
    loop {
        if with_current(|t| t.signal_pending()) {
            return false;
        }
        if crate::time::now_ns() >= deadline {
            return true;
        }
        block_current(Some(deadline));
    }
}

pub fn sleep_ms(ms: u64) -> bool {
    sleep_ns(ms.saturating_mul(1_000_000))
}

pub fn yield_now() {
    schedule();
}

/// Yield if the current time slice is used up (call from long loops).
#[inline]
pub fn cond_resched() {
    if NEED_RESCHED.load(Ordering::Relaxed) {
        schedule();
    }
}

pub fn need_resched() -> bool {
    NEED_RESCHED.load(Ordering::Relaxed)
}

/// Exit the current task. Never returns.
pub fn exit_current(code: i32) -> ! {
    let me = current();
    assert!(!me.is_idle(), "the idle task cannot exit");
    me.exit_code.store(code, Ordering::Release);
    me.exited.store(true, Ordering::Release);
    me.exit_wq.wake_all();
    {
        let _irq = cpu::IrqGuard::new();
        let mut rq = RQ.lock();
        me.set_state(TaskState::Dead);
        rq.zombies.push(me.clone());
    }
    drop(me);
    schedule();
    unreachable!("a dead task was scheduled again");
}

/// Pick the next task and switch to it.
pub fn schedule() {
    let held = crate::sync::spinlocks_held();
    assert!(held == 0, "schedule() called with {held} spinlock(s) held");
    let irq = cpu::irq_save();
    let now = crate::time::now_ns();
    let (prev_rsp, next_rsp) = {
        let mut rq = RQ.lock();
        let prev = rq.current.clone().expect("sched::init not called");
        if prev.state() == TaskState::Running {
            if prev.is_idle() {
                prev.set_state(TaskState::Ready);
            } else {
                prev.set_state(TaskState::Ready);
                rq.ready.push_back(prev.clone());
            }
        }
        let next = match rq.ready.pop_front() {
            Some(t) => t,
            None => rq.idle.clone().expect("idle task"),
        };
        next.set_state(TaskState::Running);
        rq.slice_start_ns = now;
        NEED_RESCHED.store(false, Ordering::Relaxed);
        if Arc::ptr_eq(&prev, &next) {
            drop(rq);
            cpu::irq_restore(irq);
            return;
        }
        let ran = now.saturating_sub(rq.last_switch_ns);
        prev.cpu_ns.fetch_add(ran, Ordering::Relaxed);
        if prev.is_idle() {
            IDLE_NS.fetch_add(ran, Ordering::Relaxed);
        } else if prev.owner.load(Ordering::Relaxed) != 0 {
            USER_NS.fetch_add(ran, Ordering::Relaxed);
        } else {
            SYSTEM_NS.fetch_add(ran, Ordering::Relaxed);
        }
        rq.last_switch_ns = now;
        rq.switches += 1;
        if !next.is_idle() {
            gdt::set_kernel_stack(next.stack_top as u64);
        }
        CURRENT.store(Arc::as_ptr(&next) as *mut Task, Ordering::Release);
        let p = prev.saved_rsp.get();
        let n = unsafe { *next.saved_rsp.get() };
        rq.current = Some(next);
        (p, n)
        // `prev` stays alive: it is in `ready`, a wait queue, `sleepers`,
        // `zombies` or `TASKS`.
    };
    unsafe { switch_stacks(prev_rsp, next_rsp) };
    after_switch();
    cpu::irq_restore(irq);
}

/// Work every task does right after it gets the CPU back.
fn after_switch() {
    reap_zombies();
}

fn reap_zombies() {
    let dead: Vec<Arc<Task>> = {
        let mut rq = RQ.lock();
        let cur = CURRENT.load(Ordering::Relaxed);
        let (gone, keep): (Vec<_>, Vec<_>) = rq.zombies.drain(..).partition(|z| Arc::as_ptr(z) != cur);
        rq.zombies = keep;
        gone
    };
    if dead.is_empty() {
        return;
    }
    let mut tasks = TASKS.lock();
    for z in &dead {
        tasks.remove(&z.tid);
    }
    drop(tasks);
    for z in dead {
        // Free the stack now even if someone still holds the Task (join handles).
        let stack = z.stack.lock().take();
        drop(stack);
    }
}

/// First code a new task runs (called from `task_entry_asm`).
#[no_mangle]
extern "C" fn task_entry() -> ! {
    after_switch();
    cpu::irq_enable();
    let f = with_current(|t| t.entry.lock().take()).expect("task started twice");
    f();
    exit_current(0);
}

/// Timer interrupt: wake expired sleepers, account the time slice.
pub fn timer_tick() {
    let now = crate::time::now_ns();
    let mut rq = RQ.lock();
    let mut i = 0;
    while i < rq.sleepers.len() {
        let (deadline, ref t) = rq.sleepers[i];
        let live = t.wake_at.load(Ordering::Relaxed) == deadline && t.state() == TaskState::Blocked;
        if !live {
            rq.sleepers.swap_remove(i);
        } else if deadline <= now {
            let (_, t) = rq.sleepers.swap_remove(i);
            t.wake_at.store(0, Ordering::Relaxed);
            t.set_state(TaskState::Ready);
            rq.ready.push_back(t);
        } else {
            i += 1;
        }
    }
    if now.saturating_sub(rq.slice_start_ns) >= TIME_SLICE_NS && !rq.ready.is_empty() {
        NEED_RESCHED.store(true, Ordering::Relaxed);
    }
    // Every 5 s fold the number of runnable tasks into the load averages.
    if now >= LOAD_NEXT_NS.load(Ordering::Relaxed) {
        LOAD_NEXT_NS.store(now + 5_000_000_000, Ordering::Relaxed);
        let cur_running = rq.current.as_ref().is_some_and(|c| !c.is_idle()) as u64;
        let active = (rq.ready.len() as u64 + cur_running) * FIXED_1;
        for (i, e) in EXP.iter().enumerate() {
            let old = LOADAVG[i].load(Ordering::Relaxed);
            let new = (old * e + active * (FIXED_1 - e) + FIXED_1 / 2) >> FSHIFT;
            LOADAVG[i].store(new, Ordering::Relaxed);
        }
    }
}

/// Load averages as (integer, hundredths) pairs for 1, 5 and 15 minutes.
pub fn loadavg() -> [(u64, u64); 3] {
    core::array::from_fn(|i| {
        let v = LOADAVG[i].load(Ordering::Relaxed) + FIXED_1 / 200;
        (v >> FSHIFT, ((v & (FIXED_1 - 1)) * 100) >> FSHIFT)
    })
}

/// (user, system, idle) CPU nanoseconds since boot, including the running slice.
pub fn cpu_times() -> (u64, u64, u64) {
    let (cur_user, cur_sys, cur_idle) = {
        let rq = RQ.lock();
        let ran = crate::time::now_ns().saturating_sub(rq.last_switch_ns);
        match rq.current.as_ref() {
            Some(c) if c.is_idle() => (0, 0, ran),
            Some(c) if c.owner.load(Ordering::Relaxed) != 0 => (ran, 0, 0),
            Some(_) => (0, ran, 0),
            None => (0, 0, 0),
        }
    };
    (
        USER_NS.load(Ordering::Relaxed) + cur_user,
        SYSTEM_NS.load(Ordering::Relaxed) + cur_sys,
        IDLE_NS.load(Ordering::Relaxed) + cur_idle,
    )
}

/// Last task id handed out (the "last pid" of /proc/loadavg).
pub fn last_tid() -> Tid {
    NEXT_TID.load(Ordering::Relaxed) - 1
}

/// The idle loop: run whatever is ready, otherwise halt until an interrupt.
pub fn idle_loop() -> ! {
    loop {
        cpu::irq_disable();
        let idle = RQ.lock().ready.is_empty();
        if idle {
            cpu::enable_and_halt();
        } else {
            cpu::irq_enable();
            schedule();
        }
    }
}

pub struct SchedStats {
    pub switches: u64,
    pub idle_ns: u64,
    pub runnable: usize,
    pub tasks: usize,
}

pub fn stats() -> SchedStats {
    let (switches, runnable) = {
        let rq = RQ.lock();
        (rq.switches, rq.ready.len())
    };
    SchedStats { switches, idle_ns: IDLE_NS.load(Ordering::Relaxed), runnable, tasks: TASKS.lock().len() }
}
