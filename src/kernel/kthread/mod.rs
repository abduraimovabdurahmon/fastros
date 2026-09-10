//! Cooperative kernel threads (kthreads) for FastROS.
//!
//! Provides N independent kernel threads, each with its own 32 KB stack.
//! Threads share the same address space (kernel space, no cr3 switch).
//! Scheduling is cooperative: a thread runs until it calls yield_now().
//!
//! Usage:
//!   kthread::init()              — call once from kernel_main (marks thread 0 as main)
//!   kthread::spawn(fn, arg)      — spawn a new thread; returns id or None if full
//!   kthread::yield_now()         — give up CPU to the next ready thread
//!
//! Thread 0 is always the main/boot thread and is never freed.
//! Threads 1..MAX_KTHREADS are used for SSH sessions (one per session).

// ── KContext: saved CPU state per thread ─────────────────────────────────────
//
// Layout MUST match arch/x86_64/boot.s :: kthread_switch offsets:
//   offset  0: rsp
//   offset  8: rbp
//   offset 16: rbx
//   offset 24: r12
//   offset 32: r13
//   offset 40: r14
//   offset 48: r15
//   offset 56: rip

#[repr(C)]
struct KContext {
    rsp: u64,  // 0
    rbp: u64,  // 8
    rbx: u64,  // 16
    r12: u64,  // 24
    r13: u64,  // 32
    r14: u64,  // 40
    r15: u64,  // 48
    rip: u64,  // 56  — entry point for new threads; .kret for resumed threads
}

impl KContext {
    const fn zeroed() -> Self {
        Self { rsp: 0, rbp: 0, rbx: 0, r12: 0, r13: 0, r14: 0, r15: 0, rip: 0 }
    }
}

// ── Thread state ──────────────────────────────────────────────────────────────

#[derive(Copy, Clone, PartialEq)]
pub enum KThreadState {
    Free,     // slot unused
    Ready,    // runnable, waiting for CPU
    Running,  // currently on CPU
    Dead,     // function returned; slot will be freed on next schedule
}

struct KThread {
    ctx:   KContext,
    state: KThreadState,
    func:  usize,   // fn(usize) stored as raw pointer
    arg:   usize,
}

impl KThread {
    const fn empty() -> Self {
        Self {
            ctx:   KContext::zeroed(),
            state: KThreadState::Free,
            func:  0,
            arg:   0,
        }
    }
}

// ── Constants ─────────────────────────────────────────────────────────────────

/// Thread 0 = main/boot thread; threads 1..MAX_KTHREADS = SSH sessions.
pub const MAX_KTHREADS: usize = 5;

/// Stack size per kthread. 5 × 32 KB = 160 KB total in BSS — acceptable.
const STACK_SIZE: usize = 32 * 1024;

// ── Global state (single-CPU bare metal — no locking needed) ─────────────────

static mut KTHREADS: [KThread; MAX_KTHREADS] = [const { KThread::empty() }; MAX_KTHREADS];
static mut CURRENT: usize = 0;
/// One 32 KB stack per kthread slot, allocated statically in BSS.
static mut KSTACKS: [[u8; STACK_SIZE]; MAX_KTHREADS] = [[0u8; STACK_SIZE]; MAX_KTHREADS];

// ── Assembly context switch (defined in arch/x86_64/boot.s) ──────────────────

extern "C" {
    /// Save *from* registers, switch stack, restore *to* registers.
    /// Jumps to to.rip (kthread_trampoline for new threads; .kret for resumed).
    fn kthread_switch(from: *mut KContext, to: *const KContext);
}

// ── Thread trampoline ─────────────────────────────────────────────────────────

/// Entry point for all newly spawned kthreads.
/// Called via `jmp` from kthread_switch when a thread runs for the first time.
/// At this point rsp points to the thread's own clean stack.
unsafe extern "C" fn kthread_trampoline() -> ! {
    let id = CURRENT;
    let func: fn(usize) = core::mem::transmute(KTHREADS[id].func);
    let arg  = KTHREADS[id].arg;
    func(arg);                           // run the thread's work
    KTHREADS[id].state = KThreadState::Dead;
    do_schedule();                       // never returns to this thread
    loop { core::hint::spin_loop(); }
}

// ── Scheduler ─────────────────────────────────────────────────────────────────

unsafe fn do_schedule() {
    let cur = CURRENT;

    // If the current thread is still alive, mark it Ready for the next round.
    if KTHREADS[cur].state == KThreadState::Running {
        KTHREADS[cur].state = KThreadState::Ready;
    }

    // Free any Dead threads so their slots can be reused.
    for t in KTHREADS.iter_mut() {
        if t.state == KThreadState::Dead { t.state = KThreadState::Free; }
    }

    // Round-robin: find the next Ready thread starting after `cur`.
    let next = (1..=MAX_KTHREADS)
        .map(|i| (cur + i) % MAX_KTHREADS)
        .find(|&i| KTHREADS[i].state == KThreadState::Ready);

    let next = match next {
        Some(n) => n,
        None    => {
            // No other thread is ready — resume current if still alive.
            if KTHREADS[cur].state == KThreadState::Ready {
                KTHREADS[cur].state = KThreadState::Running;
            }
            return;
        }
    };

    KTHREADS[next].state = KThreadState::Running;
    CURRENT = next;

    let from = &mut KTHREADS[cur].ctx  as *mut KContext;
    let to   = &    KTHREADS[next].ctx as *const KContext;
    kthread_switch(from, to);
    // Returns here when another thread switches back to `cur`.
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Initialize the kthread subsystem.
/// Must be called once from kernel_main before any other kthread function.
/// Marks the calling context (boot thread) as thread 0, currently Running.
pub fn init() {
    unsafe {
        KTHREADS[0].state = KThreadState::Running;
        CURRENT = 0;
    }
}

/// Spawn a new kthread that will call `func(arg)`.
/// Returns the thread id on success, or None if all slots are occupied.
pub fn spawn(func: fn(usize), arg: usize) -> Option<usize> {
    unsafe {
        // Find a free slot (skip 0 — always the main thread).
        let id = (1..MAX_KTHREADS).find(|&i| KTHREADS[i].state == KThreadState::Free)?;

        // Set up the initial stack frame.
        //
        // kthread_switch restores rsp then does `jmp [rsi+56]` (no implicit push).
        // x86_64 ABI: at function entry rsp ≡ 8 (mod 16) — because `call` pushes
        // 8 bytes. Since we jmp (not call) into kthread_trampoline we must
        // pre-align rsp so it satisfies the ABI at trampoline entry.
        //   desired: rsp_after_jmp % 16 == 8
        //   kthread_switch sets rsp = ctx.rsp, then jmps → no extra push
        //   so ctx.rsp must be ≡ 8 (mod 16).
        let stack_top = KSTACKS[id].as_ptr() as u64 + STACK_SIZE as u64;
        let rsp = (stack_top & !15u64) - 8; // 16-aligned top minus 8 → ≡ 8 mod 16

        KTHREADS[id] = KThread {
            ctx: KContext {
                rsp,
                rbp: 0, rbx: 0, r12: 0, r13: 0, r14: 0, r15: 0,
                rip: kthread_trampoline as u64,
            },
            state: KThreadState::Ready,
            func:  func as usize,
            arg,
        };

        Some(id)
    }
}

/// Cooperatively yield the CPU to the next ready kthread.
#[inline]
pub fn yield_now() {
    unsafe { do_schedule(); }
}

/// Returns the id of the currently running kthread.
#[inline]
pub fn current() -> usize {
    unsafe { CURRENT }
}

/// Returns true if any non-main kthread (id ≥ 1) is alive (Ready or Running).
pub fn any_alive() -> bool {
    unsafe {
        KTHREADS[1..].iter().any(|t| {
            matches!(t.state, KThreadState::Ready | KThreadState::Running)
        })
    }
}

/// Returns the state of kthread `id`.
pub fn state(id: usize) -> KThreadState {
    unsafe {
        if id < MAX_KTHREADS { KTHREADS[id].state } else { KThreadState::Free }
    }
}
