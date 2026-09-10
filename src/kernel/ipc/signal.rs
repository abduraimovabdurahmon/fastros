//! UNIX-like Signal subsystem
//!
//! Signals are asynchronous notifications sent to a process.
//! Delivery: checked on every return from syscall or interrupt (before iretq/sysretq).
//!
//! Per-process signal state lives in `Process::signals`.
//! Delivery is initiated by the syscall/interrupt return path (kernel exit).

pub const SIGHUP:  u8 = 1;
pub const SIGINT:  u8 = 2;
pub const SIGQUIT: u8 = 3;
pub const SIGILL:  u8 = 4;
pub const SIGTRAP: u8 = 5;
pub const SIGABRT: u8 = 6;
pub const SIGFPE:  u8 = 8;
pub const SIGKILL: u8 = 9;
pub const SIGSEGV: u8 = 11;
pub const SIGPIPE: u8 = 13;
pub const SIGTERM: u8 = 15;
pub const SIGCHLD: u8 = 17;
pub const SIGCONT: u8 = 18;
pub const SIGSTOP: u8 = 19;

/// What the kernel does when a signal has no user handler.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DefaultAction {
    Terminate,
    Ignore,
    Stop,
    Continue,
    CoreDump, // terminate + (TODO) write core file
}

pub fn default_action(sig: u8) -> DefaultAction {
    match sig {
        SIGHUP | SIGINT | SIGQUIT | SIGILL | SIGTRAP
        | SIGABRT | SIGFPE | SIGSEGV | SIGPIPE | SIGTERM => DefaultAction::Terminate,
        SIGKILL  => DefaultAction::Terminate, // cannot be caught or ignored
        SIGSTOP  => DefaultAction::Stop,
        SIGCONT  => DefaultAction::Continue,
        SIGCHLD  => DefaultAction::Ignore,
        _        => DefaultAction::Ignore,
    }
}

/// A signal handler registered via sigaction().
/// None = default action.  Some(0) = SIG_IGN (ignore).
#[derive(Clone, Copy)]
pub struct SigAction {
    pub handler: Option<u64>,   // userspace function pointer
    pub mask:    SigSet,        // signals to block while handler runs
    pub flags:   u32,
}

/// Bitmask of up to 64 signals (signal N is bit N-1).
#[derive(Clone, Copy, Default)]
pub struct SigSet(pub u64);

impl SigSet {
    pub const fn empty() -> Self { Self(0) }
    pub const fn all()   -> Self { Self(!0) }

    pub fn add(&mut self, sig: u8) {
        if sig >= 1 && sig <= 64 { self.0 |= 1u64 << (sig - 1); }
    }
    pub fn remove(&mut self, sig: u8) {
        if sig >= 1 && sig <= 64 { self.0 &= !(1u64 << (sig - 1)); }
    }
    pub fn contains(&self, sig: u8) -> bool {
        sig >= 1 && sig <= 64 && (self.0 >> (sig - 1)) & 1 == 1
    }
    pub fn is_empty(&self) -> bool { self.0 == 0 }

    /// Lowest pending signal not in `mask`.  Returns None if none pending.
    pub fn next_pending(&self, mask: SigSet) -> Option<u8> {
        let unblocked = self.0 & !mask.0;
        if unblocked == 0 { return None; }
        Some(unblocked.trailing_zeros() as u8 + 1)
    }
}

/// Per-process signal state (embedded in Process).
#[derive(Clone, Copy)]
pub struct SignalState {
    /// Pending signals (bit set = signal queued).
    pub pending:  SigSet,
    /// Currently blocked signals (signal mask).
    pub blocked:  SigSet,
    /// Per-signal actions (indices 0–63 correspond to signals 1–64).
    pub actions:  [Option<SigAction>; 64],
}

impl SignalState {
    pub const fn new() -> Self {
        Self {
            pending: SigSet::empty(),
            blocked: SigSet::empty(),
            actions: [None; 64],
        }
    }

    /// Queue a signal for delivery.
    pub fn send(&mut self, sig: u8) {
        self.pending.add(sig);
    }

    /// Deliver the next pending unblocked signal.
    /// Returns (signal_number, handler_address_or_default_action).
    pub fn deliver_next(&mut self) -> Option<(u8, Option<u64>)> {
        let sig = self.pending.next_pending(self.blocked)?;
        self.pending.remove(sig);

        let action = if (sig as usize) < 64 { self.actions[sig as usize - 1] } else { None };
        let handler = action.and_then(|a| a.handler);
        Some((sig, handler))
    }

    /// Register a signal handler (sigaction).
    pub fn set_action(&mut self, sig: u8, action: SigAction) {
        if sig >= 1 && sig <= 64 && sig != SIGKILL && sig != SIGSTOP {
            self.actions[sig as usize - 1] = Some(action);
        }
    }
}
