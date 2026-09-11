//! Trap dispatch: exceptions, hardware interrupts, spurious vectors.

use crate::arch::trap::{exception_name, TrapFrame, VEC_IRQ_BASE};
use crate::arch::{cpu, pic};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

const IRQ_LINES: usize = 16;

/// Handler per legacy IRQ line (a `fn()` stored as usize; 0 = none).
static HANDLERS: [AtomicUsize; IRQ_LINES] = [const { AtomicUsize::new(0) }; IRQ_LINES];
/// Interrupt counts per line (for /proc/interrupts).
static COUNTS: [AtomicU64; IRQ_LINES] = [const { AtomicU64::new(0) }; IRQ_LINES];
static SPURIOUS: AtomicU64 = AtomicU64::new(0);

/// Install `handler` for IRQ `line` and unmask it.
pub fn register_irq(line: u8, handler: fn()) {
    HANDLERS[line as usize].store(handler as usize, Ordering::Release);
    pic::unmask(line);
}

pub fn irq_counts() -> [u64; IRQ_LINES] {
    core::array::from_fn(|i| COUNTS[i].load(Ordering::Relaxed))
}

pub fn spurious_count() -> u64 {
    SPURIOUS.load(Ordering::Relaxed)
}

pub fn dispatch(tf: &mut TrapFrame) {
    let v = tf.vector;
    if v < 32 {
        exception(tf);
    } else if v < (VEC_IRQ_BASE as u64 + IRQ_LINES as u64) {
        irq((v - VEC_IRQ_BASE as u64) as u8);
    } else {
        SPURIOUS.fetch_add(1, Ordering::Relaxed);
    }
    // Returning to ring 3? Deliver any pending fatal signal (e.g. a timer
    // tick that noticed a SIGTERM/SIGKILL sent to this container).
    if tf.from_user() {
        crate::proc::deliver_user_signals();
    }
}

fn irq(line: u8) {
    if (line == 7 || line == 15) && pic::is_spurious(line) {
        SPURIOUS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    COUNTS[line as usize].fetch_add(1, Ordering::Relaxed);
    let h = HANDLERS[line as usize].load(Ordering::Acquire);
    // EOI first: handlers may wake tasks, and the line must be able to fire
    // again as soon as interrupts are re-enabled.
    pic::eoi(line);
    if h != 0 {
        let f: fn() = unsafe { core::mem::transmute(h) };
        f();
    }
}

fn exception(tf: &mut TrapFrame) {
    let v = tf.vector;
    if v == 14 {
        let addr = cpu::read_cr2() as usize;
        if crate::mm::fault::handle(tf, addr) {
            return;
        }
    }
    if v == 3 && !tf.from_user() {
        crate::kwarn!("trap", "breakpoint at {:#x}", tf.rip);
        return;
    }
    if v == 2 {
        crate::kerr!("trap", "NMI received (rip {:#x}) — ignoring", tf.rip);
        return;
    }
    // A fault in a user program kills only that process, never the kernel:
    // a container segfault must not take the whole system down.
    if tf.from_user() {
        let sig = match v {
            0 | 16 | 19 => crate::proc::signal::SIGFPE,
            6 => crate::proc::signal::SIGILL,
            _ => crate::proc::signal::SIGSEGV,
        };
        let pid = crate::proc::current().pid;
        crate::kwarn!("trap", "{} in pid {} at rip {:#x} (cr2 {:#x}) -> {}", exception_name(v), pid, tf.rip, cpu::read_cr2(), crate::proc::signal::name(sig));
        crate::proc::exit_current(crate::proc::ExitStatus::Signaled(sig));
    }
    crate::panic::exception(tf, exception_name(v));
}
