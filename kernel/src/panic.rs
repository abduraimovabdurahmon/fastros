//! Fatal error reporting: panics, unhandled exceptions, lock recursion.
//!
//! Everything here writes straight to the UART, bypassing (and breaking) the
//! locks the normal log path uses, because a panic may interrupt their holder.

use crate::arch::trap::TrapFrame;
use crate::arch::cpu;
use core::fmt::Write;
use core::panic::{Location, PanicInfo};
use core::sync::atomic::{AtomicBool, Ordering};

static PANICKING: AtomicBool = AtomicBool::new(false);

struct Raw;
impl Write for Raw {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        crate::drivers::serial::write_raw(s.as_bytes());
        Ok(())
    }
}

fn begin() -> Raw {
    cpu::irq_disable();
    if PANICKING.swap(true, Ordering::SeqCst) {
        let _ = Raw.write_str("\n*** nested panic — halting\n");
        cpu::halt_forever();
    }
    unsafe { crate::drivers::serial::LOCK.force_unlock() };
    Raw
}

fn finish(mut w: Raw) -> ! {
    backtrace(&mut w);
    let _ = writeln!(w, "--- end of kernel panic ---");
    // Tests and supervisors look for this line.
    let _ = writeln!(w, "KERNEL PANIC");
    if crate::boot::info().arg("panic").is_some_and(|v| v == "poweroff") {
        crate::power::poweroff();
    }
    cpu::halt_forever();
}

fn backtrace(w: &mut Raw) {
    let _ = writeln!(w, "backtrace (frame pointers):");
    let mut rbp: usize;
    unsafe { core::arch::asm!("mov {}, rbp", out(reg) rbp) };
    for depth in 0..32 {
        if rbp < crate::mm::PHYS_OFFSET || rbp % 8 != 0 {
            break;
        }
        if crate::mm::virt_to_phys(rbp).is_none() {
            break;
        }
        let ret = unsafe { *((rbp + 8) as *const usize) };
        let next = unsafe { *(rbp as *const usize) };
        if ret == 0 {
            break;
        }
        let _ = writeln!(w, "  #{depth:<2} {ret:#018x}");
        if next <= rbp {
            break;
        }
        rbp = next;
    }
}

fn dump_frame(w: &mut Raw, tf: &TrapFrame) {
    let _ = writeln!(w, "  rip {:#018x}  cs  {:#06x}  rflags {:#010x}", tf.rip, tf.cs, tf.rflags);
    let _ = writeln!(w, "  rsp {:#018x}  ss  {:#06x}  error  {:#x}", tf.rsp, tf.ss, tf.error);
    let _ = writeln!(w, "  rax {:#018x}  rbx {:#018x}  rcx {:#018x}", tf.rax, tf.rbx, tf.rcx);
    let _ = writeln!(w, "  rdx {:#018x}  rsi {:#018x}  rdi {:#018x}", tf.rdx, tf.rsi, tf.rdi);
    let _ = writeln!(w, "  rbp {:#018x}  r8  {:#018x}  r9  {:#018x}", tf.rbp, tf.r8, tf.r9);
    let _ = writeln!(w, "  r10 {:#018x}  r11 {:#018x}  r12 {:#018x}", tf.r10, tf.r11, tf.r12);
    let _ = writeln!(w, "  r13 {:#018x}  r14 {:#018x}  r15 {:#018x}", tf.r13, tf.r14, tf.r15);
    let _ = writeln!(w, "  cr2 {:#018x}  cr3 {:#018x}", cpu::read_cr2(), cpu::read_cr3());
}

fn task_line(w: &mut Raw) {
    let tid = crate::sched::current_tid();
    let _ = writeln!(w, "  task: tid {tid}");
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    let mut w = begin();
    let _ = writeln!(w, "\n*** KERNEL PANIC: {}", info.message());
    if let Some(l) = info.location() {
        let _ = writeln!(w, "  at {}:{}:{}", l.file(), l.line(), l.column());
    }
    task_line(&mut w);
    finish(w)
}

pub fn exception(tf: &TrapFrame, name: &str) -> ! {
    let mut w = begin();
    let mode = if tf.from_user() { "user" } else { "kernel" };
    let _ = writeln!(w, "\n*** KERNEL PANIC: unhandled {name} in {mode} mode");
    if tf.vector == 14 {
        let e = tf.error;
        let _ = writeln!(
            w,
            "  page fault at {:#x}: {} {} {}{}",
            cpu::read_cr2(),
            if e & 1 != 0 { "protection-violation" } else { "not-present" },
            if e & 2 != 0 { "write" } else { "read" },
            if e & 4 != 0 { "user" } else { "supervisor" },
            if e & 16 != 0 { " instruction-fetch" } else { "" }
        );
    }
    task_line(&mut w);
    dump_frame(&mut w, tf);
    finish(w)
}

pub fn stack_overflow(tf: &TrapFrame, addr: usize) -> ! {
    let mut w = begin();
    let _ = writeln!(w, "\n*** KERNEL PANIC: kernel stack overflow (guard page {addr:#x} hit)");
    task_line(&mut w);
    dump_frame(&mut w, tf);
    finish(w)
}

pub fn guard_hit(tf: &TrapFrame, addr: usize, owner: usize) -> ! {
    let mut w = begin();
    let _ = writeln!(w, "\n*** KERNEL PANIC: out-of-bounds access at {addr:#x}: guard page of vmalloc block {owner:#x}");
    task_line(&mut w);
    dump_frame(&mut w, tf);
    finish(w)
}

pub fn lock_recursion(at: &'static Location<'static>, owner: *mut Location<'static>) -> ! {
    let mut w = begin();
    let _ = writeln!(w, "\n*** KERNEL PANIC: spinlock deadlock: re-acquired at {}:{}", at.file(), at.line());
    if !owner.is_null() {
        let o = unsafe { &*owner };
        let _ = writeln!(w, "  held since {}:{}", o.file(), o.line());
    }
    task_line(&mut w);
    finish(w)
}
