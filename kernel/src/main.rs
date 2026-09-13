//! FastROS kernel.
//!
//! Boot order (each step depends only on the ones before it):
//!
//! 1. serial console, CPU features, GDT/TSS, IDT        (`arch::early_init`)
//! 2. boot information from the loader                   (`boot::parse_pvh`)
//! 3. frames → final page tables → heap                  (`mm::init`)
//! 4. CPU protections (SMEP/SMAP/UMIP/WP), clocks, IRQs
//! 5. scheduler: the boot context becomes the idle task
//! 6. `init` task: drivers, filesystems, network, services  (`init::main`)

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(static_mut_refs)]

extern crate alloc;

#[macro_use]
mod log;

mod arch;
mod boot;
mod console;
mod crypto;
mod device;
mod drivers;
mod errno;
mod fastman;
mod firewall;
mod fs;
mod cgroup;
mod init;
mod ipc;
mod mm;
mod net;
mod panic;
mod power;
mod proc;
mod sched;
pub mod syscall;
mod shell;
mod smp;
mod ftpd;
mod ssh;
mod sync;
mod sysfs;
mod time;
mod trap;
mod tty;
mod uaccess;
mod usermode;
mod users;
mod utmp;

use arch::cpu;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// `uname -v` / `/proc/version` text.
pub fn version_string() -> alloc::string::String {
    let built: i64 = env!("FASTROS_BUILD_UNIX").parse().unwrap_or(0);
    alloc::format!(
        "FastROS version {} (root@fastros) (rustc nightly, rust-lld) #1 SMP PREEMPT_DYNAMIC {}",
        VERSION,
        shell::cmds::fmtutil::date_string(built)
    )
}

#[no_mangle]
pub extern "C" fn kernel_main(start_info_phys: u32) -> ! {
    drivers::serial::init();
    arch::early_init();
    let boot = boot::parse_pvh(start_info_phys as u64);
    kinfo!("boot", "FastROS {VERSION} starting; cmdline: '{}'", boot.cmdline());
    for r in boot.regions() {
        kinfo!("boot", "  mem {:#012x}-{:#012x} {:?}", r.start, r.end, r.kind);
    }

    mm::init(boot);
    log::heap_ready();
    let prot = cpu::enable_protections();
    cpu::enable_user_fpu();
    kinfo!(
        "cpu",
        "{}; protections: NX={} SMEP={} SMAP={} UMIP={}",
        cpu::model_name(),
        prot & cpu::feature::NX != 0,
        prot & cpu::feature::SMEP != 0,
        prot & cpu::feature::SMAP != 0,
        prot & cpu::feature::UMIP != 0
    );
    let ms = mm::stats();
    kinfo!("mm", "{} MiB usable, {} MiB free", ms.total_bytes >> 20, ms.free_bytes >> 20);

    time::init();
    kinfo!("time", "TSC {} MHz, wall clock {}", time::tsc_hz() / 1_000_000, time::unix_now());
    sched::init();
    trap::register_irq(0, timer_irq);
    arch::init_interrupts(time::HZ);
    // Discover the CPU topology (ACPI MADT) before enabling the LAPIC, so the
    // real LAPIC address and the AP list are available to both steps below.
    smp::init();
    // Prefer the local-APIC timer for the scheduler tick (per-CPU, the basis for
    // SMP preemption). If it comes up, retire the PIT tick so we don't double.
    if arch::apic::init_bsp(time::HZ) {
        arch::pic::mask(0);
        kinfo!("apic", "LAPIC timer @ {} Hz drives the scheduler tick (PIC kept for legacy IRQs)", time::HZ);
        // Bring the application processors into long mode and park them. This
        // uses the PIT busy-wait (no IRQs needed) and must run before we unmask
        // interrupts, while low memory is still identity-mappable.
        smp::bringup();
    } else {
        kinfo!("apic", "no local APIC timer; using the PIT tick");
    }
    cpu::irq_enable();

    sched::spawn("init", init::main);
    sched::idle_loop();
}

fn timer_irq() {
    time::tick();
    sched::timer_tick();
}
