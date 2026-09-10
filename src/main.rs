//! FastROS — Kernel Entry Point
//!
//! Boot sequence: each subsystem initializes in dependency order.
//! No subsystem logic lives here — only orchestration.

#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]
#![feature(generic_const_exprs)]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::panic::PanicInfo;

mod arch;
mod container;
mod drivers;
mod fs;
mod hal;
mod kernel;
mod libs;
mod orchestrator;
mod shell;

/// Called from arch/x86_64/boot.s after entering 64-bit long mode.
#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    // ── Layer 0: Architecture ──────────────────────────────────────────────
    // GDT + TSS, IDT + PIC (interrupts enabled), SYSCALL MSRs, PIT timer
    arch::init();

    // ── Layer 3 (early): Serial + VGA ─────────────────────────────────────
    drivers::char::serial::init();
    drivers::char::serial::write(b"\n");
    drivers::char::serial::write(b"=====================================\n");
    drivers::char::serial::write(b"  FastROS v0.1.0  [64-bit long mode]\n");
    drivers::char::serial::write(b"=====================================\n");

    // VGA text mode: draws boot banner visible in QEMU display window
    drivers::display::vga::init();

    // ── Layer 2: Physical memory manager ──────────────────────────────────
    kernel::memory::pmm::init();

    // ── Layer 2: Virtual memory manager ───────────────────────────────────
    kernel::memory::vmm::init();

    // Hook the page-fault handler so demand paging works
    arch::set_page_fault_hook(kernel::memory::vmm::handle_page_fault);

    // ── Layer 2: Kernel heap (bump allocator — enables Box/Vec) ───────────
    kernel::memory::heap::init();

    // ── Layer 2: Sync primitives (already usable via SpinLock::new) ───────
    kernel::sync::init();

    // ── Layer 3: Remaining drivers ────────────────────────────────────────
    drivers::init();

    // ── Layer 3: PCI enumeration (required before network driver probe) ───
    drivers::bus::pci::init();

    // Wire PS/2 keyboard IRQ → keyboard driver (arch↔drivers boundary lives here)
    arch::set_keyboard_hook(drivers::char::keyboard::on_irq);
    arch::unmask_irq(1); // enable IRQ 1 (PS/2 keyboard)

    // ── Layer 4: File systems ──────────────────────────────────────────────
    fs::init();

    // ── Layer 2: User/group management ────────────────────────────────────
    kernel::users::init();

    // ── Layer 2: Process manager + scheduler ──────────────────────────────
    kernel::process::init();

    // Connect the timer IRQ to the scheduler tick
    arch::set_timer_hook(kernel::process::scheduler::tick);

    // ── Layer 3: Network drivers (after PCI, uses kernel::net callbacks) ──
    kernel::net::init();
    drivers::net::init();

    // ── Layer 5: SSH server (after network stack is up) ────────────────────
    kernel::net::ssh::init();

    // ── Layer 6: Container runtime ─────────────────────────────────────────
    container::init();

    // ── Layer 7: Orchestration layer ───────────────────────────────────────
    orchestrator::init();

    drivers::char::serial::write(b"  Boot complete. Starting shell.\n");

    // Launch the interactive shell — never returns
    shell::run();
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Write panic message to serial
    drivers::char::serial::write(b"KERNEL PANIC: ");
    if let Some(loc) = info.location() {
        // Write file name bytes
        drivers::char::serial::write(loc.file().as_bytes());
    }
    drivers::char::serial::write(b"\n");
    loop {
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack, noreturn)); }
    }
}

#[alloc_error_handler]
fn alloc_error(_layout: core::alloc::Layout) -> ! {
    drivers::char::serial::write(b"KERNEL PANIC: out of memory\n");
    loop {
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack, noreturn)); }
    }
}
