//! FastROS — Kernel Entry Point
//!
//! This file only orchestrates the boot sequence.
//! Each subsystem initializes itself in order.
//! No subsystem logic lives here.

#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]
#![feature(generic_const_exprs)]

use core::panic::PanicInfo;

mod arch;
mod container;
mod drivers;
mod fs;
mod hal;
mod kernel;
mod libs;
mod orchestrator;

/// Called from arch/x86_64/boot.s after entering 64-bit long mode.
///
/// Boot sequence order is intentional — each layer depends on the one below it.
#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    // 1. Architecture-specific early init (GDT, IDT)
    arch::init();

    // 2. Serial port — early debug output visible in QEMU -serial stdio
    drivers::char::serial::init();
    drivers::char::serial::write(b"\n");
    drivers::char::serial::write(b"========================================\n");
    drivers::char::serial::write(b"  FastROS v0.1.0 - kernel is running!\n");
    drivers::char::serial::write(b"  arch: x86_64  mode: long mode (64-bit)\n");
    drivers::char::serial::write(b"========================================\n");
    drivers::char::serial::write(b"\n");

    // 3. VGA display
    drivers::display::vga::init();
    drivers::display::vga::print(b"FastROS v0.1.0", 0x0a); // green

    // 4. Physical memory manager
    kernel::memory::pmm::init();

    // 5. Virtual memory / paging
    kernel::memory::vmm::init();

    // 6. Kernel heap
    kernel::memory::heap::init();

    // 7. Interrupts + timer
    kernel::sync::init();

    // 8. Drivers
    drivers::init();

    // 9. File systems (VFS + overlayfs for containers)
    fs::init();

    // 10. Process manager + scheduler
    kernel::process::init();

    // 11. Container runtime (image store, lifecycle manager)
    container::init();

    // 12. Orchestration layer (node agent, service discovery, network mesh)
    orchestrator::init();

    // 13. Hand off to init process (userspace PID 1)
    // kernel::process::spawn_init();

    loop {}
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // TODO: print panic info via serial/VGA
    let _ = info;
    loop {}
}
