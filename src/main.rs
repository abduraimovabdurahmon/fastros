//! FastROS — Kernel Entry Point
//!
//! This file only orchestrates the boot sequence.
//! Each subsystem initializes itself in order.
//! No subsystem logic lives here.

#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

use core::panic::PanicInfo;

mod arch;
mod drivers;
mod fs;
mod hal;
mod kernel;
mod libs;

/// Called from arch/x86_64/boot.s after entering 64-bit long mode.
///
/// Boot sequence order is intentional — each layer depends on the one below it.
#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    // 1. Architecture-specific early init (GDT, IDT)
    arch::init();

    // 2. Display — needed for all subsequent debug output
    drivers::display::vga::init();
    drivers::display::vga::print(b"FastROS v0.1.0", 0x0a); // green

    // 3. Physical memory manager
    kernel::memory::pmm::init();

    // 4. Virtual memory / paging
    kernel::memory::vmm::init();

    // 5. Kernel heap
    kernel::memory::heap::init();

    // 6. Interrupts + timer
    kernel::sync::init();

    // 7. Drivers
    drivers::init();

    // 8. File systems
    fs::init();

    // 9. Process manager + scheduler
    kernel::process::init();

    // 10. Hand off to init process (userspace PID 1)
    // kernel::process::spawn_init();

    loop {}
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // TODO: print panic info via serial/VGA
    let _ = info;
    loop {}
}
