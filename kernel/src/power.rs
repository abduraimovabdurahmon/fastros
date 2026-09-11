//! Power control: ACPI S5 (QEMU i440FX/PIIX4 and q35) with a keyboard-
//! controller reset as the reboot path.

use crate::arch::{cpu, port};

pub fn poweroff() -> ! {
    crate::kinfo!("power", "powering off");
    unsafe {
        // PIIX4 PM1a control (QEMU -machine pc): SLP_TYPa=0, SLP_EN.
        port::outw(0x604, 0x2000);
        // ICH9 (QEMU -machine q35).
        port::outw(0xB004, 0x2000);
        // Bochs/older QEMU.
        port::outw(0x4004, 0x3400);
    }
    cpu::halt_forever();
}

pub fn reboot() -> ! {
    crate::kinfo!("power", "rebooting");
    unsafe {
        // Pulse the CPU reset line through the 8042 keyboard controller.
        for _ in 0..0x10000 {
            if port::inb(0x64) & 0x02 == 0 {
                break;
            }
        }
        port::outb(0x64, 0xFE);
        // PCI reset control register as a fallback.
        port::outb(0xCF9, 0x06);
    }
    cpu::halt_forever();
}
