//! Power control.
//!
//! * [`shutdown`]: the orderly path — SIGTERM every process, give them a
//!   grace period, SIGKILL the rest, flush every filesystem, then power off
//!   or reset. `poweroff`/`reboot` and the ACPI power button all use it.
//! * ACPI power button: PIIX4/ICH9 fixed-feature event (PM1 PWRBTN) on the
//!   SCI line, so `docker stop` (QEMU `system_powerdown`) shuts down cleanly.
//! * [`poweroff`]/[`reboot`]: the final hardware step (ACPI S5 / reset).

use crate::arch::{cpu, pic, port};
use crate::sync::WaitQueue;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Action {
    PowerOff = 1,
    Reboot = 2,
    Halt = 3,
}

impl Action {
    fn from_u8(v: u8) -> Option<Action> {
        match v {
            1 => Some(Action::PowerOff),
            2 => Some(Action::Reboot),
            3 => Some(Action::Halt),
            _ => None,
        }
    }
    fn verb(self) -> &'static str {
        match self {
            Action::PowerOff => "power-off",
            Action::Reboot => "reboot",
            Action::Halt => "halt",
        }
    }
}

/// Grace period between SIGTERM and SIGKILL.
const GRACE_MS: u64 = 3000;

static REQUESTED: AtomicU8 = AtomicU8::new(0);
static REQUEST_WQ: WaitQueue = WaitQueue::new();
static STARTED: AtomicBool = AtomicBool::new(false);

/// Ask the power daemon to shut the system down. Returns immediately; the
/// first request wins. Safe from interrupt context.
pub fn request(action: Action) {
    if REQUESTED.compare_exchange(0, action as u8, Ordering::AcqRel, Ordering::Acquire).is_ok() {
        REQUEST_WQ.wake_all();
    }
}

pub fn shutdown_in_progress() -> bool {
    REQUESTED.load(Ordering::Acquire) != 0
}

/// Generation of the pending `shutdown +N` (0 = none); bumping it cancels.
static SCHEDULED: AtomicU64 = AtomicU64::new(0);
static SCHED_GEN: AtomicU64 = AtomicU64::new(0);

/// Request `action` after `delay_secs` unless [`cancel_scheduled`] runs
/// first. A newer schedule replaces an older one.
pub fn schedule(action: Action, delay_secs: u64) {
    let gen = SCHED_GEN.fetch_add(1, Ordering::AcqRel) + 1;
    SCHEDULED.store(gen, Ordering::Release);
    crate::sched::spawn("shutdown-timer", move || {
        let deadline = crate::time::now_ns() + delay_secs * 1_000_000_000;
        while crate::time::now_ns() < deadline {
            if SCHEDULED.load(Ordering::Acquire) != gen {
                return;
            }
            crate::sched::sleep_ms(500);
        }
        if SCHEDULED.compare_exchange(gen, 0, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            request(action);
        }
    });
}

/// Cancel a pending scheduled shutdown; false if none was pending.
pub fn cancel_scheduled() -> bool {
    SCHEDULED.swap(0, Ordering::AcqRel) != 0
}

/// Start the power daemon (a kernel thread, so it survives the SIGKILL
/// round it performs) and arm the ACPI power button.
pub fn init() {
    crate::sched::spawn("powerd", || {
        let action = REQUEST_WQ.wait_until(|| Action::from_u8(REQUESTED.load(Ordering::Acquire)));
        shutdown(action);
    });
    acpi_init();
}

fn shutdown(action: Action) -> ! {
    if STARTED.swap(true, Ordering::AcqRel) {
        cpu::halt_forever();
    }
    crate::knotice!("power", "the system is going down for {} now", action.verb());
    crate::utmp::shutdown();
    let live = || crate::proc::all().into_iter().filter(|p| p.pid != 0 && !p.is_zombie()).count();
    for p in crate::proc::all() {
        if p.pid != 0 {
            p.signal(crate::proc::signal::SIGTERM);
        }
    }
    let deadline = crate::time::now_ns() + GRACE_MS * 1_000_000;
    while live() > 0 && crate::time::now_ns() < deadline {
        crate::sched::sleep_ms(50);
    }
    let left = live();
    if left > 0 {
        crate::kwarn!("power", "{left} process(es) ignored SIGTERM; sending SIGKILL");
        for p in crate::proc::all() {
            if p.pid != 0 {
                p.signal(crate::proc::signal::SIGKILL);
            }
        }
        crate::sched::sleep_ms(200);
    }
    crate::fs::bcache::sync_all();
    crate::kinfo!("power", "filesystems synced");
    match action {
        Action::PowerOff => poweroff(),
        Action::Reboot => reboot(),
        Action::Halt => {
            crate::kinfo!("power", "system halted");
            cpu::halt_forever()
        }
    }
}

// ── ACPI fixed events ──────────────────────────────────────────────────────

/// PM1 event block base (PM1_STS at +0, PM1_EN at +2, PM1_CNT at +4).
static PM_BASE: AtomicU16 = AtomicU16::new(0);
const PM1_STS: u16 = 0;
const PM1_EN: u16 = 2;
const PM1_CNT: u16 = 4;
const PWRBTN: u16 = 1 << 8;
const SCI_EN: u16 = 1;
/// APM/ACPI command port and the "enable ACPI" command (FADT values on
/// PIIX4 and ICH9 alike).
const SMI_CMD: u16 = 0xB2;
const ACPI_ENABLE: u8 = 0xF1;
const SCI_IRQ: u8 = 9;

fn acpi_init() {
    // PIIX4 PM function (8086:7113) keeps its I/O base at config 0x40;
    // the ICH9 LPC bridge (8086:2918) at config 0x40 as well.
    let pm = crate::drivers::pci::find(0x8086, 0x7113).or_else(|| crate::drivers::pci::find(0x8086, 0x2918));
    let Some(dev) = pm else {
        crate::kinfo!("acpi", "no PIIX4/ICH9 power management: power button disabled");
        return;
    };
    let base = (dev.addr.read32(0x40) & 0xFFC0) as u16;
    if base == 0 {
        crate::kinfo!("acpi", "PM I/O space not configured: power button disabled");
        return;
    }
    PM_BASE.store(base, Ordering::Release);
    unsafe {
        if port::inw(base + PM1_CNT) & SCI_EN == 0 {
            port::outb(SMI_CMD, ACPI_ENABLE);
            for _ in 0..1000 {
                if port::inw(base + PM1_CNT) & SCI_EN != 0 {
                    break;
                }
                core::hint::spin_loop();
            }
        }
        // Clear a stale press, then enable the button event.
        port::outw(base + PM1_STS, PWRBTN);
        let en = port::inw(base + PM1_EN);
        port::outw(base + PM1_EN, en | PWRBTN);
    }
    crate::trap::register_irq(SCI_IRQ, sci_irq);
    pic::unmask(2); // cascade to the slave PIC
    crate::kinfo!("acpi", "power button armed (PM base {base:#x}, SCI irq {SCI_IRQ})");
}

fn sci_irq() {
    let base = PM_BASE.load(Ordering::Acquire);
    if base == 0 {
        return;
    }
    let sts = unsafe { port::inw(base + PM1_STS) };
    if sts & PWRBTN != 0 {
        // Write-one-to-clear, so the level-triggered SCI line drops.
        unsafe { port::outw(base + PM1_STS, PWRBTN) };
        request(Action::PowerOff);
    }
}

// ── the final hardware step ────────────────────────────────────────────────

pub fn poweroff() -> ! {
    crate::kinfo!("power", "powering off");
    unsafe {
        let base = PM_BASE.load(Ordering::Acquire);
        if base != 0 {
            // SLP_TYP for S5 is 0 on QEMU's DSDT; SLP_EN = bit 13.
            port::outw(base + PM1_CNT, 0x2000);
        }
        // Fallbacks: PIIX4 at the SeaBIOS default, QEMU legacy, Bochs.
        port::outw(0xB004, 0x2000);
        port::outw(0x604, 0x2000);
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
