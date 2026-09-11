//! CPU identification, control registers, MSRs and interrupt-flag control.

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

pub const MSR_EFER: u32 = 0xC000_0080;
pub const MSR_STAR: u32 = 0xC000_0081;
pub const MSR_LSTAR: u32 = 0xC000_0082;
pub const MSR_SFMASK: u32 = 0xC000_0084;
pub const MSR_FS_BASE: u32 = 0xC000_0100;
pub const MSR_GS_BASE: u32 = 0xC000_0101;
pub const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;

pub const EFER_SCE: u64 = 1 << 0;
pub const EFER_NXE: u64 = 1 << 11;

pub const CR0_WP: u64 = 1 << 16;
pub const CR0_EM: u64 = 1 << 2;
pub const CR0_MP: u64 = 1 << 1;
pub const CR0_TS: u64 = 1 << 3;
pub const CR4_OSFXSR: u64 = 1 << 9;
pub const CR4_OSXMMEXCPT: u64 = 1 << 10;
pub const CR4_UMIP: u64 = 1 << 11;
pub const CR4_FSGSBASE: u64 = 1 << 16;
pub const CR4_OSXSAVE: u64 = 1 << 18;
pub const CR4_SMEP: u64 = 1 << 20;
pub const CR4_SMAP: u64 = 1 << 21;

pub const RFLAGS_IF: u64 = 1 << 9;
pub const RFLAGS_AC: u64 = 1 << 18;

#[derive(Clone, Copy)]
pub struct CpuidResult {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

pub fn cpuid(leaf: u32, sub: u32) -> CpuidResult {
    let r = unsafe { core::arch::x86_64::__cpuid_count(leaf, sub) };
    CpuidResult { eax: r.eax, ebx: r.ebx, ecx: r.ecx, edx: r.edx }
}

#[inline]
pub unsafe fn rdmsr(msr: u32) -> u64 {
    unsafe {
        let (lo, hi): (u32, u32);
        asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags));
        ((hi as u64) << 32) | lo as u64
    }
}
#[inline]
pub unsafe fn wrmsr(msr: u32, v: u64) {
    unsafe {
        asm!("wrmsr", in("ecx") msr, in("eax") v as u32, in("edx") (v >> 32) as u32,
             options(nomem, nostack, preserves_flags));
    }
}

macro_rules! creg {
    ($read:ident, $write:ident, $reg:literal) => {
        #[inline]
        pub fn $read() -> u64 {
            let v: u64;
            unsafe { asm!(concat!("mov {}, ", $reg), out(reg) v, options(nomem, nostack, preserves_flags)) };
            v
        }
        #[inline]
        pub unsafe fn $write(v: u64) {
            unsafe {
                asm!(concat!("mov ", $reg, ", {}"), in(reg) v, options(nostack, preserves_flags));
            }
        }
    };
}
creg!(read_cr0, write_cr0, "cr0");
creg!(read_cr2, write_cr2, "cr2");
creg!(read_cr3, write_cr3, "cr3");
creg!(read_cr4, write_cr4, "cr4");

#[inline]
pub fn rdtsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

#[inline]
pub fn invlpg(addr: usize) {
    unsafe { asm!("invlpg [{}]", in(reg) addr, options(nostack, preserves_flags)) };
}

/// Flush the whole TLB (non-global entries) by reloading CR3.
pub fn flush_tlb() {
    unsafe { write_cr3(read_cr3()) };
}

// ── Interrupt flag ─────────────────────────────────────────────────────────

#[inline]
pub fn rflags() -> u64 {
    let r: u64;
    unsafe { asm!("pushfq; pop {}", out(reg) r, options(nomem, preserves_flags)) };
    r
}
#[inline]
pub fn irqs_enabled() -> bool {
    rflags() & RFLAGS_IF != 0
}
// `cli`/`sti` must be compiler barriers (no `nomem`): otherwise the compiler
// may move a spinlock's acquire above the `cli` or its release below the
// `sti`, opening a window where an IRQ handler finds the lock held.
#[inline]
pub fn irq_disable() {
    unsafe { asm!("cli", options(nostack)) };
}
#[inline]
pub fn irq_enable() {
    unsafe { asm!("sti", options(nostack)) };
}
/// Disable interrupts, returning whether they were enabled.
#[inline]
pub fn irq_save() -> bool {
    let was = irqs_enabled();
    irq_disable();
    was
}
#[inline]
pub fn irq_restore(was_enabled: bool) {
    if was_enabled {
        irq_enable();
    }
}
/// Atomically enable interrupts and halt until the next one (`sti; hlt`:
/// the interrupt shadow of `sti` guarantees no IRQ is lost in between).
#[inline]
pub fn enable_and_halt() {
    unsafe { asm!("sti; hlt", options(nostack)) };
}
pub fn halt_forever() -> ! {
    loop {
        unsafe { asm!("cli; hlt", options(nomem, nostack)) };
    }
}

// ── Feature detection ──────────────────────────────────────────────────────

pub mod feature {
    pub const NX: u64 = 1 << 0;
    pub const SMEP: u64 = 1 << 1;
    pub const SMAP: u64 = 1 << 2;
    pub const UMIP: u64 = 1 << 3;
    pub const RDRAND: u64 = 1 << 4;
    pub const RDSEED: u64 = 1 << 5;
    pub const PGE: u64 = 1 << 6;
    pub const FSGSBASE: u64 = 1 << 7;
    pub const INVARIANT_TSC: u64 = 1 << 8;
    pub const PDPE1GB: u64 = 1 << 9;
    pub const XSAVE: u64 = 1 << 10;
    pub const FXSR: u64 = 1 << 11;
    pub const SSE2: u64 = 1 << 12;
    pub const X2APIC: u64 = 1 << 13;
}

static FEATURES: AtomicU64 = AtomicU64::new(0);
static VENDOR_MODEL: spin_cell::Cell = spin_cell::Cell::new();

mod spin_cell {
    use core::cell::UnsafeCell;
    /// Write-once-at-boot text storage (vendor + brand string).
    pub struct Cell(UnsafeCell<[u8; 64]>, UnsafeCell<usize>);
    unsafe impl Sync for Cell {}
    impl Cell {
        pub const fn new() -> Self {
            Self(UnsafeCell::new([0; 64]), UnsafeCell::new(0))
        }
        /// # Safety: called once during single-threaded early boot.
        pub unsafe fn set(&self, s: &[u8]) {
            unsafe {
                let n = s.len().min(64);
                (&mut *self.0.get())[..n].copy_from_slice(&s[..n]);
                *self.1.get() = n;
            }
        }
        pub fn get(&self) -> &str {
            unsafe { core::str::from_utf8(&(&*self.0.get())[..*self.1.get()]).unwrap_or("?") }
        }
    }
}

pub fn has(f: u64) -> bool {
    FEATURES.load(Ordering::Relaxed) & f != 0
}

pub fn model_name() -> &'static str {
    VENDOR_MODEL.get()
}

pub fn detect() {
    let mut f = 0u64;
    let l1 = cpuid(1, 0);
    if l1.ecx & (1 << 30) != 0 {
        f |= feature::RDRAND;
    }
    if l1.ecx & (1 << 26) != 0 {
        f |= feature::XSAVE;
    }
    if l1.ecx & (1 << 21) != 0 {
        f |= feature::X2APIC;
    }
    if l1.edx & (1 << 13) != 0 {
        f |= feature::PGE;
    }
    if l1.edx & (1 << 24) != 0 {
        f |= feature::FXSR;
    }
    if l1.edx & (1 << 26) != 0 {
        f |= feature::SSE2;
    }
    let max = cpuid(0, 0).eax;
    if max >= 7 {
        let l7 = cpuid(7, 0);
        if l7.ebx & (1 << 7) != 0 {
            f |= feature::SMEP;
        }
        if l7.ebx & (1 << 20) != 0 {
            f |= feature::SMAP;
        }
        if l7.ebx & (1 << 18) != 0 {
            f |= feature::RDSEED;
        }
        if l7.ebx & (1 << 0) != 0 {
            f |= feature::FSGSBASE;
        }
        if l7.ecx & (1 << 2) != 0 {
            f |= feature::UMIP;
        }
    }
    let ext_max = cpuid(0x8000_0000, 0).eax;
    if ext_max >= 0x8000_0001 {
        let e1 = cpuid(0x8000_0001, 0);
        if e1.edx & (1 << 20) != 0 {
            f |= feature::NX;
        }
        if e1.edx & (1 << 26) != 0 {
            f |= feature::PDPE1GB;
        }
    }
    if ext_max >= 0x8000_0007 && cpuid(0x8000_0007, 0).edx & (1 << 8) != 0 {
        f |= feature::INVARIANT_TSC;
    }
    FEATURES.store(f, Ordering::Relaxed);

    let mut name = [0u8; 64];
    let mut n = 0;
    if ext_max >= 0x8000_0004 {
        for leaf in 0x8000_0002..=0x8000_0004u32 {
            let r = cpuid(leaf, 0);
            for w in [r.eax, r.ebx, r.ecx, r.edx] {
                for b in w.to_le_bytes() {
                    if n < 48 {
                        name[n] = b;
                        n += 1;
                    }
                }
            }
        }
    }
    let trimmed = trim(&name[..n]);
    unsafe { VENDOR_MODEL.set(trimmed) };
}

fn trim(s: &[u8]) -> &[u8] {
    let s = &s[..s.iter().position(|&b| b == 0).unwrap_or(s.len())];
    let start = s.iter().position(|&b| b != b' ').unwrap_or(s.len());
    let end = s.iter().rposition(|&b| b != b' ').map_or(start, |e| e + 1);
    &s[start..end]
}

/// Turn on the CPU's own protections: write-protect in ring 0, no execution
/// of user pages from the kernel (SMEP), no kernel access to user pages
/// outside explicit `stac`/`clac` windows (SMAP), no `sgdt`/`sidt`/... in
/// user mode (UMIP). Returns a bitmask of the enabled `feature` flags.
pub fn enable_protections() -> u64 {
    let mut on = 0;
    unsafe {
        write_cr0(read_cr0() | CR0_WP);
        let mut cr4 = read_cr4();
        if has(feature::SMEP) {
            cr4 |= CR4_SMEP;
            on |= feature::SMEP;
        }
        if has(feature::SMAP) {
            cr4 |= CR4_SMAP;
            on |= feature::SMAP;
        }
        if has(feature::UMIP) {
            cr4 |= CR4_UMIP;
            on |= feature::UMIP;
        }
        write_cr4(cr4);
    }
    if has(feature::NX) {
        on |= feature::NX;
    }
    on
}

/// Allow SSE/x87 (and AVX where present) use by user programs. glibc/musl
/// select AVX `memcpy`/`strlen` on a capable CPU, so without XSAVE + XCR0 the
/// first `vmov*` would #UD. The kernel itself stays soft-float.
pub fn enable_user_fpu() {
    unsafe {
        let cr0 = (read_cr0() & !(CR0_EM | CR0_TS)) | CR0_MP;
        write_cr0(cr0);
        let mut cr4 = read_cr4() | CR4_OSFXSR | CR4_OSXMMEXCPT;
        if has(feature::XSAVE) {
            cr4 |= CR4_OSXSAVE;
        }
        write_cr4(cr4);
        asm!("fninit", options(nomem, nostack));
        if has(feature::XSAVE) {
            // XCR0: enable x87 (bit 0) + SSE (bit 1), and AVX (bit 2) if the
            // CPU advertises it in CPUID.1:ECX.28.
            let mut xcr0 = 0b11u64;
            if cpuid(1, 0).ecx & (1 << 28) != 0 {
                xcr0 |= 0b100;
            }
            asm!("xsetbv", in("ecx") 0u32, in("eax") xcr0 as u32, in("edx") (xcr0 >> 32) as u32, options(nomem, nostack));
        }
    }
}

/// Hardware random number from RDSEED (preferred) or RDRAND.
pub fn hw_random() -> Option<u64> {
    for _ in 0..32 {
        let mut v: u64 = 0;
        let ok: u8;
        unsafe {
            if has(feature::RDSEED) {
                asm!("rdseed {v}", "setc {ok}", v = inout(reg) v, ok = out(reg_byte) ok, options(nomem, nostack));
            } else if has(feature::RDRAND) {
                asm!("rdrand {v}", "setc {ok}", v = inout(reg) v, ok = out(reg_byte) ok, options(nomem, nostack));
            } else {
                return None;
            }
        }
        if ok != 0 {
            return Some(v);
        }
        core::hint::spin_loop();
    }
    None
}

/// Guard that re-enables interrupts (if they were on) when dropped.
pub struct IrqGuard(bool);
impl IrqGuard {
    #[inline]
    pub fn new() -> Self {
        Self(irq_save())
    }
}
impl Drop for IrqGuard {
    #[inline]
    fn drop(&mut self) {
        // Deferred while a spinlock is still held (see `sync::restore_irqs`).
        crate::sync::restore_irqs(self.0)
    }
}

/// Temporarily permit supervisor access to user pages (SMAP window).
#[inline]
pub fn stac() {
    if has(feature::SMAP) {
        unsafe { asm!("stac", options(nomem, nostack)) };
    }
}
#[inline]
pub fn clac() {
    if has(feature::SMAP) {
        unsafe { asm!("clac", options(nomem, nostack)) };
    }
}
