//! CPUID instruction wrapper
//!
//! Used to query CPU features (SSE, AVX, long mode, etc.)

pub struct CpuidResult {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

/// Execute CPUID with the given leaf.
pub fn cpuid(leaf: u32) -> CpuidResult {
    let (eax, ebx, ecx, edx): (u32, u32, u32, u32);
    unsafe {
        core::arch::asm!(
            "cpuid",
            inout("eax") leaf => eax,
            out("ebx") ebx,
            out("ecx") ecx,
            out("edx") edx,
        );
    }
    CpuidResult { eax, ebx, ecx, edx }
}

/// Returns the 12-byte vendor string (e.g. "GenuineIntel").
pub fn vendor_string() -> [u8; 12] {
    let result = cpuid(0);
    let mut vendor = [0u8; 12];
    vendor[0..4].copy_from_slice(&result.ebx.to_le_bytes());
    vendor[4..8].copy_from_slice(&result.edx.to_le_bytes());
    vendor[8..12].copy_from_slice(&result.ecx.to_le_bytes());
    vendor
}
