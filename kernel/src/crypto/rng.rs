//! Cryptographically secure random numbers.
//!
//! Design (after Linux's `crng`, with fast key erasure):
//! * an entropy pool (SHA-256 state) absorbs hardware randomness (RDSEED /
//!   RDRAND), TSC jitter measured at boot, and interrupt timings;
//! * output comes from ChaCha20 keyed by a 256-bit key; after every request
//!   the next 32 keystream bytes replace the key, so a later compromise of the
//!   state reveals nothing about earlier output;
//! * the key is re-derived from the pool every 60 s or 1 MiB of output.
//!
//! There is no "blocking pool": once seeded at boot the generator never
//! blocks (the same stance as modern Linux `getrandom`).

use crate::sync::SpinLock;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use sha2::{Digest, Sha256};
use core::sync::atomic::{AtomicU64, Ordering};

const RESEED_NS: u64 = 60_000_000_000;
const RESEED_BYTES: u64 = 1 << 20;

struct Crng {
    key: [u8; 32],
    pool: Sha256,
    generated: u64,
    last_reseed_ns: u64,
    pool_bits: u64,
}

static CRNG: SpinLock<Option<Crng>> = SpinLock::new(None);
/// Cheap interrupt-time accumulator folded into the pool on reseed.
static IRQ_MIX: AtomicU64 = AtomicU64::new(0x6A09_E667_F3BC_C908);

/// Seed the generator. Call once, early (before any consumer).
pub fn init() {
    let mut pool = Sha256::new();
    let mut bits = 0u64;
    for _ in 0..16 {
        if let Some(v) = crate::arch::cpu::hw_random() {
            pool.update(v.to_le_bytes());
            bits += 64;
        }
    }
    // TSC jitter: the low bits of the time a fixed loop takes vary with
    // cache/TLB state and (under emulation) host scheduling.
    let mut prev = crate::arch::cpu::rdtsc();
    for i in 0..4096u64 {
        let mut x = i;
        for _ in 0..(i % 13) {
            x = x.wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(7);
        }
        let now = crate::arch::cpu::rdtsc();
        pool.update((now.wrapping_sub(prev) ^ x).to_le_bytes());
        prev = now;
    }
    bits += 4096 / 8; // conservative: 1/8 bit per sample
    pool.update(crate::time::wall_clock().0.to_le_bytes());
    let key: [u8; 32] = pool.clone().finalize().into();
    pool.update(b"fastros-crng-pool");
    *CRNG.lock() = Some(Crng { key, pool, generated: 0, last_reseed_ns: crate::time::now_ns(), pool_bits: bits });
    crate::kinfo!("random", "crng seeded (~{} bits, hw={})", bits.min(256), crate::arch::cpu::hw_random().is_some());
}

/// Fold an interrupt timestamp into the entropy accumulator (IRQ-safe, lock-free).
#[inline]
pub fn add_interrupt_entropy() {
    let t = crate::arch::cpu::rdtsc();
    let cur = IRQ_MIX.load(Ordering::Relaxed);
    IRQ_MIX.store(cur.rotate_left(13) ^ t.wrapping_mul(0x9E37_79B9_7F4A_7C15), Ordering::Relaxed);
}

/// Mix caller-provided data (device addresses, packet timings...) into the pool.
pub fn add_entropy(data: &[u8]) {
    if let Some(c) = CRNG.lock().as_mut() {
        c.pool.update(data);
    }
}

/// Fill `buf` with random bytes.
pub fn fill(buf: &mut [u8]) {
    let mut g = CRNG.lock();
    let c = g.as_mut().expect("rng::init not called");
    let now = crate::time::now_ns();
    if c.generated >= RESEED_BYTES || now.saturating_sub(c.last_reseed_ns) >= RESEED_NS {
        c.pool.update(IRQ_MIX.load(Ordering::Relaxed).to_le_bytes());
        c.pool.update(crate::arch::cpu::rdtsc().to_le_bytes());
        if let Some(v) = crate::arch::cpu::hw_random() {
            c.pool.update(v.to_le_bytes());
            c.pool_bits += 64;
        }
        let mut h = Sha256::new();
        h.update(c.key);
        h.update(c.pool.clone().finalize());
        c.key = h.finalize().into();
        c.generated = 0;
        c.last_reseed_ns = now;
    }
    // Generate in chunks: each chunk uses a fresh key (fast key erasure).
    for chunk in buf.chunks_mut(4096) {
        let mut cipher = ChaCha20::new(&c.key.into(), &[0u8; 12].into());
        let mut next_key = [0u8; 32];
        cipher.apply_keystream(&mut next_key);
        chunk.fill(0);
        cipher.apply_keystream(chunk);
        c.key = next_key;
        c.generated += chunk.len() as u64;
    }
}

pub fn u64() -> u64 {
    let mut b = [0u8; 8];
    fill(&mut b);
    u64::from_le_bytes(b)
}

pub fn u32() -> u32 {
    u64() as u32
}

/// Uniform integer in `0..n` (rejection sampling, no modulo bias).
pub fn below(n: u64) -> u64 {
    assert!(n > 0);
    let zone = u64::MAX - (u64::MAX % n);
    loop {
        let v = u64();
        if v < zone {
            return v % n;
        }
    }
}

pub fn array<const N: usize>() -> [u8; N] {
    let mut a = [0u8; N];
    fill(&mut a);
    a
}
