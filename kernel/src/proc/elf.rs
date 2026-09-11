//! Static ELF64 program loader.
//!
//! Loads `PT_LOAD` segments of an `ET_EXEC` or `ET_DYN` (PIE) x86_64 binary
//! into a fresh [`AddressSpace`], lays out the initial process stack (argc,
//! argv, envp, auxv, per the System V AMD64 ABI), and returns the entry
//! [`UserFrame`]. Dynamically-linked executables (`PT_INTERP`) are not yet
//! supported — build container tools static for now.

use crate::arch::x86_64::syscall::UserFrame;
use crate::errno::{Errno, KResult};
use crate::mm::aspace::{AddressSpace, Prot, USER_STACK_TOP};
use crate::mm::{align_down, align_up, PAGE_SIZE};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;

/// Where a PIE (ET_DYN) executable is placed.
const PIE_BASE: usize = 0x5555_5555_0000;
const STACK_SIZE: usize = 8 * 1024 * 1024;

fn rd_u16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn rd_u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn rd_u64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3], b[o + 4], b[o + 5], b[o + 6], b[o + 7]])
}

struct Loaded {
    entry: usize,
    phdr: usize,
    phent: usize,
    phnum: usize,
    brk: usize,
}

fn load_segments(space: &AddressSpace, data: &[u8]) -> KResult<Loaded> {
    if data.len() < 64 || &data[..4] != b"\x7fELF" {
        return Err(Errno::ENOEXEC);
    }
    if data[4] != 2 || data[5] != 1 {
        return Err(Errno::ENOEXEC); // 64-bit, little-endian only
    }
    let etype = rd_u16(data, 16);
    if rd_u16(data, 18) != 0x3E {
        return Err(Errno::ENOEXEC); // not x86_64
    }
    let bias = if etype == ET_DYN { PIE_BASE } else { 0 };
    if etype != ET_EXEC && etype != ET_DYN {
        return Err(Errno::ENOEXEC);
    }
    let entry = rd_u64(data, 24) as usize + bias;
    let phoff = rd_u64(data, 32) as usize;
    let phentsize = rd_u16(data, 54) as usize;
    let phnum = rd_u16(data, 56) as usize;
    let mut brk = 0usize;
    let mut phdr_vaddr = 0usize;

    for i in 0..phnum {
        let o = phoff + i * phentsize;
        if o + 56 > data.len() {
            return Err(Errno::ENOEXEC);
        }
        let ptype = rd_u32(data, o);
        if ptype == PT_INTERP {
            return Err(Errno::ENOEXEC); // dynamic linker (PT_INTERP) unsupported
        }
        if ptype != PT_LOAD {
            continue;
        }
        let flags = rd_u32(data, o + 4);
        let foff = rd_u64(data, o + 8) as usize;
        let vaddr = rd_u64(data, o + 16) as usize + bias;
        let filesz = rd_u64(data, o + 32) as usize;
        let memsz = rd_u64(data, o + 40) as usize;
        // The ELF header maps at the first segment's file offset 0.
        if foff == 0 && phdr_vaddr == 0 {
            phdr_vaddr = vaddr + phoff;
        }
        let mut prot = Prot::NONE;
        if flags & PF_R != 0 {
            prot = prot | Prot::READ;
        }
        if flags & PF_W != 0 {
            prot = prot | Prot::WRITE;
        }
        if flags & PF_X != 0 {
            prot = prot | Prot::EXEC;
        }
        let start = align_down(vaddr, PAGE_SIZE);
        let end = align_up(vaddr + memsz, PAGE_SIZE);
        // Map writable first so the copy succeeds; re-protect after.
        space.map_region(start, end, prot | Prot::WRITE, false)?;
        if filesz > 0 {
            let src = data.get(foff..foff + filesz).ok_or(Errno::ENOEXEC)?;
            space.write(vaddr, src)?;
        }
        if !prot.contains(Prot::WRITE) {
            space.protect(start, end - start, prot)?;
        }
        brk = brk.max(end);
    }
    Ok(Loaded { entry, phdr: phdr_vaddr, phent: phentsize, phnum, brk })
}

/// Push the argument/environment vectors and auxv onto a fresh stack.
/// Returns the final RSP.
fn build_stack(space: &AddressSpace, l: &Loaded, argv: &[String], envp: &[String]) -> KResult<usize> {
    let stack_top = USER_STACK_TOP;
    let stack_bottom = stack_top - STACK_SIZE;
    space.map_region(stack_bottom, stack_top, Prot::READ | Prot::WRITE, true)?;

    // Lay strings down from the top, collecting their user addresses.
    let mut sp = stack_top;
    let mut put_str = |s: &[u8], sp: &mut usize| -> KResult<usize> {
        *sp -= s.len() + 1;
        space.write(*sp, s)?;
        space.write(*sp + s.len(), &[0u8])?;
        Ok(*sp)
    };
    let mut argv_addrs = Vec::new();
    for a in argv {
        argv_addrs.push(put_str(a.as_bytes(), &mut sp)?);
    }
    let mut envp_addrs = Vec::new();
    for e in envp {
        envp_addrs.push(put_str(e.as_bytes(), &mut sp)?);
    }
    // 16 random bytes for AT_RANDOM.
    let rnd: [u8; 16] = crate::crypto::rng::array();
    sp -= 16;
    space.write(sp, &rnd)?;
    let at_random = sp;

    // Build the vector; align RSP so that after pushing it stays 16-aligned.
    let cred = crate::proc::current().cred();
    let auxv: [(u64, u64); 12] = [
        (3, l.phdr as u64),   // AT_PHDR
        (4, l.phent as u64),  // AT_PHENT
        (5, l.phnum as u64),  // AT_PHNUM
        (6, PAGE_SIZE as u64),// AT_PAGESZ
        (9, l.entry as u64),  // AT_ENTRY
        (11, cred.uid as u64),// AT_UID
        (12, cred.euid as u64),// AT_EUID
        (13, cred.gid as u64),// AT_GID
        (14, cred.egid as u64),// AT_EGID
        (23, 0),              // AT_SECURE
        (25, at_random as u64),// AT_RANDOM
        (0, 0),               // AT_NULL
    ];
    let mut words: Vec<u64> = Vec::new();
    words.push(argv.len() as u64);
    words.extend(argv_addrs.iter().map(|&a| a as u64));
    words.push(0);
    words.extend(envp_addrs.iter().map(|&a| a as u64));
    words.push(0);
    for (k, v) in auxv {
        words.push(k);
        words.push(v);
    }
    let bytes = words.len() * 8;
    sp -= bytes;
    sp = align_down(sp, 16);
    // Re-derive after alignment so argc lands exactly at rsp.
    let base = sp;
    for (i, w) in words.iter().enumerate() {
        space.write(base + i * 8, &w.to_le_bytes())?;
    }
    Ok(base)
}

/// Load `data` into a new address space and return the space plus the entry
/// frame. `argv[0]` is conventionally the program path.
pub fn load(data: &[u8], argv: &[String], envp: &[String]) -> KResult<(Arc<AddressSpace>, UserFrame)> {
    let space = AddressSpace::new()?;
    let l = load_segments(&space, data)?;
    space.set_brk_base(l.brk);
    let sp = build_stack(&space, &l, argv, envp)?;
    let frame = UserFrame::new(l.entry, sp);
    Ok((space, frame))
}
