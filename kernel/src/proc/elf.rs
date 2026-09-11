//! ELF64 program loader — static and dynamically-linked x86_64 executables.
//!
//! For a dynamic executable (one with a `PT_INTERP` segment naming an
//! interpreter such as `/lib64/ld-linux-x86-64.so.2`), the kernel loads both
//! the program and the interpreter, then jumps to the **interpreter's** entry
//! with an auxiliary vector describing the program (`AT_PHDR`, `AT_ENTRY`,
//! `AT_BASE`, ...). The interpreter then `mmap`s the shared libraries (see
//! file-backed mappings in `mm::aspace`) and runs the program.

use crate::arch::x86_64::syscall::UserFrame;
use crate::errno::{Errno, KResult};
use crate::fs::ops::{self, Ctx};
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

/// Load address for a PIE main program and for the interpreter.
const PIE_BASE: usize = 0x5555_5555_0000;
const INTERP_BASE: usize = 0x7FE0_0000_0000;
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

/// What loading one ELF object yielded.
struct Object {
    entry: usize,
    phdr: usize,
    phent: usize,
    phnum: usize,
    brk: usize,
    interp: Option<String>,
}

fn prot_of(flags: u32) -> Prot {
    let mut p = Prot::NONE;
    if flags & PF_R != 0 {
        p = p | Prot::READ;
    }
    if flags & PF_W != 0 {
        p = p | Prot::WRITE;
    }
    if flags & PF_X != 0 {
        p = p | Prot::EXEC;
    }
    p
}

/// Load one ELF image's `PT_LOAD` segments into `space` at `bias` (0 for a
/// fixed ET_EXEC, a load base for a PIE / the interpreter).
fn load_object(space: &AddressSpace, data: &[u8], bias: usize) -> KResult<Object> {
    if data.len() < 64 || &data[..4] != b"\x7fELF" || data[4] != 2 || data[5] != 1 {
        return Err(Errno::ENOEXEC);
    }
    if rd_u16(data, 18) != 0x3E {
        return Err(Errno::ENOEXEC); // not x86_64
    }
    let etype = rd_u16(data, 16);
    if etype != ET_EXEC && etype != ET_DYN {
        return Err(Errno::ENOEXEC);
    }
    let entry = rd_u64(data, 24) as usize + bias;
    let phoff = rd_u64(data, 32) as usize;
    let phentsize = rd_u16(data, 54) as usize;
    let phnum = rd_u16(data, 56) as usize;
    let mut brk = 0usize;
    let mut interp = None;
    // AT_PHDR must be the *virtual* address of the program headers. They sit
    // inside the load segment that maps file offset 0 (which also maps the ELF
    // header), so phdr = that segment's vaddr + phoff. Using bias + phoff is
    // wrong for ET_EXEC (bias 0 → phdr = 0x40, a null-ish deref).
    let mut phdr = bias + phoff;

    for i in 0..phnum {
        let o = phoff + i * phentsize;
        if o + 56 > data.len() {
            return Err(Errno::ENOEXEC);
        }
        let ptype = rd_u32(data, o);
        let foff = rd_u64(data, o + 8) as usize;
        let vaddr = rd_u64(data, o + 16) as usize + bias;
        let filesz = rd_u64(data, o + 32) as usize;
        let memsz = rd_u64(data, o + 40) as usize;
        if ptype == PT_INTERP {
            let end = (foff + filesz).min(data.len());
            let s = &data[foff..end];
            let s = &s[..s.iter().position(|&b| b == 0).unwrap_or(s.len())];
            interp = Some(String::from_utf8_lossy(s).into_owned());
            continue;
        }
        if ptype != PT_LOAD {
            continue;
        }
        if foff <= phoff && phoff < foff + filesz {
            phdr = vaddr + (phoff - foff);
        }
        let prot = prot_of(rd_u32(data, o + 4));
        let start = align_down(vaddr, PAGE_SIZE);
        let end = align_up(vaddr + memsz, PAGE_SIZE);
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
    Ok(Object { entry, phdr, phent: phentsize, phnum, brk, interp })
}

/// Push the argv/envp/auxv stack. Returns the final RSP.
fn build_stack(space: &AddressSpace, obj: &Object, at_base: Option<usize>, argv: &[String], envp: &[String]) -> KResult<usize> {
    let stack_top = USER_STACK_TOP;
    space.map_region(stack_top - STACK_SIZE, stack_top, Prot::READ | Prot::WRITE, true)?;
    let mut sp = stack_top;
    let mut put = |s: &[u8], sp: &mut usize| -> KResult<usize> {
        *sp -= s.len() + 1;
        space.write(*sp, s)?;
        space.write(*sp + s.len(), &[0u8])?;
        Ok(*sp)
    };
    let execfn = put(argv.first().map(|s| s.as_bytes()).unwrap_or(b""), &mut sp)?;
    let mut argv_a = Vec::new();
    for a in argv {
        argv_a.push(put(a.as_bytes(), &mut sp)?);
    }
    let mut envp_a = Vec::new();
    for e in envp {
        envp_a.push(put(e.as_bytes(), &mut sp)?);
    }
    let rnd: [u8; 16] = crate::crypto::rng::array();
    sp -= 16;
    space.write(sp, &rnd)?;
    let at_random = sp;

    let cred = crate::proc::current().cred();
    let mut aux: Vec<(u64, u64)> = alloc::vec![
        (3, obj.phdr as u64),   // AT_PHDR
        (4, obj.phent as u64),  // AT_PHENT
        (5, obj.phnum as u64),  // AT_PHNUM
        (6, PAGE_SIZE as u64),  // AT_PAGESZ
        (9, obj.entry as u64),  // AT_ENTRY (the program, not the interpreter)
        (11, cred.uid as u64),  // AT_UID
        (12, cred.euid as u64), // AT_EUID
        (13, cred.gid as u64),  // AT_GID
        (14, cred.egid as u64), // AT_EGID
        (23, 0),                // AT_SECURE
        (25, at_random as u64), // AT_RANDOM
        (31, execfn as u64),    // AT_EXECFN
    ];
    if let Some(base) = at_base {
        aux.push((7, base as u64)); // AT_BASE (interpreter load base)
    }
    aux.push((0, 0)); // AT_NULL

    let mut words: Vec<u64> = Vec::new();
    words.push(argv.len() as u64);
    words.extend(argv_a.iter().map(|&a| a as u64));
    words.push(0);
    words.extend(envp_a.iter().map(|&a| a as u64));
    words.push(0);
    for (k, v) in aux {
        words.push(k);
        words.push(v);
    }
    let bytes = words.len() * 8;
    sp = align_down(sp - bytes, 16);
    for (i, w) in words.iter().enumerate() {
        space.write(sp + i * 8, &w.to_le_bytes())?;
    }
    Ok(sp)
}

/// Load `data` (a program image) into a new address space, resolving a
/// dynamic interpreter through `ctx` if the program needs one.
pub fn load(ctx: &Ctx, data: &[u8], argv: &[String], envp: &[String]) -> KResult<(Arc<AddressSpace>, UserFrame)> {
    let space = AddressSpace::new()?;
    let etype = rd_u16(data, 16);
    let bias = if etype == ET_DYN { PIE_BASE } else { 0 };
    let prog = load_object(&space, data, bias)?;

    let (entry, at_base, brk) = match &prog.interp {
        Some(path) => {
            let interp_data = ops::read_file(ctx, path).map_err(|_| Errno::ENOEXEC)?;
            let interp = load_object(&space, &interp_data, INTERP_BASE)?;
            (interp.entry, Some(INTERP_BASE), prog.brk)
        }
        None => (prog.entry, None, prog.brk),
    };
    space.set_brk_base(brk);
    let sp = build_stack(&space, &prog, at_base, argv, envp)?;
    Ok((space, UserFrame::new(entry, sp)))
}
