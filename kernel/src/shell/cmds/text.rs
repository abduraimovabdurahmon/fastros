//! Text commands.

use crate::errno::Errno;
use crate::shell::ctx::{parse_opts, Ctx, OptSpec};
use alloc::string::String;
use alloc::vec::Vec;

/// Call `f` with each chunk of every input operand (stdin when none).
/// Errors are reported as `name: FILE: error`; returns false if any failed.
pub fn for_each_input(ctx: &mut Ctx, files: &[String], f: &mut dyn FnMut(&mut Ctx, &[u8]) -> bool) -> bool {
    let list: Vec<String> = if files.is_empty() { alloc::vec![String::from("-")] } else { files.to_vec() };
    let mut ok = true;
    let mut buf = alloc::vec![0u8; 32 * 1024];
    for name in list {
        let file = match ctx.open_input(&name) {
            Ok(f) => f,
            Err(e) => {
                let n = ctx.name().to_string();
                ctx.eprint(&alloc::format!("{n}: {name}: {e}\n"));
                ok = false;
                continue;
            }
        };
        ctx.flush();
        loop {
            match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if !f(ctx, &buf[..n]) {
                        return ok;
                    }
                }
                Err(Errno::EINTR) => return false,
                Err(e) => {
                    let n = ctx.name().to_string();
                    ctx.eprint(&alloc::format!("{n}: {name}: {e}\n"));
                    ok = false;
                    break;
                }
            }
            if ctx.should_stop() {
                return false;
            }
        }
    }
    ok
}

use alloc::string::ToString;

pub fn cat(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "nbsAETveu",
        values: "",
        long: &[("number", 'n', false), ("number-nonblank", 'b', false), ("squeeze-blank", 's', false), ("show-all", 'A', false), ("show-ends", 'E', false), ("show-tabs", 'T', false)],
    };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(m) => return ctx.fail(m),
    };
    let number_nb = p.has('b');
    let number = p.has('n') && !number_nb;
    let squeeze = p.has('s');
    let ends = p.has('E') || p.has('A') || p.has('e');
    let tabs = p.has('T') || p.has('A');
    let nonprint = p.has('v') || p.has('A') || p.has('e');
    let plain = !(number || number_nb || squeeze || ends || tabs || nonprint);
    let mut line_no = 0u64;
    let mut at_line_start = true;
    let mut blank_run = 0u32;
    let ok = for_each_input(ctx, &p.operands, &mut |ctx, data| {
        if plain {
            ctx.write(data);
            return true;
        }
        let mut out = Vec::with_capacity(data.len() + 16);
        for &b in data {
            if at_line_start {
                if b == b'\n' {
                    blank_run += 1;
                    if squeeze && blank_run > 1 {
                        continue;
                    }
                } else {
                    blank_run = 0;
                }
                if number || (number_nb && b != b'\n') {
                    line_no += 1;
                    out.extend_from_slice(alloc::format!("{:>6}\t", line_no).as_bytes());
                }
                at_line_start = false;
            }
            match b {
                b'\n' => {
                    if ends {
                        out.push(b'$');
                    }
                    out.push(b'\n');
                    at_line_start = true;
                }
                b'\t' if tabs => out.extend_from_slice(b"^I"),
                b'\t' => out.push(b),
                c if nonprint && c < 0x20 => {
                    out.push(b'^');
                    out.push(c + 64);
                }
                0x7F if nonprint => out.extend_from_slice(b"^?"),
                c if nonprint && c >= 0x80 => {
                    out.extend_from_slice(b"M-");
                    let c = c & 0x7F;
                    if c < 0x20 {
                        out.push(b'^');
                        out.push(c + 64);
                    } else {
                        out.push(c);
                    }
                }
                c => out.push(c),
            }
        }
        ctx.write(&out);
        true
    });
    if ok {
        0
    } else {
        1
    }
}
