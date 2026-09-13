//! `nano` — a small, modeless full-screen editor.

use super::{load_file, pad, Buffer, Key, Term};
use crate::shell::ctx::Ctx;
use alloc::format;
use alloc::string::String;

struct Nano {
    buf: Buffer,
    status: String,
}

impl Nano {
    fn insert_char(&mut self, c: char) {
        let b = &mut self.buf;
        let at = b.cx.min(b.lines[b.cy].len());
        b.lines[b.cy].insert(at, c);
        b.cx = at + 1;
        b.modified = true;
    }

    fn insert_newline(&mut self) {
        let b = &mut self.buf;
        let at = b.cx.min(b.lines[b.cy].len());
        let rest = b.lines[b.cy].split_off(at);
        b.lines.insert(b.cy + 1, rest);
        b.cy += 1;
        b.cx = 0;
        b.modified = true;
    }

    fn backspace(&mut self) {
        let b = &mut self.buf;
        if b.cx > 0 {
            b.lines[b.cy].remove(b.cx - 1);
            b.cx -= 1;
            b.modified = true;
        } else if b.cy > 0 {
            let cur = b.lines.remove(b.cy);
            b.cy -= 1;
            b.cx = b.line_len(b.cy);
            b.lines[b.cy].push_str(&cur);
            b.modified = true;
        }
    }

    fn delete_forward(&mut self) {
        let b = &mut self.buf;
        let len = b.line_len(b.cy);
        if b.cx < len {
            b.lines[b.cy].remove(b.cx);
            b.modified = true;
        } else if b.cy + 1 < b.lines.len() {
            let next = b.lines.remove(b.cy + 1);
            b.lines[b.cy].push_str(&next);
            b.modified = true;
        }
    }

    fn cut_line(&mut self) {
        let b = &mut self.buf;
        if b.lines.len() == 1 {
            b.lines[0].clear();
        } else {
            b.lines.remove(b.cy);
            if b.cy >= b.lines.len() {
                b.cy = b.lines.len() - 1;
            }
        }
        b.cx = 0;
        b.modified = true;
    }
}

/// `nano [FILE]` — edit a file on the terminal.
pub fn nano(ctx: &mut Ctx) -> i32 {
    let name = ctx.args.iter().skip(1).find(|a| !a.starts_with('-')).cloned();
    let Some(tty) = ctx.stdout_tty() else {
        ctx.eprint("nano: standard output is not a terminal\n");
        return 1;
    };
    let (fname, text) = match &name {
        Some(n) => match load_file(ctx, n) {
            Ok(t) => (n.clone(), t),
            Err(e) => {
                ctx.eprint(&format!("nano: {n}: {e}\n"));
                return 1;
            }
        },
        None => (String::from("Untitled"), String::new()),
    };
    let mut ed = Nano { buf: Buffer::from_text(fname, &text), status: String::new() };
    if name.is_none() || text.is_empty() {
        ed.status = String::from("New Buffer");
    }
    ctx.flush();
    let term = Term::open(tty);
    term.write("\x1b[?1049h");
    let code = run(ctx, &term, &mut ed);
    term.write("\x1b[?1049l");
    code
}

fn run(ctx: &mut Ctx, term: &Term, ed: &mut Nano) -> i32 {
    loop {
        let (cols, rows) = term.size();
        draw(term, ed, cols, rows);
        match term.key() {
            Key::Timeout => {
                if !crate::sched::sleep_ms(20) {
                    crate::sched::with_current(|t| t.clear_signals());
                }
            }
            Key::Hangup => return 0,
            Key::Char(c) => {
                ed.insert_char(c as char);
                ed.status.clear();
            }
            Key::Enter => {
                ed.insert_newline();
                ed.status.clear();
            }
            Key::Backspace => ed.backspace(),
            Key::Up => {
                if ed.buf.cy > 0 {
                    ed.buf.cy -= 1;
                    ed.buf.clamp_cx();
                }
            }
            Key::Down => {
                if ed.buf.cy + 1 < ed.buf.lines.len() {
                    ed.buf.cy += 1;
                    ed.buf.clamp_cx();
                }
            }
            Key::Left => {
                if ed.buf.cx > 0 {
                    ed.buf.cx -= 1;
                } else if ed.buf.cy > 0 {
                    ed.buf.cy -= 1;
                    ed.buf.cx = ed.buf.line_len(ed.buf.cy);
                }
            }
            Key::Right => {
                if ed.buf.cx < ed.buf.line_len(ed.buf.cy) {
                    ed.buf.cx += 1;
                } else if ed.buf.cy + 1 < ed.buf.lines.len() {
                    ed.buf.cy += 1;
                    ed.buf.cx = 0;
                }
            }
            Key::Home | Key::Ctrl(1) => ed.buf.cx = 0,
            Key::End | Key::Ctrl(5) => ed.buf.cx = ed.buf.line_len(ed.buf.cy),
            Key::PageUp => {
                let page = rows.saturating_sub(3);
                ed.buf.cy = ed.buf.cy.saturating_sub(page);
                ed.buf.clamp_cx();
            }
            Key::PageDown => {
                let page = rows.saturating_sub(3);
                ed.buf.cy = (ed.buf.cy + page).min(ed.buf.lines.len() - 1);
                ed.buf.clamp_cx();
            }
            Key::Ctrl(4) => ed.delete_forward(),
            Key::Ctrl(11) => ed.cut_line(),
            Key::Ctrl(15) => save(ctx, term, ed, cols, rows),
            Key::Esc => {}
            Key::Ctrl(24) => {
                if ed.buf.modified {
                    match term.prompt(rows, cols, "Save modified buffer? (Y/N) ", "") {
                        Some(a) if a.starts_with(['y', 'Y']) => {
                            save(ctx, term, ed, cols, rows);
                            return 0;
                        }
                        Some(a) if a.starts_with(['n', 'N']) => return 0,
                        _ => {}
                    }
                } else {
                    return 0;
                }
            }
            Key::Ctrl(_) => {}
        }
    }
}

fn save(ctx: &mut Ctx, term: &Term, ed: &mut Nano, cols: usize, rows: usize) {
    let target = if ed.buf.name == "Untitled" {
        match term.prompt(rows, cols, "File Name to Write: ", "") {
            Some(n) if !n.is_empty() => n,
            _ => {
                ed.status = String::from("Cancelled");
                return;
            }
        }
    } else {
        ed.buf.name.clone()
    };
    match crate::fs::ops::write_file(&ctx.fs(), &target, ed.buf.text().as_bytes(), 0o644) {
        Ok(()) => {
            ed.buf.name = target;
            ed.buf.modified = false;
            let n = ed.buf.lines.len();
            ed.status = format!("Wrote {n} line{}", if n == 1 { "" } else { "s" });
        }
        Err(e) => ed.status = format!("Error writing: {e}"),
    }
}

fn draw(term: &Term, ed: &mut Nano, cols: usize, rows: usize) {
    let text_rows = rows.saturating_sub(2);
    if ed.buf.cy < ed.buf.top {
        ed.buf.top = ed.buf.cy;
    } else if ed.buf.cy >= ed.buf.top + text_rows {
        ed.buf.top = ed.buf.cy + 1 - text_rows;
    }
    let mut out = String::from("\x1b[H\x1b[2J");
    let title = format!("  nano  —  {}{}", ed.buf.name, if ed.buf.modified { " *" } else { "" });
    out.push_str(&format!("\x1b[7m{}\x1b[m\r\n", pad(&title, cols)));
    for r in 0..text_rows {
        if let Some(line) = ed.buf.lines.get(ed.buf.top + r) {
            let shown: String = line.chars().take(cols).collect();
            out.push_str(&shown);
        } else {
            out.push('~');
        }
        out.push_str("\r\n");
    }
    if !ed.status.is_empty() {
        out.push_str(&format!("\x1b[7m{}\x1b[m", pad(&format!("[ {} ]", ed.status), cols)));
    } else {
        out.push_str("^O Save   ^X Exit   ^K Cut   ^A Home   ^E End");
    }
    let scr_row = 2 + (ed.buf.cy - ed.buf.top);
    let scr_col = ed.buf.cx.min(cols.saturating_sub(1)) + 1;
    out.push_str(&format!("\x1b[{scr_row};{scr_col}H"));
    term.write(&out);
}
