//! `nano` — simple full-screen text editor.
//!
//! Layout (80×25 VGA):
//!   Row  0     : title bar  (White on Blue)
//!   Rows 1–23  : text area  (LightGray on Black)
//!   Row 24     : status bar (Black on LightGray)
//!
//! Key bindings:
//!   Ctrl+X  (0x18) — exit
//!   Ctrl+O  (0x0F) — save (in-memory, shows confirmation)
//!   Ctrl+S  (0x13) — save alias
//!   Ctrl+K  (0x0B) — cut (delete) current line
//!   Ctrl+G  (0x07) — show help message
//!   Arrow keys     — navigate
//!   Home / End     — start / end of line
//!   PgUp / PgDn    — scroll by screen
//!   Enter          — insert new line
//!   Backspace      — delete character before cursor
//!   Del            — delete character at cursor

use super::Command;
use super::editor::{EditorBuf, CLR_TEXT, CLR_TITLE, CLR_STATUS, CLR_TILDE};
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;
use crate::drivers::char::keyboard::{
    KEY_UP, KEY_DOWN, KEY_LEFT, KEY_RIGHT,
    KEY_HOME, KEY_END, KEY_PGUP, KEY_PGDN, KEY_DEL,
};

const CONTENT_ROWS: usize = 23; // rows 1..=23
const SCREEN_COLS:  usize = 80;

// Ctrl key codes
const CTRL_X: u8 = 0x18;
const CTRL_O: u8 = 0x0F;
const CTRL_S: u8 = 0x13;
const CTRL_K: u8 = 0x0B;
const CTRL_G: u8 = 0x07;

pub struct NanoCommand;
pub static NANO: NanoCommand = NanoCommand;

// Static buffer — avoids stack overflow (8 KB in BSS).
static mut NANO_BUF: EditorBuf = EditorBuf::new();

// ── Editor state ──────────────────────────────────────────────────────────────

struct State {
    cx:       usize,   // cursor column in the current line
    cy:       usize,   // cursor row within visible area (0 .. CONTENT_ROWS-1)
    scroll:   usize,   // index of the first visible line
    modified: bool,
    fname:    [u8; 64],
    fname_len: usize,
    msg:      [u8; 64],
    msg_len:  usize,
}

impl State {
    fn line_idx(&self) -> usize { self.scroll + self.cy }

    fn set_msg(&mut self, m: &[u8]) {
        let n = m.len().min(64);
        self.msg[..n].copy_from_slice(&m[..n]);
        self.msg_len = n;
    }
    fn clear_msg(&mut self) { self.msg_len = 0; }
}

impl Command for NanoCommand {
    fn name(&self) -> &'static str { "nano" }
    fn description(&self) -> &'static str { "Simple text editor (Ctrl+X to exit)" }

    fn execute(&self, args: &[&[u8]], env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        let buf = unsafe { &mut NANO_BUF };

        // Build filename
        let mut st = State {
            cx: 0, cy: 0, scroll: 0,
            modified: false,
            fname: [0u8; 64], fname_len: 0,
            msg:   [0u8; 64], msg_len:   0,
        };

        if let Some(&fname) = args.first() {
            // Resolve to absolute path so memfs key matches what cat/ls use
            let mut abs_buf = [0u8; 256];
            let abs = resolve_path(env.cwd(), fname, &mut abs_buf);
            let n = abs.len().min(64);
            st.fname[..n].copy_from_slice(&abs[..n]);
            st.fname_len = n;
            // Try to load content (memfs first, then virtual FS static content)
            if let Some(content) = super::virt_fs::get_content(abs) {
                buf.load(content);
                st.set_msg(b"File loaded");
            } else {
                buf.clear();
            }
        } else {
            buf.clear();
        }

        io.clear_screen();
        redraw(io, buf, &st);

        loop {
            let key = io.read_byte_blocking();
            st.clear_msg();

            match key {
                // ── Exit ──────────────────────────────────────────────────
                CTRL_X => break,

                // ── Save ──────────────────────────────────────────────────
                CTRL_O | CTRL_S => {
                    if st.fname_len > 0 {
                        save_to_memfs(buf, &st.fname[..st.fname_len]);
                        st.modified = false;
                        st.set_msg(b"[ File written ]");
                    } else {
                        st.set_msg(b"[ No filename - use: nano <filename> ]");
                    }
                }

                // ── Cut line ──────────────────────────────────────────────
                CTRL_K => {
                    let li = st.line_idx();
                    buf.remove_line(li);
                    if st.cy > 0 && st.cy >= buf.count.saturating_sub(st.scroll) {
                        st.cy = st.cy.saturating_sub(1);
                    }
                    st.cx = st.cx.min(buf.line(st.line_idx()).len());
                    st.modified = true;
                }

                // ── Help ──────────────────────────────────────────────────
                CTRL_G => {
                    st.set_msg(b"^X Exit  ^O Save  ^K Cut line  Arrow keys: navigate");
                }

                // ── Navigation ────────────────────────────────────────────
                KEY_UP => {
                    if st.cy > 0 {
                        st.cy -= 1;
                    } else if st.scroll > 0 {
                        st.scroll -= 1;
                    }
                    st.cx = st.cx.min(buf.line(st.line_idx()).len());
                }
                KEY_DOWN => {
                    let total = buf.count;
                    if st.line_idx() + 1 < total {
                        if st.cy < CONTENT_ROWS - 1 {
                            st.cy += 1;
                        } else {
                            st.scroll += 1;
                        }
                        st.cx = st.cx.min(buf.line(st.line_idx()).len());
                    }
                }
                KEY_LEFT => {
                    if st.cx > 0 {
                        st.cx -= 1;
                    } else if st.line_idx() > 0 {
                        // Wrap to end of previous line
                        if st.cy > 0 { st.cy -= 1; }
                        else if st.scroll > 0 { st.scroll -= 1; }
                        st.cx = buf.line(st.line_idx()).len();
                    }
                }
                KEY_RIGHT => {
                    let line_len = buf.line(st.line_idx()).len();
                    if st.cx < line_len {
                        st.cx += 1;
                    } else if st.line_idx() + 1 < buf.count {
                        if st.cy < CONTENT_ROWS - 1 { st.cy += 1; }
                        else { st.scroll += 1; }
                        st.cx = 0;
                    }
                }
                KEY_HOME => { st.cx = 0; }
                KEY_END  => { st.cx = buf.line(st.line_idx()).len(); }
                KEY_PGUP => {
                    if st.scroll >= CONTENT_ROWS {
                        st.scroll -= CONTENT_ROWS;
                    } else {
                        st.scroll = 0;
                        st.cy = 0;
                    }
                    st.cx = st.cx.min(buf.line(st.line_idx()).len());
                }
                KEY_PGDN => {
                    let max_scroll = buf.count.saturating_sub(CONTENT_ROWS);
                    st.scroll = (st.scroll + CONTENT_ROWS).min(max_scroll);
                    st.cx = st.cx.min(buf.line(st.line_idx()).len());
                }

                // ── Editing ───────────────────────────────────────────────
                b'\n' | b'\r' => {
                    let li = st.line_idx();
                    buf.split_line(li, st.cx);
                    if st.cy < CONTENT_ROWS - 1 { st.cy += 1; }
                    else { st.scroll += 1; }
                    st.cx = 0;
                    st.modified = true;
                }
                0x08 | 0x7F => {
                    // Backspace
                    let mut li = st.line_idx();
                    let mut cx = st.cx;
                    buf.backspace(&mut li, &mut cx);
                    // Recalculate cy/scroll from new li
                    if li < st.scroll {
                        st.scroll = li;
                        st.cy = 0;
                    } else {
                        st.cy = li - st.scroll;
                    }
                    st.cx = cx;
                    st.modified = true;
                }
                KEY_DEL => {
                    let li = st.line_idx();
                    buf.delete_char(li, st.cx);
                    st.cx = st.cx.min(buf.line(li).len());
                    st.modified = true;
                }
                // Printable ASCII
                0x20..=0x7E => {
                    let li = st.line_idx();
                    buf.insert_char(li, st.cx, key);
                    st.cx += 1;
                    st.modified = true;
                }
                // Ignore everything else (tabs, other control chars)
                _ => {}
            }

            redraw(io, buf, &st);
        }

        // Restore terminal for the shell
        io.clear_screen();
        0
    }
}

// ── Rendering ─────────────────────────────────────────────────────────────────

fn redraw(io: &mut dyn ShellIo, buf: &EditorBuf, st: &State) {
    // ── Row 0: title bar ──────────────────────────────────────────────────────
    io.fill_row(0, b' ', CLR_TITLE);
    io.write_at(0, 0, b"  FastROS nano  ", CLR_TITLE);
    if st.fname_len > 0 {
        io.write_at(16, 0, &st.fname[..st.fname_len], CLR_TITLE);
    } else {
        io.write_at(16, 0, b"(new file)", CLR_TITLE);
    }
    if st.modified {
        let mod_col = (SCREEN_COLS - 10) as u16;
        io.write_at(mod_col, 0, b"[Modified]", CLR_TITLE);
    }

    // ── Rows 1–23: text content ───────────────────────────────────────────────
    for r in 0..CONTENT_ROWS {
        let screen_row = (r + 1) as u16;
        io.fill_row(screen_row, b' ', CLR_TEXT);
        let line_idx = st.scroll + r;
        if line_idx < buf.count {
            let line = buf.line(line_idx);
            let visible = line.len().min(SCREEN_COLS);
            if visible > 0 {
                io.write_at(0, screen_row, &line[..visible], CLR_TEXT);
            }
        } else {
            io.put_char_at(0, screen_row, b'~', CLR_TILDE);
        }
    }

    // ── Row 24: status / shortcuts ────────────────────────────────────────────
    io.fill_row(24, b' ', CLR_STATUS);
    if st.msg_len > 0 {
        io.write_at(0, 24, &st.msg[..st.msg_len], CLR_STATUS);
    } else {
        // Show line/col on right, shortcuts on left
        io.write_at(0, 24, b"^X Exit  ^O Save  ^K Cut  ^G Help", CLR_STATUS);
        write_line_col(io, buf.count, st);
    }

    // ── Hardware cursor ───────────────────────────────────────────────────────
    let clamped_cx = st.cx.min(SCREEN_COLS - 1);
    io.move_cursor(clamped_cx as u16, (st.cy + 1) as u16);
}

/// Write "Ln:N  Col:N" right-aligned in the status bar.
fn write_line_col(io: &mut dyn ShellIo, _total: usize, st: &State) {
    let mut buf = [0u8; 20];
    let mut pos = 0;

    // "Ln:"
    buf[pos] = b'L'; pos += 1;
    buf[pos] = b'n'; pos += 1;
    buf[pos] = b':'; pos += 1;
    pos += write_num(&mut buf[pos..], (st.scroll + st.cy + 1) as u64);
    buf[pos] = b' '; pos += 1;
    buf[pos] = b'C'; pos += 1;
    buf[pos] = b'o'; pos += 1;
    buf[pos] = b'l'; pos += 1;
    buf[pos] = b':'; pos += 1;
    pos += write_num(&mut buf[pos..], (st.cx + 1) as u64);

    let col = (SCREEN_COLS - pos.min(SCREEN_COLS)) as u16;
    io.write_at(col, 24, &buf[..pos], CLR_STATUS);
}

/// Serialize EditorBuf lines (joined with \n) and write to memfs.
fn save_to_memfs(buf: &EditorBuf, path: &[u8]) {
    let mut tmp = [0u8; 4096];
    let mut pos = 0;
    for i in 0..buf.count {
        let line = buf.line(i);
        for &b in line {
            if pos < 4095 { tmp[pos] = b; pos += 1; }
        }
        if pos < 4095 { tmp[pos] = b'\n'; pos += 1; }
    }
    crate::shell::memfs::write(path, &tmp[..pos]);
}

fn write_num(buf: &mut [u8], mut n: u64) -> usize {
    if buf.is_empty() { return 0; }
    if n == 0 { buf[0] = b'0'; return 1; }
    let mut tmp = [0u8; 20];
    let mut len = 0;
    while n > 0 {
        tmp[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    let out = len.min(buf.len());
    for i in 0..out { buf[i] = tmp[len - 1 - i]; }
    out
}

/// Resolve `path` against `cwd` into `buf`. Returns slice of buf.
fn resolve_path<'a>(cwd: &[u8], path: &[u8], buf: &'a mut [u8; 256]) -> &'a [u8] {
    if path.first() == Some(&b'/') {
        let n = path.len().min(255);
        buf[..n].copy_from_slice(&path[..n]);
        return &buf[..n];
    }
    let mut n = 0usize;
    for &b in cwd { if n < 255 { buf[n] = b; n += 1; } }
    if cwd != b"/" && n < 255 { buf[n] = b'/'; n += 1; }
    for &b in path { if n < 255 { buf[n] = b; n += 1; } }
    &buf[..n]
}
