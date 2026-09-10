//! `vim` — modal text editor (Vi-compatible subset).
//!
//! Layout (80×25 VGA):
//!   Rows 0–22  : text area   (LightGray on Black)
//!   Row  23    : status line (White on Blue / White on Green in Insert)
//!   Row  24    : command line / mode indicator
//!
//! Modes:
//!   Normal  — default; navigation and commands
//!   Insert  — text entry; Esc returns to Normal
//!   Command — after ':'; enter Ex commands (:q :w :wq)
//!
//! Normal mode keys:
//!   h/j/k/l or Arrows — navigate
//!   i   — Insert before cursor
//!   a   — Insert after cursor
//!   A   — Insert at end of line
//!   o   — Open new line below and insert
//!   O   — Open new line above and insert
//!   x   — Delete character at cursor
//!   dd  — Delete current line  (press d twice)
//!   0   — Start of line
//!   $   — End of line
//!   gg  — First line
//!   G   — Last line
//!   :   — Enter command mode
//!
//! Command mode (:):
//!   :q  :q!  :w  :wq  :wq!  — quit / write / both
//!   :N  (number)             — go to line N

use super::Command;
use super::editor::{
    EditorBuf, CLR_TEXT, CLR_TITLE, CLR_TILDE, CLR_INSERT, CLR_CMD,
};
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;
use crate::drivers::char::keyboard::{
    KEY_UP, KEY_DOWN, KEY_LEFT, KEY_RIGHT,
    KEY_HOME, KEY_END, KEY_PGUP, KEY_PGDN, KEY_DEL,
};

const CONTENT_ROWS: usize = 23; // rows 0..=22
const SCREEN_COLS:  usize = 80;
const ESC:          u8    = 0x1B;
const CLR_STATUSBAR: u8   = CLR_TITLE; // White on Blue for status bar

pub struct VimCommand;
pub static VIM: VimCommand = VimCommand;

static mut VIM_BUF: EditorBuf = EditorBuf::new();

// ── Editor mode ───────────────────────────────────────────────────────────────

#[derive(PartialEq, Clone, Copy)]
enum Mode { Normal, Insert, Command }

// ── Editor state ──────────────────────────────────────────────────────────────

struct State {
    cx:       usize,
    cy:       usize,
    scroll:   usize,
    mode:     Mode,
    modified: bool,
    fname:    [u8; 64],
    fname_len: usize,
    // Command line buffer (after ':')
    cmd:      [u8; 40],
    cmd_len:  usize,
    // Message shown in command line
    msg:      [u8; 64],
    msg_len:  usize,
    // Normal mode: track last key for two-key commands (dd, gg)
    last_key: u8,
}

impl State {
    fn line_idx(&self) -> usize { self.scroll + self.cy }

    fn set_msg(&mut self, m: &[u8]) {
        let n = m.len().min(64);
        self.msg[..n].copy_from_slice(&m[..n]);
        self.msg_len = n;
    }
    fn clear_msg(&mut self) { self.msg_len = 0; self.cmd_len = 0; }
}

impl Command for VimCommand {
    fn name(&self) -> &'static str { "vim" }
    fn description(&self) -> &'static str { "Modal text editor (Esc=Normal, i=Insert, :q=quit)" }

    fn execute(&self, args: &[&[u8]], _env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        let buf = unsafe { &mut VIM_BUF };

        let mut st = State {
            cx: 0, cy: 0, scroll: 0,
            mode: Mode::Normal,
            modified: false,
            fname: [0u8; 64], fname_len: 0,
            cmd:   [0u8; 40], cmd_len: 0,
            msg:   [0u8; 64], msg_len: 0,
            last_key: 0,
        };

        if let Some(&fname) = args.first() {
            let n = fname.len().min(64);
            st.fname[..n].copy_from_slice(&fname[..n]);
            st.fname_len = n;
            if let Some(content) = super::virt_fs::get_content(fname) {
                buf.load(content);
            } else {
                buf.clear();
            }
        } else {
            buf.clear();
        }

        redraw(io, buf, &st);

        loop {
            let key = io.read_byte_blocking();

            match st.mode {
                Mode::Normal  => {
                    if handle_normal(key, &mut st, buf) { break; }
                }
                Mode::Insert  => handle_insert(key, &mut st, buf),
                Mode::Command => {
                    if handle_command(key, &mut st, buf) { break; }
                }
            }

            redraw(io, buf, &st);
        }

        io.clear_screen();
        0
    }
}

// ── Normal mode ───────────────────────────────────────────────────────────────

/// Returns true if the editor should exit.
fn handle_normal(key: u8, st: &mut State, buf: &mut EditorBuf) -> bool {
    st.clear_msg();

    match key {
        // ── Enter insert mode ──────────────────────────────────────────────
        b'i' => {
            st.mode = Mode::Insert;
            st.last_key = 0;
        }
        b'a' => {
            let line_len = buf.line(st.line_idx()).len();
            if st.cx < line_len { st.cx += 1; }
            st.mode = Mode::Insert;
            st.last_key = 0;
        }
        b'A' => {
            st.cx = buf.line(st.line_idx()).len();
            st.mode = Mode::Insert;
            st.last_key = 0;
        }
        b'o' => {
            let li = st.line_idx();
            buf.split_line(li, buf.line(li).len());
            if st.cy < CONTENT_ROWS - 1 { st.cy += 1; } else { st.scroll += 1; }
            st.cx = 0;
            st.mode = Mode::Insert;
            st.modified = true;
            st.last_key = 0;
        }
        b'O' => {
            let li = st.line_idx();
            buf.split_line(li, 0);
            st.cx = 0;
            st.mode = Mode::Insert;
            st.modified = true;
            st.last_key = 0;
        }

        // ── Enter command mode ─────────────────────────────────────────────
        b':' => {
            st.mode = Mode::Command;
            st.cmd_len = 0;
            st.last_key = 0;
        }

        // ── Navigation: h j k l ───────────────────────────────────────────
        b'h' | KEY_LEFT => move_left(st, buf),
        b'l' | KEY_RIGHT => move_right(st, buf),
        b'k' | KEY_UP   => move_up(st, buf),
        b'j' | KEY_DOWN => move_down(st, buf),

        KEY_HOME | b'0' => { st.cx = 0; }
        KEY_END  | b'$' => { st.cx = buf.line(st.line_idx()).len().saturating_sub(1).max(0); }
        KEY_PGUP => {
            if st.scroll >= CONTENT_ROWS { st.scroll -= CONTENT_ROWS; }
            else { st.scroll = 0; st.cy = 0; }
            clamp_cx(st, buf);
        }
        KEY_PGDN => {
            let max_scroll = buf.count.saturating_sub(CONTENT_ROWS);
            st.scroll = (st.scroll + CONTENT_ROWS).min(max_scroll);
            clamp_cx(st, buf);
        }

        // ── g/G — first/last line ─────────────────────────────────────────
        b'g' => {
            if st.last_key == b'g' {
                st.scroll = 0; st.cy = 0; st.cx = 0;
                st.last_key = 0;
            } else {
                st.last_key = b'g';
                return false; // wait for second key
            }
        }
        b'G' => {
            let total = buf.count;
            if total > CONTENT_ROWS {
                st.scroll = total - CONTENT_ROWS;
                st.cy = CONTENT_ROWS - 1;
            } else {
                st.scroll = 0;
                st.cy = total.saturating_sub(1);
            }
            st.cx = 0;
        }

        // ── x — delete character at cursor ────────────────────────────────
        b'x' | KEY_DEL => {
            buf.delete_char(st.line_idx(), st.cx);
            let line_len = buf.line(st.line_idx()).len();
            if st.cx > 0 && st.cx >= line_len { st.cx = line_len.saturating_sub(1); }
            st.modified = true;
            st.last_key = 0;
        }

        // ── d — delete (dd = delete line) ─────────────────────────────────
        b'd' => {
            if st.last_key == b'd' {
                buf.remove_line(st.line_idx());
                if buf.count == 0 { buf.clear(); }
                if st.cy > 0 && st.cy >= buf.count.saturating_sub(st.scroll) {
                    st.cy = st.cy.saturating_sub(1);
                }
                clamp_cx(st, buf);
                st.modified = true;
                st.last_key = 0;
            } else {
                st.last_key = b'd';
                return false;
            }
        }

        // ── u — undo (stub: show message) ─────────────────────────────────
        b'u' => {
            st.set_msg(b"Already at oldest change");
            st.last_key = 0;
        }

        _ => { st.last_key = 0; }
    }

    false
}

// ── Insert mode ───────────────────────────────────────────────────────────────

fn handle_insert(key: u8, st: &mut State, buf: &mut EditorBuf) {
    st.clear_msg();
    match key {
        ESC => {
            st.mode = Mode::Normal;
            // Move cursor left one if possible (vim behaviour)
            if st.cx > 0 { st.cx -= 1; }
        }
        b'\n' | b'\r' => {
            let li = st.line_idx();
            buf.split_line(li, st.cx);
            if st.cy < CONTENT_ROWS - 1 { st.cy += 1; } else { st.scroll += 1; }
            st.cx = 0;
            st.modified = true;
        }
        0x08 | 0x7F => {
            let mut li = st.line_idx();
            let mut cx = st.cx;
            buf.backspace(&mut li, &mut cx);
            if li < st.scroll { st.scroll = li; st.cy = 0; }
            else { st.cy = li - st.scroll; }
            st.cx = cx;
            st.modified = true;
        }
        KEY_DEL => {
            buf.delete_char(st.line_idx(), st.cx);
            clamp_cx(st, buf);
            st.modified = true;
        }
        KEY_UP    => move_up(st, buf),
        KEY_DOWN  => move_down(st, buf),
        KEY_LEFT  => move_left(st, buf),
        KEY_RIGHT => move_right(st, buf),
        KEY_HOME  => { st.cx = 0; }
        KEY_END   => { st.cx = buf.line(st.line_idx()).len(); }
        0x20..=0x7E => {
            buf.insert_char(st.line_idx(), st.cx, key);
            st.cx += 1;
            st.modified = true;
        }
        _ => {}
    }
}

// ── Command mode (:) ─────────────────────────────────────────────────────────

/// Returns true to exit.
fn handle_command(key: u8, st: &mut State, buf: &mut EditorBuf) -> bool {
    match key {
        ESC | b'\x03' => {
            st.mode = Mode::Normal;
            st.cmd_len = 0;
        }
        b'\n' | b'\r' => {
            let result = exec_cmd(st, buf);
            st.mode = Mode::Normal;
            st.cmd_len = 0;
            return result;
        }
        0x08 | 0x7F => {
            if st.cmd_len > 0 { st.cmd_len -= 1; }
            else { st.mode = Mode::Normal; }
        }
        0x20..=0x7E => {
            if st.cmd_len < 40 {
                st.cmd[st.cmd_len] = key;
                st.cmd_len += 1;
            }
        }
        _ => {}
    }
    false
}

/// Execute Ex command. Returns true to exit.
fn exec_cmd(st: &mut State, buf: &mut EditorBuf) -> bool {
    let cmd = &st.cmd[..st.cmd_len];
    match cmd {
        b"q" => {
            if st.modified {
                st.set_msg(b"E37: No write since last change (add ! to override)");
                return false;
            }
            return true;
        }
        b"q!" => { return true; }
        b"w" | b"w!" => {
            if st.fname_len > 0 {
                save_to_memfs(buf, &st.fname[..st.fname_len]);
                st.modified = false;
                st.set_msg(b"File written");
            } else {
                st.set_msg(b"E32: No file name");
            }
        }
        b"wq" | b"wq!" | b"x" => {
            if st.fname_len > 0 {
                save_to_memfs(buf, &st.fname[..st.fname_len]);
            }
            st.modified = false;
            return true;
        }
        _ => {
            // Try line-number jump (:N)
            if let Some(n) = parse_line_number(cmd) {
                let target = (n as usize).saturating_sub(1).min(buf.count.saturating_sub(1));
                if target < CONTENT_ROWS {
                    st.scroll = 0;
                    st.cy = target;
                } else {
                    st.scroll = target - CONTENT_ROWS / 2;
                    st.cy = CONTENT_ROWS / 2;
                }
                st.cx = 0;
            } else {
                st.set_msg(b"E492: Not an editor command");
            }
        }
    }
    false
}

fn parse_line_number(s: &[u8]) -> Option<u64> {
    if s.is_empty() { return None; }
    let mut n: u64 = 0;
    for &b in s {
        if b < b'0' || b > b'9' { return None; }
        n = n * 10 + (b - b'0') as u64;
    }
    Some(n)
}

// ── Movement helpers ──────────────────────────────────────────────────────────

fn move_up(st: &mut State, buf: &EditorBuf) {
    if st.cy > 0 { st.cy -= 1; }
    else if st.scroll > 0 { st.scroll -= 1; }
    clamp_cx(st, buf);
}
fn move_down(st: &mut State, buf: &EditorBuf) {
    if st.line_idx() + 1 < buf.count {
        if st.cy < CONTENT_ROWS - 1 { st.cy += 1; } else { st.scroll += 1; }
        clamp_cx(st, buf);
    }
}
fn move_left(st: &mut State, buf: &EditorBuf) {
    if st.cx > 0 { st.cx -= 1; }
    else if st.line_idx() > 0 {
        if st.cy > 0 { st.cy -= 1; } else if st.scroll > 0 { st.scroll -= 1; }
        st.cx = buf.line(st.line_idx()).len().saturating_sub(1);
    }
}
fn move_right(st: &mut State, buf: &EditorBuf) {
    let ll = buf.line(st.line_idx()).len();
    let limit = if st.mode == Mode::Normal { ll.saturating_sub(1) } else { ll };
    if st.cx < limit { st.cx += 1; }
    else if st.line_idx() + 1 < buf.count {
        if st.cy < CONTENT_ROWS - 1 { st.cy += 1; } else { st.scroll += 1; }
        st.cx = 0;
    }
}
fn clamp_cx(st: &mut State, buf: &EditorBuf) {
    let ll = buf.line(st.line_idx()).len();
    let limit = if st.mode == Mode::Normal && ll > 0 { ll - 1 } else { ll };
    if st.cx > limit { st.cx = limit; }
}

// ── Rendering ─────────────────────────────────────────────────────────────────

fn redraw(io: &mut dyn ShellIo, buf: &EditorBuf, st: &State) {
    // ── Rows 0–22: text ───────────────────────────────────────────────────────
    for r in 0..CONTENT_ROWS {
        let screen_row = r as u16;
        io.fill_row(screen_row, b' ', CLR_TEXT);
        let line_idx = st.scroll + r;
        if line_idx < buf.count {
            let line = buf.line(line_idx);
            let vis = line.len().min(SCREEN_COLS);
            if vis > 0 { io.write_at(0, screen_row, &line[..vis], CLR_TEXT); }
        } else {
            io.put_char_at(0, screen_row, b'~', CLR_TILDE);
        }
    }

    // ── Row 23: status line ───────────────────────────────────────────────────
    let status_color = if st.mode == Mode::Insert { CLR_INSERT } else { CLR_STATUSBAR };
    io.fill_row(23, b' ', status_color);

    // Filename / [No Name]
    if st.fname_len > 0 {
        io.write_at(1, 23, &st.fname[..st.fname_len], status_color);
    } else {
        io.write_at(1, 23, b"[No Name]", status_color);
    }
    if st.modified {
        io.write_at(st.fname_len as u16 + 2, 23, b"[+]", status_color);
    }

    // Line/col info on right of status line
    let li = st.line_idx() + 1;
    let col = st.cx + 1;
    let mut info = [0u8; 20];
    let mut pos = 0;
    pos += write_num(&mut info[pos..], li as u64);
    info[pos] = b','; pos += 1;
    pos += write_num(&mut info[pos..], col as u64);
    let info_col = (SCREEN_COLS.saturating_sub(pos + 2)) as u16;
    io.write_at(info_col, 23, &info[..pos], status_color);

    // ── Row 24: command line / mode ───────────────────────────────────────────
    io.fill_row(24, b' ', CLR_TEXT);
    match st.mode {
        Mode::Normal => {
            if st.msg_len > 0 {
                io.write_at(0, 24, &st.msg[..st.msg_len], CLR_CMD);
            }
            // Pending 'd' indicator
            if st.last_key == b'd' {
                io.write_at(0, 24, b"d", CLR_CMD);
            }
        }
        Mode::Insert => {
            io.write_at(0, 24, b"-- INSERT --", CLR_INSERT);
        }
        Mode::Command => {
            io.put_char_at(0, 24, b':', CLR_CMD);
            if st.cmd_len > 0 {
                io.write_at(1, 24, &st.cmd[..st.cmd_len], CLR_CMD);
            }
        }
    }

    // ── Hardware cursor ───────────────────────────────────────────────────────
    match st.mode {
        Mode::Command => {
            io.move_cursor((st.cmd_len as u16) + 1, 24);
        }
        _ => {
            let clamped = st.cx.min(SCREEN_COLS - 1);
            io.move_cursor(clamped as u16, st.cy as u16);
        }
    }
}

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
    while n > 0 { tmp[len] = b'0' + (n % 10) as u8; n /= 10; len += 1; }
    let out = len.min(buf.len());
    for i in 0..out { buf[i] = tmp[len - 1 - i]; }
    out
}
