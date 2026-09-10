//! VGA Text Mode Driver — 80×25, color
//!
//! Physical buffer: 0xB8000
//! Each cell: [char: u8][attr: u8]
//! Attribute: [bg: 4 bits][fg: 4 bits]
//!
//! Hardware cursor: controlled via CRTC ports 0x3D4/0x3D5
//! Implements core::fmt::Write → use vga_print!/vga_println! macros.

use core::fmt;
use crate::kernel::sync::spinlock::SpinLock;

// ── Constants ─────────────────────────────────────────────────────────────────

const VGA_BASE: usize = 0xB8000;
const COLS: usize = 80;
const ROWS: usize = 25;

const CRTC_ADDR: u16 = 0x3D4;
const CRTC_DATA: u16 = 0x3D5;

// ── Colors ────────────────────────────────────────────────────────────────────

#[allow(dead_code)]
#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Color {
    Black        = 0,
    Blue         = 1,
    Green        = 2,
    Cyan         = 3,
    Red          = 4,
    Magenta      = 5,
    Brown        = 6,
    LightGray    = 7,
    DarkGray     = 8,
    LightBlue    = 9,
    LightGreen   = 10,
    LightCyan    = 11,
    LightRed     = 12,
    Pink         = 13,
    Yellow       = 14,
    White        = 15,
}

/// Pack foreground + background into a VGA attribute byte.
pub const fn attr(fg: Color, bg: Color) -> u8 {
    (bg as u8) << 4 | (fg as u8)
}

// ── Global writer state ───────────────────────────────────────────────────────

static VGA_LOCK: SpinLock = SpinLock::new();

static mut COL: usize = 0;
static mut ROW: usize = 0;
static mut ATTR: u8 = attr(Color::LightGreen, Color::Black); // default: green on black

// ── Public API ────────────────────────────────────────────────────────────────

/// Initialize VGA: clear screen, enable hardware cursor.
pub fn init() {
    unsafe {
        COL  = 0;
        ROW  = 0;
        ATTR = attr(Color::LightGreen, Color::Black);
    }
    clear();
    enable_cursor(0, 15); // full-height blinking cursor
    draw_banner();
}

/// Set the current foreground+background color for all subsequent writes.
pub fn set_color(fg: Color, bg: Color) {
    unsafe { ATTR = attr(fg, bg); }
}

/// Write raw bytes at the current cursor position.
pub fn write(msg: &[u8]) {
    VGA_LOCK.lock();
    for &b in msg {
        unsafe { put_char(b); }
    }
    unsafe { update_hw_cursor(COL, ROW); }
    VGA_LOCK.unlock();
}

/// Clear the entire screen to black.
pub fn clear() {
    let buf = VGA_BASE as *mut u16;
    let blank = (attr(Color::LightGray, Color::Black) as u16) << 8 | b' ' as u16;
    for i in 0..(COLS * ROWS) {
        unsafe { *buf.add(i) = blank; }
    }
    unsafe { COL = 0; ROW = 0; }
    update_hw_cursor(0, 0);
}

/// Move the hardware cursor to (col, row) and update internal state.
pub fn set_cursor(col: usize, row: usize) {
    unsafe { COL = col.min(COLS - 1); ROW = row.min(ROWS - 1); }
    update_hw_cursor(col.min(COLS - 1), row.min(ROWS - 1));
}

/// Fill an entire row with `ch` using `color`.
pub fn fill_row(row: usize, ch: u8, color: u8) {
    if row >= ROWS { return; }
    for col in 0..COLS {
        write_cell(col, row, ch, color);
    }
}

/// Write a byte slice at (x, y) with explicit `color`, clipping at screen edge.
pub fn write_at(x: usize, y: usize, s: &[u8], color: u8) {
    if y >= ROWS { return; }
    for (i, &b) in s.iter().enumerate() {
        if x + i >= COLS { break; }
        write_cell(x + i, y, b, color);
    }
}

/// Write a single character with an explicit color at position (x, y).
pub fn put_at(x: usize, y: usize, ch: u8, color: u8) {
    if x >= COLS || y >= ROWS { return; }
    let off = y * COLS + x;
    unsafe {
        let buf = VGA_BASE as *mut u8;
        *buf.add(off * 2)     = ch;
        *buf.add(off * 2 + 1) = color;
    }
}

/// Write a string using the fmt::Write interface (for use with write! macro).
pub fn write_fmt(args: fmt::Arguments) {
    use core::fmt::Write;
    VGA_LOCK.lock();
    let mut w = VgaFmtWriter;
    let _ = w.write_fmt(args);
    unsafe { update_hw_cursor(COL, ROW); }
    VGA_LOCK.unlock();
}

// ── fmt::Write ────────────────────────────────────────────────────────────────

struct VgaFmtWriter;

impl fmt::Write for VgaFmtWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            unsafe { put_char(b); }
        }
        Ok(())
    }
}

// ── Macros ────────────────────────────────────────────────────────────────────

#[macro_export]
macro_rules! vga_print {
    ($($arg:tt)*) => {
        $crate::drivers::display::vga::write_fmt(core::format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! vga_println {
    ()            => { $crate::vga_print!("\n") };
    ($($arg:tt)*) => { $crate::vga_print!("{}\n", core::format_args!($($arg)*)) };
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Write one byte at the current cursor position and advance.
unsafe fn put_char(ch: u8) {
    match ch {
        b'\n' => newline(),
        b'\r' => { COL = 0; }
        0x08  => backspace(), // BS
        _ => {
            write_cell(COL, ROW, ch, ATTR);
            COL += 1;
            if COL >= COLS { newline(); }
        }
    }
}

unsafe fn newline() {
    COL = 0;
    ROW += 1;
    if ROW >= ROWS { scroll_up(); ROW = ROWS - 1; }
}

unsafe fn backspace() {
    if COL > 0 {
        COL -= 1;
    } else if ROW > 0 {
        ROW -= 1;
        COL = COLS - 1;
    }
    write_cell(COL, ROW, b' ', ATTR);
}

fn write_cell(x: usize, y: usize, ch: u8, color: u8) {
    let off = (y * COLS + x) * 2;
    unsafe {
        let buf = VGA_BASE as *mut u8;
        *buf.add(off)     = ch;
        *buf.add(off + 1) = color;
    }
}

/// Scroll all rows up by one, clear the last row.
unsafe fn scroll_up() {
    let buf = VGA_BASE as *mut u16;
    // Copy rows 1..ROWS → 0..ROWS-1
    for row in 1..ROWS {
        for col in 0..COLS {
            let src = row * COLS + col;
            let dst = (row - 1) * COLS + col;
            *buf.add(dst) = *buf.add(src);
        }
    }
    // Blank the last row
    let blank = (attr(Color::LightGreen, Color::Black) as u16) << 8 | b' ' as u16;
    for col in 0..COLS {
        *buf.add((ROWS - 1) * COLS + col) = blank;
    }
}

// ── Hardware cursor ───────────────────────────────────────────────────────────

fn outb(port: u16, val: u8) {
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack));
    }
}

fn inb(port: u16) -> u8 {
    let v: u8;
    unsafe { core::arch::asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack)); }
    v
}

/// Enable the hardware blinking cursor. `start`/`end` = scan lines (0–15).
pub fn enable_cursor(start: u8, end: u8) {
    outb(CRTC_ADDR, 0x0A);
    outb(CRTC_DATA, (inb(CRTC_DATA) & 0xC0) | (start & 0x3F));
    outb(CRTC_ADDR, 0x0B);
    outb(CRTC_DATA, (inb(CRTC_DATA) & 0xE0) | (end & 0x1F));
}

/// Disable the hardware cursor (hide it).
pub fn disable_cursor() {
    outb(CRTC_ADDR, 0x0A);
    outb(CRTC_DATA, 0x20); // bit 5 = cursor off
}

/// Move the hardware cursor to (col, row).
fn update_hw_cursor(col: usize, row: usize) {
    let pos = (row * COLS + col) as u16;
    outb(CRTC_ADDR, 0x0F);
    outb(CRTC_DATA, (pos & 0xFF) as u8);
    outb(CRTC_ADDR, 0x0E);
    outb(CRTC_DATA, ((pos >> 8) & 0xFF) as u8);
}

// ── Boot banner ───────────────────────────────────────────────────────────────

fn draw_banner() {
    // Row 0: cyan header bar
    let header_attr = attr(Color::White, Color::Blue);
    let header = b"  FastROS v0.1.0                  Container-Native OS in Rust                  ";
    for (i, &b) in header.iter().enumerate().take(COLS) {
        put_at(i, 0, b, header_attr);
    }

    // Row 1: blank separator
    for i in 0..COLS {
        put_at(i, 1, b' ', attr(Color::Black, Color::Black));
    }

    // Move cursor to row 2 for kernel output
    unsafe { COL = 0; ROW = 2; }
    update_hw_cursor(0, 2);

    // Print status lines
    write(b"  Arch: x86_64    Mode: Long Mode (64-bit)\n");
    write(b"  GDT: loaded     IDT: loaded     PIC: remapped\n");
    write(b"  PMM: ready      VMM: ready      Heap: ready\n");
    write(b"\n");
    set_color(Color::Yellow, Color::Black);
    write(b"  FastROS kernel initialized. Ready.\n");
    write(b"\n");
    set_color(Color::LightGreen, Color::Black);
}
