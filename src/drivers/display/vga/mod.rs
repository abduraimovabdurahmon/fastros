//! VGA Text Mode Driver (80x25)
//!
//! The simplest way to output text — directly write to 0xb8000.
//! Each cell is 2 bytes: [char_ascii, color_attribute].
//!
//! Color attribute: [bg:4 bits][fg:4 bits]
//!   0=black, 1=blue, 2=green, 3=cyan, 4=red, 5=magenta, 6=brown, 7=white
//!   8–15 = bright variants

const VGA_BASE: *mut u8 = 0xb8000 as *mut u8;
const COLS: usize = 80;
const ROWS: usize = 25;

static mut CURSOR_X: usize = 0;
static mut CURSOR_Y: usize = 1; // Row 0 = kernel version banner

pub fn init() {
    clear(0x00); // black background
}

/// Print bytes at a fixed row (no cursor movement). For simple banners.
pub fn print(msg: &[u8], color: u8) {
    for (i, &ch) in msg.iter().enumerate() {
        if i >= COLS { break; }
        unsafe {
            *VGA_BASE.add(i * 2)     = ch;
            *VGA_BASE.add(i * 2 + 1) = color;
        }
    }
}

/// Print a string at the current cursor position with scrolling.
pub fn write(msg: &[u8], color: u8) {
    for &ch in msg {
        write_char(ch, color);
    }
}

fn write_char(ch: u8, color: u8) {
    unsafe {
        match ch {
            b'\n' => {
                CURSOR_X = 0;
                CURSOR_Y += 1;
                if CURSOR_Y >= ROWS { scroll(); CURSOR_Y = ROWS - 1; }
            }
            _ => {
                let offset = (CURSOR_Y * COLS + CURSOR_X) * 2;
                *VGA_BASE.add(offset)     = ch;
                *VGA_BASE.add(offset + 1) = color;
                CURSOR_X += 1;
                if CURSOR_X >= COLS {
                    CURSOR_X = 0;
                    CURSOR_Y += 1;
                    if CURSOR_Y >= ROWS { scroll(); CURSOR_Y = ROWS - 1; }
                }
            }
        }
    }
}

fn scroll() {
    unsafe {
        // Move all rows up by one
        for row in 1..ROWS {
            for col in 0..COLS {
                let dst = ((row - 1) * COLS + col) * 2;
                let src = (row * COLS + col) * 2;
                *VGA_BASE.add(dst)     = *VGA_BASE.add(src);
                *VGA_BASE.add(dst + 1) = *VGA_BASE.add(src + 1);
            }
        }
        // Clear the last row
        for col in 0..COLS {
            let offset = ((ROWS - 1) * COLS + col) * 2;
            *VGA_BASE.add(offset)     = b' ';
            *VGA_BASE.add(offset + 1) = 0x07;
        }
    }
}

fn clear(color: u8) {
    for i in 0..(COLS * ROWS) {
        unsafe {
            *VGA_BASE.add(i * 2)     = b' ';
            *VGA_BASE.add(i * 2 + 1) = color;
        }
    }
}
