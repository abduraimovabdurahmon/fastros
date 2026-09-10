//! PS/2 Keyboard Driver — Set 1 scancodes
//!
//! Architecture (Clean Separation):
//!   arch/idt.rs           reads raw scancode from port 0x60
//!   arch/interrupts/mod.rs exposes set_keyboard_hook(fn(u8))
//!   THIS FILE              translates scancode → ASCII, buffers result
//!   shell/readline         reads buffered ASCII via keyboard::read_byte()
//!
//! IRQ 1 (vector 33) fires on every key event (press + release).
//! Break codes = make code | 0x80 → we ignore them.
//! Special keys (Shift) update modifier state but produce no ASCII.

use crate::libs::collections::ring_buffer::RingBuffer;
use crate::kernel::sync::spinlock::SpinLock;

// ── Scancode → ASCII tables (PS/2 Set 1) ─────────────────────────────────────

/// Lowercase / no-modifier map.  Index = scancode (0x00–0x39).
const MAP_LOWER: [u8; 58] = [
    0,      // 0x00 — unused
    0x1B,   // 0x01 — Escape
    b'1',   // 0x02
    b'2',   // 0x03
    b'3',   // 0x04
    b'4',   // 0x05
    b'5',   // 0x06
    b'6',   // 0x07
    b'7',   // 0x08
    b'8',   // 0x09
    b'9',   // 0x0A
    b'0',   // 0x0B
    b'-',   // 0x0C
    b'=',   // 0x0D
    0x08,   // 0x0E — Backspace
    b'\t',  // 0x0F — Tab
    b'q',   // 0x10
    b'w',   // 0x11
    b'e',   // 0x12
    b'r',   // 0x13
    b't',   // 0x14
    b'y',   // 0x15
    b'u',   // 0x16
    b'i',   // 0x17
    b'o',   // 0x18
    b'p',   // 0x19
    b'[',   // 0x1A
    b']',   // 0x1B
    b'\n',  // 0x1C — Enter
    0,      // 0x1D — Left Ctrl
    b'a',   // 0x1E
    b's',   // 0x1F
    b'd',   // 0x20
    b'f',   // 0x21
    b'g',   // 0x22
    b'h',   // 0x23
    b'j',   // 0x24
    b'k',   // 0x25
    b'l',   // 0x26
    b';',   // 0x27
    b'\'',  // 0x28
    b'`',   // 0x29
    0,      // 0x2A — Left Shift  (modifier, not a character)
    b'\\',  // 0x2B
    b'z',   // 0x2C
    b'x',   // 0x2D
    b'c',   // 0x2E
    b'v',   // 0x2F
    b'b',   // 0x30
    b'n',   // 0x31
    b'm',   // 0x32
    b',',   // 0x33
    b'.',   // 0x34
    b'/',   // 0x35
    0,      // 0x36 — Right Shift (modifier)
    b'*',   // 0x37 — Numpad *
    0,      // 0x38 — Left Alt
    b' ',   // 0x39 — Space
];

/// Uppercase / Shift map.  Same indices as MAP_LOWER.
const MAP_UPPER: [u8; 58] = [
    0,      // 0x00
    0x1B,   // 0x01 — Escape
    b'!',   // 0x02
    b'@',   // 0x03
    b'#',   // 0x04
    b'$',   // 0x05
    b'%',   // 0x06
    b'^',   // 0x07
    b'&',   // 0x08
    b'*',   // 0x09
    b'(',   // 0x0A
    b')',   // 0x0B
    b'_',   // 0x0C
    b'+',   // 0x0D
    0x08,   // 0x0E — Backspace
    b'\t',  // 0x0F — Tab
    b'Q',   // 0x10
    b'W',   // 0x11
    b'E',   // 0x12
    b'R',   // 0x13
    b'T',   // 0x14
    b'Y',   // 0x15
    b'U',   // 0x16
    b'I',   // 0x17
    b'O',   // 0x18
    b'P',   // 0x19
    b'{',   // 0x1A
    b'}',   // 0x1B
    b'\n',  // 0x1C — Enter
    0,      // 0x1D — Ctrl
    b'A',   // 0x1E
    b'S',   // 0x1F
    b'D',   // 0x20
    b'F',   // 0x21
    b'G',   // 0x22
    b'H',   // 0x23
    b'J',   // 0x24
    b'K',   // 0x25
    b'L',   // 0x26
    b':',   // 0x27
    b'"',   // 0x28
    b'~',   // 0x29
    0,      // 0x2A — Shift
    b'|',   // 0x2B
    b'Z',   // 0x2C
    b'X',   // 0x2D
    b'C',   // 0x2E
    b'V',   // 0x2F
    b'B',   // 0x30
    b'N',   // 0x31
    b'M',   // 0x32
    b'<',   // 0x33
    b'>',   // 0x34
    b'?',   // 0x35
    0,      // 0x36 — Shift
    b'*',   // 0x37
    0,      // 0x38 — Alt
    b' ',   // 0x39 — Space
];

// Scancode constants for modifier keys
const SC_LSHIFT: u8 = 0x2A;
const SC_RSHIFT: u8 = 0x36;
const SC_BREAK:  u8 = 0x80; // bit 7 set = key release

// ── Keyboard state ────────────────────────────────────────────────────────────

/// ASCII buffer: up to 256 pending keystrokes.
static mut KEY_BUF: RingBuffer<256> = RingBuffer::new();
static mut SHIFT:   bool            = false;
static     KBD_LOCK: SpinLock       = SpinLock::new();

// ── Public API ────────────────────────────────────────────────────────────────

/// Initialize internal keyboard state.
///
/// Wiring note (Clean Architecture):
///   Drivers cannot import arch, so main.rs is responsible for:
///     `arch::set_keyboard_hook(drivers::char::keyboard::on_irq)`
///     `arch::unmask_irq(1)`
///   This function only resets buffer state.
pub fn init() {
    KBD_LOCK.lock();
    unsafe { KEY_BUF = RingBuffer::new(); SHIFT = false; }
    KBD_LOCK.unlock();
}

/// Non-blocking read: returns the next ASCII byte from the key buffer, or None.
pub fn read_byte() -> Option<u8> {
    KBD_LOCK.lock();
    let result = unsafe { KEY_BUF.pop() };
    KBD_LOCK.unlock();
    result
}

/// Called by the arch IRQ1 handler with the raw PS/2 scancode byte.
/// This is the boundary between arch (hardware) and driver (software).
pub fn on_irq(scancode: u8) {
    // Bit 7 = break code (key release)
    let is_release = (scancode & SC_BREAK) != 0;
    let make       = scancode & !SC_BREAK; // strip break bit

    // Update modifier state
    if make == SC_LSHIFT || make == SC_RSHIFT {
        unsafe { SHIFT = !is_release; }
        return;
    }

    // Ignore key releases for all other keys
    if is_release { return; }

    // Translate make code → ASCII
    let ascii = translate(make);
    if ascii == 0 { return; } // non-printable / unmapped

    KBD_LOCK.lock();
    unsafe { KEY_BUF.push(ascii); }
    KBD_LOCK.unlock();
}

// ── Internal ──────────────────────────────────────────────────────────────────

fn translate(make: u8) -> u8 {
    let idx = make as usize;
    if idx >= MAP_LOWER.len() { return 0; }
    unsafe {
        if SHIFT { MAP_UPPER[idx] } else { MAP_LOWER[idx] }
    }
}
