//! `htop` — full-screen interactive process and system monitor.
//!
//! Layout (80×25 VGA):
//!   Row  0    : title bar  — name, hostname, tasks, uptime
//!   Row  1    : CPU meter  — colored bar + percentage
//!   Row  2    : Mem meter  — colored bar + used/total
//!   Row  3    : Swp meter  — always 0 (FastROS has no swap)
//!   Row  4    : column header
//!   Rows 5–22 : process list (18 rows, scrollable, selectable)
//!   Row  23   : status / help hints
//!   Row  24   : F-key bar
//!
//! Keys:
//!   Up / Down / PgUp / PgDn / Home / End — navigate process list
//!   F6 / s                               — cycle sort column
//!   F9 / k                               — kill selected process (SIGKILL)
//!   F10 / q / Esc                        — quit

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;
use crate::kernel::process::{PROCESS_TABLE, PROCESS_USED, MAX_PROCESSES};
use crate::kernel::process::process::ProcessState;
use crate::kernel::memory::pmm;
use crate::drivers::char::keyboard::{
    KEY_UP, KEY_DOWN, KEY_PGUP, KEY_PGDN, KEY_HOME, KEY_END,
    KEY_F6, KEY_F9, KEY_F10,
};

// ── Screen geometry ───────────────────────────────────────────────────────────

const PROC_ROW0:   u16 = 5;        // first row of process list (always row 5)
const REFRESH_TKS: u64 = 100;      // 1 second at 100 Hz

// Fixed rows above the process list: title(1)+cpu(1)+mem(1)+swp(1)+hdr(1) = 5
// Fixed rows below: status(1)+fkeys(1) = 2  →  total overhead = 7
fn calc_proc_rows(term_rows: u16) -> usize {
    (term_rows as usize).saturating_sub(7).max(1)
}

// ── Color palette (VGA attribute byte: HIGH-nibble=bg, LOW-nibble=fg) ─────────
// ANSI mapping: bg nibble → 40+vga_ansi[n] (normal) or 100+vga_ansi[n] (bright)
//               fg nibble → 30+vga_ansi[n] (normal) or  90+vga_ansi[n] (bright)
// VGA_TO_ANSI: [0,4,2,6,1,5,3,7]  (Black→0, Blue→4, Green→2, Cyan→6, ...)

// For solid-block meter bars (space char), only the BACKGROUND color matters.
// bg nibbles used:  0=Black(40)  2=Green(42)  1=Blue(44)  8=DkGray(100)
//                   A=BrGreen(102) 9=BrBlue(104) C=BrRed(101)

const CLR_TITLE:    u8 = 0x1F; // bg=Blue(44)    fg=BrWhite(97)  — title bar
const CLR_UPTIME:   u8 = 0x1B; // bg=Blue(44)    fg=BrCyan(96)   — uptime
const CLR_MTR_LBL:  u8 = 0x0F; // bg=Black(40)   fg=BrWhite(97)  — "CPU[" label
const CLR_MTR_BG:   u8 = 0x80; // bg=DkGray(100) fg=Black(30)    — empty meter slot
const CLR_CPU_USED: u8 = 0xA0; // bg=BrGreen(102) fg=Black(30)   — CPU bar (bright green)
const CLR_MEM_USED: u8 = 0x90; // bg=BrBlue(104)  fg=Black(30)   — Mem bar (bright blue)
const CLR_SWP_USED: u8 = 0xC0; // bg=BrRed(101)   fg=Black(30)   — Swap (unused)
const CLR_COL_HDR:  u8 = 0x30; // bg=Cyan(46)    fg=Black(30)    — column header
const CLR_DEFAULT:  u8 = 0x07; // bg=Black(40)   fg=Gray(37)     — normal process row
const CLR_RUNNING:  u8 = 0x0A; // bg=Black(40)   fg=BrGreen(92)  — running process
const CLR_ZOMBIE:   u8 = 0x0C; // bg=Black(40)   fg=BrRed(91)    — zombie
const CLR_SELECTED: u8 = 0x70; // bg=Gray(47)    fg=Black(30)    — selected row
const CLR_STATUS:   u8 = 0x1F; // bg=Blue(44)    fg=BrWhite(97)  — status bar
const CLR_FK_NUM:   u8 = 0x0E; // bg=Black(40)   fg=BrYellow(93) — F-key number
const CLR_FK_LBL:   u8 = 0x1F; // bg=Blue(44)    fg=BrWhite(97)  — F-key label
const CLR_HILITE:   u8 = 0x0B; // bg=Black(40)   fg=BrCyan(96)   — highlighted value

// ── Sort key ─────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum SortKey { Pid, CpuPct, MemPct }

impl SortKey {
    fn next(self) -> Self {
        match self { Self::Pid => Self::CpuPct, Self::CpuPct => Self::MemPct, Self::MemPct => Self::Pid }
    }
    fn label(self) -> &'static [u8] {
        match self { Self::Pid => b"PID", Self::CpuPct => b"CPU%", Self::MemPct => b"MEM%" }
    }
}

// ── Process snapshot ─────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct ProcSnap {
    pid:         u32,
    ppid:        u32,
    state_char:  u8,    // b'R', b'S', b'Z', b'I'
    virt_kb:     u32,   // VIRT in KiB
    res_kb:      u32,   // RES  in KiB
    cpu_x10:     u32,   // CPU%  × 10  (e.g. 15 → "1.5%")
    mem_x10:     u32,   // MEM%  × 10
    time_ticks:  u64,   // ticks this process has been scheduled
    name:        [u8; 16],
    name_len:    usize,
}

impl ProcSnap {
    fn empty() -> Self {
        Self { pid: 0, ppid: 0, state_char: b'I', virt_kb: 0, res_kb: 0,
               cpu_x10: 0, mem_x10: 0, time_ticks: 0, name: [0u8; 16], name_len: 0 }
    }
    fn set_name(&mut self, s: &[u8]) {
        let n = s.len().min(16);
        self.name[..n].copy_from_slice(&s[..n]);
        self.name_len = n;
    }
    fn name_bytes(&self) -> &[u8] { &self.name[..self.name_len] }
}

// ── Main command ──────────────────────────────────────────────────────────────

pub struct HtopCommand;
pub static HTOP: HtopCommand = HtopCommand;

impl Command for HtopCommand {
    fn name(&self) -> &'static str { "htop" }
    fn description(&self) -> &'static str { "Interactive process viewer (q/F10 to quit)" }

    fn execute(&self, _args: &[&[u8]], _env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        let mut scroll:    usize    = 0;
        let mut selected:  usize    = 0;
        let mut sort:      SortKey  = SortKey::Pid;
        let mut last_tick: u64      = tick();
        let mut idle_cnt:  u32      = 0;
        let mut cpu_pct:   u32      = 0;

        io.enter_altscreen();
        io.clear_screen();

        loop {
            let now        = tick();
            let elapsed    = now.wrapping_sub(last_tick);
            let term_rows  = io.screen_rows();
            let term_cols  = io.screen_cols() as usize;
            let proc_rows  = calc_proc_rows(term_rows);

            if elapsed >= REFRESH_TKS {
                let active = elapsed.saturating_sub(idle_cnt as u64);
                cpu_pct   = (active * 1000 / elapsed.max(1)) as u32;
                idle_cnt  = 0;
                last_tick = now;

                let procs = collect_procs(cpu_pct, now);
                selected = selected.min(procs.count.saturating_sub(1));
                scroll   = scroll.min(procs.count.saturating_sub(1));

                redraw(io, &procs, scroll, selected, sort, cpu_pct, now, term_rows, term_cols);
            }

            match io.read_byte() {
                None => {
                    idle_cnt += 1;
                    unsafe { core::arch::asm!("hlt", options(nomem, nostack)); }
                }
                Some(key) => {
                    let procs = collect_procs(cpu_pct, tick());
                    let total = procs.count;
                    match key {
                        b'q' | KEY_F10 | 0x1B | 0x03 => break, // q/F10/Esc/Ctrl-C

                        KEY_UP => {
                            if selected > 0 { selected -= 1; }
                            if selected < scroll { scroll = selected; }
                        }
                        KEY_DOWN => {
                            if selected + 1 < total { selected += 1; }
                            if selected >= scroll + proc_rows { scroll = selected + 1 - proc_rows; }
                        }
                        KEY_PGUP => {
                            selected = selected.saturating_sub(proc_rows);
                            scroll   = scroll.saturating_sub(proc_rows);
                        }
                        KEY_PGDN => {
                            selected = (selected + proc_rows).min(total.saturating_sub(1));
                            if selected >= scroll + proc_rows { scroll = selected + 1 - proc_rows; }
                        }
                        KEY_HOME => { selected = 0; scroll = 0; }
                        KEY_END  => {
                            selected = total.saturating_sub(1);
                            scroll   = total.saturating_sub(proc_rows);
                        }

                        KEY_F6 | b's' | b'S' => { sort = sort.next(); }

                        KEY_F9 | b'k' | b'K' => {
                            if total > 0 && kill_selected(io, &procs, selected) {
                                break;
                            }
                        }
                        _ => { continue; }
                    }

                    let procs2 = collect_procs(cpu_pct, tick());
                    redraw(io, &procs2, scroll, selected, sort, cpu_pct, tick(), term_rows, term_cols);
                }
            }
        }

        io.clear_screen();
        io.exit_altscreen();
        0
    }
}

// ── Process collection ────────────────────────────────────────────────────────

struct SnapList {
    items: [ProcSnap; 67], // 64 real + 3 synthetic
    count: usize,
}

impl SnapList {
    fn empty() -> Self { Self { items: [ProcSnap::empty(); 67], count: 0 } }
    fn push(&mut self, s: ProcSnap) {
        if self.count < 67 { self.items[self.count] = s; self.count += 1; }
    }
    fn get(&self, i: usize) -> &ProcSnap { &self.items[i] }
}

fn collect_procs(cpu_pct: u32, _now: u64) -> SnapList {
    let total_frames = pmm::total_frame_count() as u64;
    let free_frames  = pmm::free_frame_count()  as u64;
    let used_frames  = total_frames.saturating_sub(free_frames);

    // Per-process RES in KiB = kstack (16 KiB for kernel threads)
    let kstack_kb = 16u32;
    let total_kb  = (total_frames * 4) as u32; // frames × 4 KiB

    let mem_pct_proc = if total_kb > 0 {
        (kstack_kb as u64 * 1000 / total_kb as u64) as u32
    } else { 0 };

    let _ = used_frames; // suppress unused warning

    let mut list = SnapList::empty();

    // ── Synthetic: kernel (PID 0) ──────────────────────────────────────────
    let mut k = ProcSnap::empty();
    k.pid        = 0;
    k.ppid       = 0;
    k.state_char = b'S';
    k.virt_kb    = 256;
    k.res_kb     = 256;
    k.cpu_x10    = 0;
    k.mem_x10    = (256u64 * 1000 / total_kb.max(1) as u64) as u32;
    k.time_ticks = tick();
    k.set_name(b"kernel");
    list.push(k);

    // ── Synthetic: shell (PID 1) ──────────────────────────────────────────
    let mut sh = ProcSnap::empty();
    sh.pid        = 1;
    sh.ppid       = 0;
    sh.state_char = b'S';
    sh.virt_kb    = kstack_kb;
    sh.res_kb     = kstack_kb;
    sh.cpu_x10    = 0;
    sh.mem_x10    = mem_pct_proc;
    sh.time_ticks = 0;
    sh.set_name(b"shell");
    list.push(sh);

    // ── Synthetic: htop itself (PID 2) ────────────────────────────────────
    let mut ht = ProcSnap::empty();
    ht.pid        = 2;
    ht.ppid       = 1;
    ht.state_char = b'R';
    ht.virt_kb    = kstack_kb;
    ht.res_kb     = kstack_kb;
    ht.cpu_x10    = cpu_pct.min(9999);
    ht.mem_x10    = mem_pct_proc;
    ht.time_ticks = tick();
    ht.set_name(b"htop");
    list.push(ht);

    // ── Real kernel threads from PROCESS_TABLE ────────────────────────────
    unsafe {
        for i in 0..MAX_PROCESSES {
            if !PROCESS_USED[i] { continue; }
            let p = PROCESS_TABLE[i].assume_init_ref();

            let sc = match p.state {
                ProcessState::Running => b'R',
                ProcessState::Ready   => b'S',
                ProcessState::Blocked => b'D',
                ProcessState::Zombie  => b'Z',
                ProcessState::Created => b'I',
            };

            let mut s = ProcSnap::empty();
            s.pid        = p.pid.0 + 3; // offset to avoid synthetic PID collision
            s.ppid       = p.ppid.0;
            s.state_char = sc;
            s.virt_kb    = kstack_kb;
            s.res_kb     = kstack_kb;
            s.cpu_x10    = if p.state == ProcessState::Running { 1000 } else { 0 };
            s.mem_x10    = mem_pct_proc;
            s.time_ticks = 0;
            // Name: "kthread/<i>"
            let mut name = [0u8; 16];
            let prefix = b"kthread/";
            name[..8].copy_from_slice(prefix);
            let dn = fmt_u32_into(&mut name[8..], i as u32);
            s.name_len = 8 + dn;
            s.name[..s.name_len].copy_from_slice(&name[..s.name_len]);
            list.push(s);
        }
    }

    list
}

// ── Kill selected process ─────────────────────────────────────────────────────

/// Returns true if htop should quit (i.e. htop killed itself).
fn kill_selected(io: &mut dyn ShellIo, procs: &SnapList, selected: usize) -> bool {
    if selected >= procs.count { return false; }
    let p = procs.get(selected);

    // Overlay dialog on rows 11-13
    let pid = p.pid;

    // Draw dialog box
    for r in 11u16..=13 {
        io.fill_row(r, b' ', 0x4F); // White on DarkRed
    }
    io.write_at(10, 11, b" Send SIGKILL to PID: ", 0x4F);
    let mut pid_buf = [0u8; 8];
    let pn = fmt_u32_into(&mut pid_buf, pid);
    io.write_at(32, 11, &pid_buf[..pn], 0x4F);

    io.write_at(10, 12, b" [Enter] Confirm        [Esc] Cancel  ", 0x4F);

    // Wait for input
    loop {
        let key = io.read_byte_blocking();
        match key {
            b'\n' | b'\r' => {
                // PID 2 = htop itself — quit
                if pid == 2 {
                    return true;
                }
                // PID 0 = kernel idle process — always protected (like swapper in Linux)
                if pid == 0 {
                    for r in 11u16..=13 {
                        io.fill_row(r, b' ', 0x4F);
                    }
                    io.write_at(10, 12, b"  Operation not permitted (kernel)  Press any key...  ", 0x4F);
                    io.read_byte_blocking();
                    return false;
                }
                // PID >= 3 = real kernel threads
                if pid >= 3 {
                    unsafe {
                        for i in 0..MAX_PROCESSES {
                            if !PROCESS_USED[i] { continue; }
                            let pr = PROCESS_TABLE[i].assume_init_mut();
                            if pr.pid.0 + 3 == pid {
                                pr.state = ProcessState::Zombie;
                                break;
                            }
                        }
                    }
                }
                return false;
            }
            0x1B => return false, // Esc = cancel
            _ => {}
        }
    }
}

// ── Full screen redraw ────────────────────────────────────────────────────────

fn redraw(
    io:        &mut dyn ShellIo,
    procs:     &SnapList,
    scroll:    usize,
    selected:  usize,
    sort:      SortKey,
    cpu_pct:   u32,
    now:       u64,
    term_rows: u16,
    term_cols: usize,
) {
    let proc_rows  = calc_proc_rows(term_rows);
    let status_row = term_rows.saturating_sub(2);
    let fkey_row   = term_rows.saturating_sub(1);

    draw_title(io, procs.count, now, term_cols);
    draw_cpu_meter(io, cpu_pct);
    draw_mem_meter(io);
    draw_swp_meter(io);
    draw_col_header(io, sort, term_cols);
    draw_proc_list(io, procs, scroll, selected, proc_rows);
    draw_status(io, procs, selected, status_row, term_cols);
    draw_fkeys(io, fkey_row, term_cols);

    io.move_cursor(0, PROC_ROW0 + (selected.saturating_sub(scroll)) as u16);
}

// ── Title bar (row 0) ─────────────────────────────────────────────────────────

fn draw_title(io: &mut dyn ShellIo, total: usize, now: u64, cols: usize) {
    io.fill_row(0, b' ', CLR_TITLE);

    io.write_at(0, 0, b"  FastROS htop 0.1 - fastros", CLR_TITLE);

    let mut buf = [0u8; 48];
    let mut p = 0usize;
    p += copy_bytes(&mut buf[p..], b"  Tasks: ");
    p += fmt_u32_into(&mut buf[p..], total as u32);
    io.write_at(32, 0, &buf[..p], CLR_TITLE);

    let s = now / 100;
    let m = s   / 60;
    let h = m   / 60;
    let mut ub = [0u8; 20];
    let mut up = 0usize;
    up += copy_bytes(&mut ub[up..], b"up ");
    up += fmt_u32_into(&mut ub[up..], h as u32);
    ub[up] = b':'; up += 1;
    up += fmt_u32_2d(&mut ub[up..], (m % 60) as u32);
    ub[up] = b':'; up += 1;
    up += fmt_u32_2d(&mut ub[up..], (s % 60) as u32);
    let col = cols.saturating_sub(up + 2) as u16;
    io.write_at(col, 0, &ub[..up], CLR_UPTIME);
}

// ── Meters ────────────────────────────────────────────────────────────────────

const METER_INNER: usize = 56; // width of bar between [ and ]
const METER_LBL_CPU: &[u8] = b" CPU[";
const METER_LBL_MEM: &[u8] = b" Mem[";
const METER_LBL_SWP: &[u8] = b" Swp[";

fn draw_meter(io: &mut dyn ShellIo, row: u16, label: &[u8], pct_x10: u32,
              clr_used: u8, suffix: &[u8]) {
    io.fill_row(row, b' ', CLR_DEFAULT);
    // Label
    io.write_at(0, row, label, CLR_MTR_LBL);
    let x0 = label.len() as u16;
    // Bar
    let filled = ((pct_x10 as usize) * METER_INNER / 1000).min(METER_INNER);
    let empty  = METER_INNER - filled;
    let bar_used = [b' '; METER_INNER];
    let bar_free = [b' '; METER_INNER];
    io.write_at(x0 as u16, row, &bar_used[..filled], clr_used);
    io.write_at(x0 + filled as u16, row, &bar_free[..empty], CLR_MTR_BG);
    // Closing bracket
    let cx = x0 + METER_INNER as u16;
    io.put_char_at(cx, row, b']', CLR_MTR_LBL);
    // Suffix (percentage / memory info)
    io.write_at(cx + 1, row, suffix, CLR_HILITE);
}

fn draw_cpu_meter(io: &mut dyn ShellIo, cpu_pct_x10: u32) {
    let mut suf = [0u8; 12];
    let n = fmt_pct_x10(&mut suf, cpu_pct_x10);
    suf[n] = b'%';
    draw_meter(io, 1, METER_LBL_CPU, cpu_pct_x10, CLR_CPU_USED, &suf[..n + 1]);
}

fn draw_mem_meter(io: &mut dyn ShellIo) {
    let total_kb = pmm::total_frame_count() as u64 * 4;
    let free_kb  = pmm::free_frame_count()  as u64 * 4;
    let used_kb  = total_kb.saturating_sub(free_kb);
    let pct_x10  = if total_kb > 0 { (used_kb * 1000 / total_kb) as u32 } else { 0 };

    let mut suf = [0u8; 24];
    let mut n = 0;
    n += fmt_mem_kb(&mut suf[n..], used_kb);
    suf[n] = b'/'; n += 1;
    n += fmt_mem_kb(&mut suf[n..], total_kb);
    draw_meter(io, 2, METER_LBL_MEM, pct_x10, CLR_MEM_USED, &suf[..n]);
}

fn draw_swp_meter(io: &mut dyn ShellIo) {
    draw_meter(io, 3, METER_LBL_SWP, 0, CLR_SWP_USED, b"0K/0K");
}

// ── Column header (row 4) ─────────────────────────────────────────────────────

fn draw_col_header(io: &mut dyn ShellIo, sort: SortKey, _cols: usize) {
    io.fill_row(4, b' ', CLR_COL_HDR);
    //         PID  USER      PRI  NI  VIRT   RES   S  CPU%  MEM%  TIME+   Command
    io.write_at(0, 4,
        b"  PID USER     PRI  NI   VIRT    RES S  CPU%  MEM%    TIME+  Command        ",
        CLR_COL_HDR);

    // Highlight the active sort column
    let (col, label) = match sort {
        SortKey::Pid    => (2u16,  b"PID " as &[u8]),
        SortKey::CpuPct => (39u16, b"CPU%" as &[u8]),
        SortKey::MemPct => (45u16, b"MEM%" as &[u8]),
    };
    io.write_at(col, 4, label, 0x3E); // Yellow on DarkCyan
}

// ── Process list (rows 5–22) ──────────────────────────────────────────────────

fn draw_proc_list(io: &mut dyn ShellIo, procs: &SnapList, scroll: usize, selected: usize, proc_rows: usize) {
    for r in 0..proc_rows {
        let screen_row = (PROC_ROW0 as usize + r) as u16;
        let proc_idx   = scroll + r;

        if proc_idx >= procs.count {
            io.fill_row(screen_row, b' ', CLR_DEFAULT);
            continue;
        }

        let p   = procs.get(proc_idx);
        let clr = if proc_idx == selected {
            CLR_SELECTED
        } else {
            match p.state_char {
                b'R' => CLR_RUNNING,
                b'Z' => CLR_ZOMBIE,
                _    => CLR_DEFAULT,
            }
        };

        // Clear the row
        io.fill_row(screen_row, b' ', clr);

        // ── PID (cols 2–5, right-aligned 4 digits) ────────────────────────
        let mut buf4 = [b' '; 4];
        let np = fmt_u32_into(&mut buf4, p.pid);
        let off = 4usize.saturating_sub(np);
        // shift right
        let mut pid_str = [b' '; 4];
        pid_str[off..].copy_from_slice(&buf4[..np]);
        io.write_at(2, screen_row, &pid_str, clr);

        // ── USER (cols 6–13, left-aligned) ────────────────────────────────
        io.write_at(7, screen_row, b"root    ", clr);

        // ── PRI (cols 15–17) ──────────────────────────────────────────────
        io.write_at(15, screen_row, b" 20", clr);

        // ── NI  (cols 19–21) ──────────────────────────────────────────────
        io.write_at(19, screen_row, b"  0", clr);

        // ── VIRT (cols 23–28) ─────────────────────────────────────────────
        let mut vm = [b' '; 6];
        let nv = fmt_mem_field(&mut vm, p.virt_kb as u64);
        io.write_at(23, screen_row, &vm[..6], clr);
        let _ = nv;

        // ── RES  (cols 30–35) ─────────────────────────────────────────────
        let mut rm = [b' '; 6];
        let _nr = fmt_mem_field(&mut rm, p.res_kb as u64);
        io.write_at(30, screen_row, &rm[..6], clr);

        // ── State (col 37) ────────────────────────────────────────────────
        io.put_char_at(37, screen_row, p.state_char, clr);

        // ── CPU% (cols 39–43, "NNN.N") ────────────────────────────────────
        let mut cp = [b' '; 5];
        let nc = fmt_pct_x10(&mut cp, p.cpu_x10);
        let coff = 5usize.saturating_sub(nc);
        let mut cpu_str = [b' '; 5];
        cpu_str[coff..].copy_from_slice(&cp[..nc]);
        io.write_at(39, screen_row, &cpu_str, clr);

        // ── MEM% (cols 45–49) ─────────────────────────────────────────────
        let mut mp = [b' '; 5];
        let nm = fmt_pct_x10(&mut mp, p.mem_x10);
        let moff = 5usize.saturating_sub(nm);
        let mut mem_str = [b' '; 5];
        mem_str[moff..].copy_from_slice(&mp[..nm]);
        io.write_at(45, screen_row, &mem_str, clr);

        // ── TIME+ (cols 51–59, "H:MM:SS.cc") ─────────────────────────────
        let mut ts = [b'0'; 10];
        let ticks = p.time_ticks;
        let cs  = ticks % 100;
        let ss  = (ticks / 100) % 60;
        let mm  = (ticks / 6000) % 60;
        let hh  = ticks / 360000;
        let mut tp = 0usize;
        tp += fmt_u32_into(&mut ts[tp..], hh as u32);
        ts[tp] = b':'; tp += 1;
        tp += fmt_u32_2d(&mut ts[tp..], mm as u32);
        ts[tp] = b':'; tp += 1;
        tp += fmt_u32_2d(&mut ts[tp..], ss as u32);
        ts[tp] = b'.'; tp += 1;
        tp += fmt_u32_2d(&mut ts[tp..], cs as u32);
        let toff = 10usize.saturating_sub(tp);
        let mut time_str = [b' '; 10];
        time_str[toff..].copy_from_slice(&ts[..tp]);
        io.write_at(51, screen_row, &time_str, clr);

        // ── Command (cols 61–79, max 18 chars) ────────────────────────────
        let name = p.name_bytes();
        let nn   = name.len().min(18);
        io.write_at(62, screen_row, &name[..nn], clr);
    }
}

// ── Status bar (row 23) ───────────────────────────────────────────────────────

fn draw_status(io: &mut dyn ShellIo, procs: &SnapList, selected: usize, status_row: u16, cols: usize) {
    io.fill_row(status_row, b' ', CLR_STATUS);

    if selected < procs.count {
        let p = procs.get(selected);
        let mut buf = [0u8; 60];
        let mut n = 0usize;
        n += copy_bytes(&mut buf[n..], b" Selected: PID ");
        n += fmt_u32_into(&mut buf[n..], p.pid);
        n += copy_bytes(&mut buf[n..], b" (");
        let nm = p.name_bytes().len().min(12);
        buf[n..n + nm].copy_from_slice(&p.name_bytes()[..nm]);
        n += nm;
        n += copy_bytes(&mut buf[n..], b")");
        io.write_at(0, status_row, &buf[..n], CLR_STATUS);
    }

    let hint = b"  [Up/Down] navigate  [s/F6] sort  [k/F9] kill  [q/F10/Ctrl-C] quit";
    let hlen = hint.len().min(cols);
    let hcol = cols.saturating_sub(hlen) as u16;
    io.write_at(hcol, status_row, &hint[..hlen], CLR_STATUS);
}

// ── F-key bar (row 24) ────────────────────────────────────────────────────────

const FKEYS: &[(&[u8], &[u8])] = &[
    (b"F1",  b"Help   "),
    (b"F2",  b"Setup  "),
    (b"F3",  b"Search "),
    (b"F4",  b"Filter "),
    (b"F5",  b"Tree   "),
    (b"F6",  b"SortBy "),
    (b"F7",  b"Nice-  "),
    (b"F8",  b"Nice+  "),
    (b"F9",  b"Kill   "),
    (b"F10", b"Quit"),
];

fn draw_fkeys(io: &mut dyn ShellIo, fkey_row: u16, cols: usize) {
    io.fill_row(fkey_row, b' ', CLR_STATUS);
    let mut col = 0u16;
    for (num, lbl) in FKEYS {
        if col as usize >= cols { break; }
        io.write_at(col, fkey_row, num, CLR_FK_NUM);
        col += num.len() as u16;
        io.write_at(col, fkey_row, lbl, CLR_STATUS);
        col += lbl.len() as u16;
    }
}

// ── Number formatting helpers ─────────────────────────────────────────────────

fn tick() -> u64 {
    crate::arch::x86_64::cpu::timer::ticks()
}

/// Write `n` into `buf` in decimal. Returns number of bytes written.
fn fmt_u32_into(buf: &mut [u8], mut n: u32) -> usize {
    if buf.is_empty() { return 0; }
    if n == 0 { buf[0] = b'0'; return 1; }
    let mut tmp = [0u8; 10];
    let mut len = 0usize;
    while n > 0 { tmp[len] = b'0' + (n % 10) as u8; n /= 10; len += 1; }
    let out = len.min(buf.len());
    for i in 0..out { buf[i] = tmp[len - 1 - i]; }
    out
}

/// Write 2-digit zero-padded number. Always 2 bytes.
fn fmt_u32_2d(buf: &mut [u8], n: u32) -> usize {
    if buf.len() < 2 { return 0; }
    buf[0] = b'0' + ((n / 10) % 10) as u8;
    buf[1] = b'0' + (n % 10) as u8;
    2
}

/// Write "NNN.N" for a value given as integer × 10.
/// Returns bytes written.
fn fmt_pct_x10(buf: &mut [u8], v: u32) -> usize {
    let int_part = v / 10;
    let frac     = v % 10;
    let mut tmp  = [0u8; 8];
    let ni = fmt_u32_into(&mut tmp, int_part);
    tmp[ni]     = b'.';
    tmp[ni + 1] = b'0' + frac as u8;
    let total = ni + 2;
    let n = total.min(buf.len());
    buf[..n].copy_from_slice(&tmp[..n]);
    n
}

/// Format KiB value into 6-char right-aligned field (e.g. " 16.0K", "252.0M").
fn fmt_mem_field(buf: &mut [u8; 6], kb: u64) -> usize {
    let (val_x10, unit) = if kb < 1000 {
        (kb * 10, b'K')
    } else if kb < 1_000_000 {
        (kb * 10 / 1024, b'M')
    } else {
        (kb * 10 / (1024 * 1024), b'G')
    };
    let int_p = val_x10 / 10;
    let fra_p = val_x10 % 10;
    let mut tmp = [0u8; 8];
    let ni = fmt_u32_into(&mut tmp, int_p as u32);
    tmp[ni]     = b'.';
    tmp[ni + 1] = fra_p as u8 + b'0';
    tmp[ni + 2] = unit;
    let total = ni + 3;
    // right-align into 6 chars
    let spaces = 6usize.saturating_sub(total);
    for i in 0..6 { buf[i] = b' '; }
    if total <= 6 {
        buf[spaces..spaces + total].copy_from_slice(&tmp[..total]);
    }
    total
}

/// Format KiB into human-readable string (returns bytes written).
fn fmt_mem_kb(buf: &mut [u8], kb: u64) -> usize {
    if kb == 0 { buf[0] = b'0'; buf[1] = b'K'; return 2; }
    if kb < 1024 {
        let n = fmt_u32_into(buf, kb as u32);
        if n < buf.len() { buf[n] = b'K'; return n + 1; }
        return n;
    }
    let mb = kb / 1024;
    let fm = (kb % 1024) * 10 / 1024;
    let n  = fmt_u32_into(buf, mb as u32);
    if n + 3 <= buf.len() {
        buf[n]     = b'.';
        buf[n + 1] = b'0' + fm as u8;
        buf[n + 2] = b'M';
        return n + 3;
    }
    n
}

fn copy_bytes(dst: &mut [u8], src: &[u8]) -> usize {
    let n = src.len().min(dst.len());
    dst[..n].copy_from_slice(&src[..n]);
    n
}
