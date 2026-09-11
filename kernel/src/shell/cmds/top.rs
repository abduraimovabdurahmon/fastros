//! `top` (procps-ng layout, interactive and batch) and `htop` (meters,
//! colours, tree view, search, filter, sort and signal panels).
//!
//! Both sample `/proc` like their Linux originals: CPU percentages are the
//! tick deltas between two samples over the elapsed wall time.

use super::fmtutil::NameCache;
use super::procinfo::{self as pi, CpuTimes, LoadAvg, MemInfo, ProcEntry, SysStat, HZ};
use crate::proc::signal;
use crate::shell::ctx::{parse_opts, Ctx, OptSpec};
use crate::shell::tui::{self, Key, Screen, Terminal};
use crate::time::civil;
use crate::outln;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// One sampling of the system.
struct Sample {
    at_ns: u64,
    cpu: CpuTimes,
    procs: Vec<ProcEntry>,
}

impl Sample {
    fn take(ctx: &Ctx) -> Sample {
        let fs = ctx.fs();
        Sample { at_ns: crate::time::now_ns(), cpu: SysStat::read(&fs).cpu, procs: pi::list(&fs) }
    }
}

/// A process with its CPU share (tenths of a percent) between two samples.
#[derive(Clone)]
struct Row {
    p: ProcEntry,
    cpu: u64,
    mem: u64,
}

fn rows(prev: &Sample, cur: &Sample, mem_total_kb: u64) -> Vec<Row> {
    let before: BTreeMap<u32, u64> = prev.procs.iter().map(|p| (p.pid, p.cpu_ticks())).collect();
    let elapsed_ticks = ((cur.at_ns.saturating_sub(prev.at_ns)) * HZ / 1_000_000_000).max(1);
    cur.procs
        .iter()
        .map(|p| {
            let d = p.cpu_ticks().saturating_sub(before.get(&p.pid).copied().unwrap_or(0));
            Row { p: p.clone(), cpu: (d * 1000 / elapsed_ticks).min(1000), mem: p.rss_kb() * 1000 / mem_total_kb.max(1) }
        })
        .collect()
}

fn tenths(v: u64) -> String {
    alloc::format!("{}.{}", v / 10, v % 10)
}

/// `%4.1f` of part/total as a percentage.
fn pct(part: u64, total: u64) -> String {
    let t = if total == 0 { 0 } else { part * 1000 / total };
    alloc::format!("{:>4}", tenths(t))
}

/// `%8.1f` MiB from KiB.
fn mib(kb: u64) -> String {
    let t = kb * 10 / 1024;
    alloc::format!("{:>8}", tenths(t))
}

fn clock(now: u64) -> String {
    let t = civil::from_unix(now as i64);
    alloc::format!("{:02}:{:02}:{:02}", t.hour, t.min, t.sec)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SortBy {
    Cpu,
    Mem,
    Time,
    Pid,
    User,
    Command,
    State,
    Pri,
    Virt,
    Res,
}

impl SortBy {
    const ALL: [SortBy; 10] = [SortBy::Pid, SortBy::User, SortBy::Pri, SortBy::Virt, SortBy::Res, SortBy::State, SortBy::Cpu, SortBy::Mem, SortBy::Time, SortBy::Command];
    fn name(self) -> &'static str {
        match self {
            SortBy::Cpu => "PERCENT_CPU",
            SortBy::Mem => "PERCENT_MEM",
            SortBy::Time => "TIME",
            SortBy::Pid => "PID",
            SortBy::User => "USER",
            SortBy::Command => "Command",
            SortBy::State => "STATE",
            SortBy::Pri => "PRIORITY",
            SortBy::Virt => "M_VIRT",
            SortBy::Res => "M_RESIDENT",
        }
    }
    /// Descending by default for the "bigger is interesting" columns.
    fn descending(self) -> bool {
        matches!(self, SortBy::Cpu | SortBy::Mem | SortBy::Time | SortBy::Virt | SortBy::Res)
    }
    fn from_top_field(s: &str) -> Option<SortBy> {
        Some(match s.to_ascii_uppercase().as_str() {
            "%CPU" | "CPU" => SortBy::Cpu,
            "%MEM" | "MEM" => SortBy::Mem,
            "TIME+" | "TIME" => SortBy::Time,
            "PID" => SortBy::Pid,
            "USER" => SortBy::User,
            "COMMAND" => SortBy::Command,
            "S" => SortBy::State,
            "PR" | "PRI" => SortBy::Pri,
            "VIRT" => SortBy::Virt,
            "RES" => SortBy::Res,
            _ => return None,
        })
    }
}

fn sort_rows(v: &mut [Row], by: SortBy, reverse: bool, names: &NameCache) {
    v.sort_by(|a, b| {
        let o = match by {
            SortBy::Cpu => a.cpu.cmp(&b.cpu).then(a.p.cpu_ticks().cmp(&b.p.cpu_ticks())),
            SortBy::Mem | SortBy::Res => a.p.rss_pages.cmp(&b.p.rss_pages),
            SortBy::Virt => a.p.vsize.cmp(&b.p.vsize),
            SortBy::Time => a.p.cpu_ticks().cmp(&b.p.cpu_ticks()),
            SortBy::Pid => a.p.pid.cmp(&b.p.pid),
            SortBy::User => names.user(a.p.uid).cmp(&names.user(b.p.uid)),
            SortBy::Command => a.p.comm.cmp(&b.p.comm),
            SortBy::State => a.p.state.cmp(&b.p.state),
            SortBy::Pri => a.p.priority.cmp(&b.p.priority),
        };
        let o = if by.descending() { o.reverse() } else { o };
        let o = if reverse { o.reverse() } else { o };
        o.then(a.p.pid.cmp(&b.p.pid))
    });
}

fn task_counts(procs: &[ProcEntry]) -> (usize, usize, usize, usize, usize) {
    let mut r = (procs.len(), 0, 0, 0, 0);
    for p in procs {
        match p.state {
            'R' => r.1 += 1,
            'T' | 't' => r.3 += 1,
            'Z' => r.4 += 1,
            _ => r.2 += 1,
        }
    }
    r
}

// ── top ────────────────────────────────────────────────────────────────────

struct TopState {
    sort: SortBy,
    reverse: bool,
    full_cmd: bool,
    hide_idle: bool,
    user: Option<u32>,
    pids: Vec<u32>,
    delay_ms: u64,
    scroll: usize,
    message: String,
}

fn top_summary(ctx: &Ctx, prev: &Sample, cur: &Sample, mem: &MemInfo) -> Vec<String> {
    let fs = ctx.fs();
    let up = pi::uptime_centis(&fs) / 100;
    let users = crate::utmp::sessions().len();
    let load = LoadAvg::read(&fs);
    let (total, running, sleeping, stopped, zombie) = task_counts(&cur.procs);
    let d = cur.cpu.since(&prev.cpu);
    let t = d.total().max(1);
    let swap_used = mem.swap_total().saturating_sub(mem.swap_free());
    alloc::vec![
        alloc::format!("top - {} {},  {} user{},  load average: {}", clock(crate::time::unix_now()), pi::fmt_uptime(up), users, if users == 1 { "" } else { "s" }, load.text(", ")),
        alloc::format!("Tasks: {:>3} total, {:>3} running, {:>3} sleeping, {:>3} stopped, {:>3} zombie", total, running, sleeping, stopped, zombie),
        alloc::format!(
            "%Cpu(s): {} us, {} sy, {} ni, {} id, {} wa, {} hi, {} si, {} st",
            pct(d.user, t),
            pct(d.system, t),
            pct(d.nice, t),
            pct(d.idle, t),
            pct(d.iowait, t),
            pct(d.irq, t),
            pct(d.softirq, t),
            pct(d.steal, t)
        ),
        alloc::format!("MiB Mem : {} total, {} free, {} used, {} buff/cache", mib(mem.total()), mib(mem.free()), mib(mem.used()), mib(mem.buffers() + mem.cache())),
        alloc::format!("MiB Swap: {} total, {} free, {} used. {} avail Mem", mib(mem.swap_total()), mib(mem.swap_free()), mib(swap_used), mib(mem.available())),
    ]
}

const TOP_HEADER: &str = "    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND";

fn top_row(r: &Row, names: &NameCache, full: bool) -> String {
    let p = &r.p;
    let cmd = if full { p.args() } else { p.comm.clone() };
    alloc::format!(
        "{:>7} {:<8} {:>3} {:>3} {:>7} {:>6} {:>6} {} {:>5} {:>5} {:>9} {}",
        p.pid,
        pi::fit_name(&names.user(p.uid), 8),
        p.priority,
        p.nice,
        p.vsize / 1024,
        p.rss_kb(),
        0,
        p.state,
        tenths(r.cpu),
        tenths(r.mem),
        pi::fmt_time_plus(p.cpu_ticks()),
        cmd
    )
}

fn top_select(st: &TopState, rows: Vec<Row>, names: &NameCache) -> Vec<Row> {
    let mut v: Vec<Row> = rows
        .into_iter()
        .filter(|r| st.user.is_none_or(|u| r.p.uid == u))
        .filter(|r| st.pids.is_empty() || st.pids.contains(&r.p.pid))
        .filter(|r| !st.hide_idle || r.cpu > 0 || r.p.state == 'R')
        .collect();
    sort_rows(&mut v, st.sort, st.reverse, names);
    v
}

fn top_parse_delay(s: &str) -> Option<u64> {
    let (i, f) = s.split_once('.').unwrap_or((s, ""));
    let i: u64 = if i.is_empty() { 0 } else { i.parse().ok()? };
    let mut ms = i * 1000;
    let mut scale = 100;
    for c in f.chars().take(3) {
        ms += c.to_digit(10)? as u64 * scale;
        scale /= 10;
    }
    Some(ms.max(100))
}

pub fn top(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "bcHiSs1E",
        values: "ndpuUow",
        long: &[("batch", 'b', false), ("iterations", 'n', true), ("delay", 'd', true), ("pid", 'p', true), ("user", 'u', true), ("sort-override", 'o', true), ("width", 'w', true)],
    };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(e) => {
            ctx.eprint(&alloc::format!("top: {e}\nUsage:\n  top -hv | -bcEeHiOSs1 -d secs -n max -u|U user -p pid(s) -o field -w [cols]\n"));
            return 1;
        }
    };
    let mut st = TopState {
        sort: SortBy::Cpu,
        reverse: false,
        full_cmd: p.has('c'),
        hide_idle: p.has('i'),
        user: None,
        pids: Vec::new(),
        delay_ms: 3000,
        scroll: 0,
        message: String::new(),
    };
    if let Some(d) = p.value('d') {
        match top_parse_delay(d) {
            Some(ms) => st.delay_ms = ms,
            None => return ctx.fail(alloc::format!("bad delay interval '{d}'")),
        }
    }
    if let Some(u) = p.value('u').or(p.value('U')) {
        match u.parse::<u32>().ok().or_else(|| crate::users::by_name(u).map(|x| x.uid)) {
            Some(uid) => st.user = Some(uid),
            None => return ctx.fail(alloc::format!("Invalid user: {u}")),
        }
    }
    for v in p.values('p') {
        for s in v.split(',') {
            match s.parse::<u32>() {
                Ok(n) => st.pids.push(n),
                Err(_) => return ctx.fail(alloc::format!("pid '{s}' is not a number")),
            }
        }
    }
    if let Some(o) = p.value('o') {
        let (rev, name) = match o.strip_prefix('+').or(o.strip_prefix('-')) {
            Some(n) => (o.starts_with('-'), n),
            None => (false, o),
        };
        match SortBy::from_top_field(name) {
            Some(s) => {
                st.sort = s;
                st.reverse = rev;
            }
            None => return ctx.fail(alloc::format!("unrecognized field name '{o}'")),
        }
    }
    let iterations = p.value('n').and_then(|n| n.parse::<u64>().ok());
    let tty = ctx.stdout_tty();
    let batch = p.has('b') || tty.is_none();
    let names = NameCache::new();
    let mut prev = Sample::take(ctx);
    if !ctx.sleep_ms(250) {
        return 0;
    }
    if batch {
        let mut n = 0u64;
        loop {
            let cur = Sample::take(ctx);
            let mem = MemInfo::read(&ctx.fs());
            for l in top_summary(ctx, &prev, &cur, &mem) {
                outln!(ctx, "{l}");
            }
            outln!(ctx);
            outln!(ctx, "{TOP_HEADER}");
            let width = p.value('w').and_then(|w| w.parse::<usize>().ok()).unwrap_or(usize::MAX);
            for r in top_select(&st, rows(&prev, &cur, mem.total()), &names) {
                let line = top_row(&r, &names, st.full_cmd);
                let line: String = line.chars().take(width).collect();
                outln!(ctx, "{line}");
            }
            n += 1;
            if iterations.is_some_and(|max| n >= max) || !ctx.flush() {
                return 0;
            }
            outln!(ctx);
            prev = cur;
            if !ctx.sleep_ms(st.delay_ms) {
                return 0;
            }
        }
    }
    let term = Terminal::open(tty.expect("checked above"), true);
    let mut screen = Screen::new();
    let mut n = 0u64;
    let mut last_rows: Vec<Row> = Vec::new();
    loop {
        let cur = Sample::take(ctx);
        let mem = MemInfo::read(&ctx.fs());
        let (cols, height) = term.size();
        let mut lines: Vec<String> = top_summary(ctx, &prev, &cur, &mem).into_iter().map(|l| tui::fit(&l, cols)).collect();
        lines.push(tui::fit(&st.message, cols));
        lines.push(alloc::format!("\x1b[7m{}\x1b[0m", tui::fit(TOP_HEADER, cols)));
        last_rows = top_select(&st, rows(&prev, &cur, mem.total()), &names);
        let room = height.saturating_sub(lines.len());
        st.scroll = st.scroll.min(last_rows.len().saturating_sub(1));
        for r in last_rows.iter().skip(st.scroll).take(room) {
            let line = top_row(r, &names, st.full_cmd);
            lines.push(if r.p.state == 'R' { alloc::format!("\x1b[1m{}", tui::fit(&line, cols)) } else { tui::fit(&line, cols) });
        }
        screen.present(&term, &lines);
        prev = cur;
        n += 1;
        if iterations.is_some_and(|max| n >= max) {
            return 0;
        }
        // Wait for the next refresh, handling keys meanwhile.
        let deadline = crate::time::now_ns() + st.delay_ms * 1_000_000;
        loop {
            let now = crate::time::now_ns();
            if now >= deadline {
                break;
            }
            let key = match term.read_key((deadline - now) / 1_000_000 + 1) {
                Ok(Some(k)) => k,
                Ok(None) => break,
                Err(_) => {
                    if crate::proc::absorb_signals() && !term.tty().is_hung_up() {
                        continue;
                    }
                    return 0;
                }
            };
            st.message.clear();
            match key {
                Key::Char('q') | Key::Ctrl('c') => return 0,
                Key::Char('P') => st.sort = SortBy::Cpu,
                Key::Char('M') => st.sort = SortBy::Mem,
                Key::Char('T') => st.sort = SortBy::Time,
                Key::Char('N') => st.sort = SortBy::Pid,
                Key::Char('R') => st.reverse = !st.reverse,
                Key::Char('c') => st.full_cmd = !st.full_cmd,
                Key::Char('i') => st.hide_idle = !st.hide_idle,
                Key::Up => st.scroll = st.scroll.saturating_sub(1),
                Key::Down => st.scroll += 1,
                Key::PageUp => st.scroll = st.scroll.saturating_sub(height / 2),
                Key::PageDown => st.scroll += height / 2,
                Key::Home => st.scroll = 0,
                Key::Ctrl('l') => screen.invalidate(),
                Key::Char('k') => {
                    let first = last_rows.first().map(|r| r.p.pid).unwrap_or(0);
                    let pid = match prompt(&term, &mut screen, &lines, &alloc::format!("PID to signal/kill [default pid = {first}] ")) {
                        Some(s) if s.is_empty() => first,
                        Some(s) => match s.parse::<u32>() {
                            Ok(n) => n,
                            Err(_) => {
                                st.message = alloc::format!(" Unacceptable integer");
                                break;
                            }
                        },
                        None => break,
                    };
                    let sig = match prompt(&term, &mut screen, &lines, &alloc::format!("Send pid {pid} signal [15/sigterm] ")) {
                        Some(s) if s.is_empty() => signal::SIGTERM,
                        Some(s) => match signal::parse(&s) {
                            Some(n) => n,
                            None => {
                                st.message = String::from(" Unacceptable signal value");
                                break;
                            }
                        },
                        None => break,
                    };
                    if let Err(e) = crate::proc::kill(&ctx.proc, pid as i64, sig) {
                        st.message = alloc::format!(" Failed signal pid '{pid}' with '{sig}': {e}");
                    }
                }
                Key::Char('d') | Key::Char('s') => {
                    if let Some(v) = prompt(&term, &mut screen, &lines, &alloc::format!("Change delay from {}.{} to ", st.delay_ms / 1000, st.delay_ms % 1000 / 100)) {
                        match top_parse_delay(&v) {
                            Some(ms) => st.delay_ms = ms,
                            None if v.is_empty() => {}
                            None => st.message = String::from(" Unacceptable floating point"),
                        }
                    }
                }
                Key::Char('u') | Key::Char('U') => {
                    if let Some(v) = prompt(&term, &mut screen, &lines, "Which user (blank for all) ") {
                        st.user = if v.is_empty() { None } else { v.parse::<u32>().ok().or_else(|| crate::users::by_name(&v).map(|x| x.uid)) };
                        if !v.is_empty() && st.user.is_none() {
                            st.message = String::from(" Invalid user");
                        }
                    }
                }
                Key::Char('h') | Key::Char('?') => {
                    let help = [
                        "Help for Interactive Commands - FastROS top",
                        "",
                        "  P,M,T,N  sort by %CPU, %MEM, TIME+, PID     R  reverse sort order",
                        "  c        toggle full command line           i  toggle idle processes",
                        "  k        kill a task                        u  filter by user",
                        "  d,s      change the delay                   ^L redraw",
                        "  Up/Down PgUp/PgDn Home                      scroll the task list",
                        "  q        quit",
                        "",
                        "Press any key to continue",
                    ];
                    let lines: Vec<String> = help.iter().map(|s| s.to_string()).collect();
                    screen.present(&term, &lines);
                    let _ = term.read_key(600_000);
                    screen.invalidate();
                }
                _ => continue,
            }
            break;
        }
    }
}

/// A one-line prompt on the message row; `None` on Esc.
fn prompt(term: &Terminal, screen: &mut Screen, base: &[String], question: &str) -> Option<String> {
    let mut input = String::new();
    loop {
        let mut lines = base.to_vec();
        let row = 5.min(lines.len().saturating_sub(1));
        lines[row] = alloc::format!("\x1b[1m{question}\x1b[0m{input}");
        screen.present(term, &lines);
        match term.read_key(600_000) {
            Ok(Some(Key::Enter)) => return Some(input),
            Ok(Some(Key::Esc)) | Err(_) => return None,
            Ok(Some(Key::Backspace)) => {
                input.pop();
            }
            Ok(Some(Key::Char(c))) if input.len() < 64 => input.push(c),
            _ => {}
        }
    }
}

// ── htop ───────────────────────────────────────────────────────────────────

const C_RESET: &str = "\x1b[0m";
const C_LABEL: &str = "\x1b[36m";
const C_BRACKET: &str = "\x1b[1;37m";
const C_VALUE: &str = "\x1b[1;37m";
const C_SHADOW: &str = "\x1b[1;30m";
const C_GREEN: &str = "\x1b[32m";
const C_RED: &str = "\x1b[31m";
const C_BLUE: &str = "\x1b[34m";
const C_YELLOW: &str = "\x1b[33m";
const C_HEADER: &str = "\x1b[30;42m";
const C_HEADER_SORT: &str = "\x1b[30;46m";
const C_SELECTED: &str = "\x1b[30;46m";
const C_FKEY: &str = "\x1b[0;37;40m";
const C_FLABEL: &str = "\x1b[30;46m";

/// A meter: `caption[||||||     text]`, bars coloured per component.
fn meter(caption: &str, width: usize, parts: &[(u64, &str)], total: u64, text: &str) -> String {
    let inner = width.saturating_sub(caption.len() + 2).max(1);
    let mut cells: Vec<(char, &str)> = alloc::vec![(' ', ""); inner];
    let mut pos = 0usize;
    for (v, color) in parts {
        let n = if total == 0 { 0 } else { ((*v as u128 * inner as u128 + total as u128 / 2) / total as u128) as usize };
        for _ in 0..n {
            if pos < inner {
                cells[pos] = ('|', color);
                pos += 1;
            }
        }
    }
    // The value text sits right-aligned over the bar.
    let tchars: Vec<char> = text.chars().collect();
    let start = inner.saturating_sub(tchars.len());
    let mut s = alloc::format!("{C_LABEL}{caption}{C_BRACKET}[");
    let mut cur_color = "";
    for (i, (ch, color)) in cells.iter().enumerate() {
        if i >= start && i - start < tchars.len() {
            if cur_color != C_SHADOW {
                s.push_str(C_SHADOW);
                cur_color = C_SHADOW;
            }
            s.push(tchars[i - start]);
            continue;
        }
        if *color != cur_color {
            s.push_str(C_RESET);
            s.push_str(color);
            cur_color = color;
        }
        s.push(*ch);
    }
    s.push_str(&alloc::format!("{C_BRACKET}]{C_RESET}"));
    s
}

/// htop memory figures: `503M`, `1.94G`, `0K`.
fn htop_mem(kb: u64) -> String {
    if kb < 1024 {
        alloc::format!("{kb}K")
    } else if kb < 1024 * 1024 {
        let t = kb * 10 / 1024;
        if t < 1000 {
            alloc::format!("{}.{}M", t / 10, t % 10)
        } else {
            alloc::format!("{}M", kb / 1024)
        }
    } else {
        let h = kb * 100 / (1024 * 1024);
        alloc::format!("{}.{:02}G", h / 100, h % 100)
    }
}

/// Process-list memory column: KiB below 100000, then M and G.
fn htop_kb_col(kb: u64) -> String {
    if kb < 100_000 {
        kb.to_string()
    } else if kb < 100_000 * 1024 {
        alloc::format!("{}M", kb / 1024)
    } else {
        let h = kb * 100 / (1024 * 1024);
        alloc::format!("{}.{:02}G", h / 100, h % 100)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Panel {
    None,
    Sort(usize),
    Signal(usize),
    Search,
    Filter,
    Help,
}

struct HtopState {
    sort: SortBy,
    reverse: bool,
    tree: bool,
    show_kthreads: bool,
    selected_pid: Option<u32>,
    scroll: usize,
    panel: Panel,
    search: String,
    filter: String,
    user: Option<u32>,
    pids: Vec<u32>,
    delay_ms: u64,
    color: bool,
    status: String,
}

const SIGNALS: [u32; 18] = [15, 1, 2, 3, 9, 10, 12, 13, 14, 17, 18, 19, 20, 21, 22, 28, 30, 6];

fn tree_order(rows: Vec<Row>) -> Vec<(Row, String)> {
    let pids: Vec<u32> = rows.iter().map(|r| r.p.pid).collect();
    let mut kids: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    let mut roots = Vec::new();
    for (i, r) in rows.iter().enumerate() {
        if r.p.ppid != 0 && pids.contains(&r.p.ppid) {
            kids.entry(r.p.ppid).or_default().push(i);
        } else {
            roots.push(i);
        }
    }
    let mut order: Vec<(usize, String)> = Vec::new();
    let mut stack: Vec<(usize, String, bool, bool)> = roots.iter().rev().map(|&r| (r, String::new(), true, true)).collect();
    while let Some((i, prefix, last, root)) = stack.pop() {
        let branch = if root { String::new() } else { alloc::format!("{}{}", prefix, if last { "└─ " } else { "├─ " }) };
        order.push((i, branch));
        if let Some(ch) = kids.get(&rows[i].p.pid) {
            let child_prefix = if root { String::new() } else { alloc::format!("{}{}", prefix, if last { "   " } else { "│  " }) };
            for (k, &c) in ch.iter().enumerate().rev() {
                stack.push((c, child_prefix.clone(), k + 1 == ch.len(), false));
            }
        }
    }
    let mut slots: Vec<Option<Row>> = rows.into_iter().map(Some).collect();
    order.into_iter().filter_map(|(i, b)| slots[i].take().map(|r| (r, b))).collect()
}

fn htop_header_line(st: &HtopState, cols: usize) -> String {
    let cols_def: [(&str, Option<SortBy>); 11] = [
        ("    PID ", Some(SortBy::Pid)),
        ("USER       ", Some(SortBy::User)),
        ("PRI ", Some(SortBy::Pri)),
        (" NI ", None),
        (" VIRT ", Some(SortBy::Virt)),
        ("  RES ", Some(SortBy::Res)),
        ("  SHR ", None),
        ("S ", Some(SortBy::State)),
        (" CPU% ", Some(SortBy::Cpu)),
        ("MEM% ", Some(SortBy::Mem)),
        ("  TIME+  ", Some(SortBy::Time)),
    ];
    let mut s = String::new();
    let mut used = 0;
    for (title, key) in cols_def {
        let color = if key == Some(st.sort) && st.color { C_HEADER_SORT } else if st.color { C_HEADER } else { "\x1b[7m" };
        s.push_str(color);
        s.push_str(title);
        used += title.len();
    }
    let tail = "Command";
    s.push_str(if st.sort == SortBy::Command && st.color { C_HEADER_SORT } else if st.color { C_HEADER } else { "\x1b[7m" });
    s.push_str(tail);
    used += tail.len();
    s.push_str(if st.color { C_HEADER } else { "\x1b[7m" });
    for _ in used..cols {
        s.push(' ');
    }
    s.push_str(C_RESET);
    s
}

fn htop_row(r: &Row, branch: &str, names: &NameCache, selected: bool, st: &HtopState, cols: usize) -> String {
    let p = &r.p;
    let user = pi::fit_name(&names.user(p.uid), 10);
    let body = alloc::format!(
        "{:>7} {:<10} {:>3} {:>3} {:>5} {:>5} {:>5} {} {:>5} {:>4} {:>8} ",
        p.pid,
        user,
        p.priority,
        p.nice,
        htop_kb_col(p.vsize / 1024),
        htop_kb_col(p.rss_kb()),
        0,
        p.state,
        tenths(r.cpu),
        tenths(r.mem),
        pi::fmt_time_plus(p.cpu_ticks())
    );
    let cmd = if p.is_kthread() { p.comm.clone() } else { p.args() };
    if selected {
        return alloc::format!("{}{}{}", C_SELECTED, tui::fit(&alloc::format!("{body}{branch}{cmd}"), cols), C_RESET);
    }
    if !st.color {
        return tui::fit(&alloc::format!("{body}{branch}{cmd}"), cols);
    }
    let state = if p.state == 'R' { alloc::format!("{C_GREEN}R{C_RESET}") } else if p.state == 'Z' || p.state == 'D' { alloc::format!("{C_RED}{}{C_RESET}", p.state) } else { p.state.to_string() };
    // Colour the command: kernel threads dimmed, the program name bold.
    let cmd_col = if p.is_kthread() {
        alloc::format!("{C_SHADOW}{branch}{cmd}{C_RESET}")
    } else {
        let (prog, rest) = match cmd.split_once(' ') {
            Some((a, b)) => (a.to_string(), alloc::format!(" {b}")),
            None => (cmd.clone(), String::new()),
        };
        alloc::format!("{C_SHADOW}{branch}{C_RESET}\x1b[1m{prog}{C_RESET}{rest}")
    };
    let body = body.replacen(&alloc::format!(" {} ", p.state), &alloc::format!(" {state} "), 1);
    tui::fit(&alloc::format!("{body}{cmd_col}"), cols)
}

fn function_bar(items: &[(&str, &str)], cols: usize) -> String {
    let mut s = String::new();
    let mut used = 0;
    for (k, label) in items {
        s.push_str(C_FKEY);
        s.push_str(k);
        s.push_str(C_FLABEL);
        s.push_str(label);
        used += k.len() + label.len();
    }
    s.push_str(C_FLABEL);
    for _ in used..cols {
        s.push(' ');
    }
    s.push_str(C_RESET);
    s
}

pub fn htop(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "CtMHV",
        values: "dups",
        long: &[("no-color", 'C', false), ("no-colour", 'C', false), ("tree", 't', false), ("delay", 'd', true), ("user", 'u', true), ("pid", 'p', true), ("sort-key", 's', true), ("version", 'V', false)],
    };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(e) => return ctx.fail(e),
    };
    if p.has('V') {
        outln!(ctx, "htop 3.3.0 (FastROS {})", crate::VERSION);
        return 0;
    }
    let Some(tty) = ctx.stdout_tty() else {
        return ctx.fail("htop requires a terminal (use `top -b` for batch output)");
    };
    let mut st = HtopState {
        sort: SortBy::Cpu,
        reverse: false,
        tree: p.has('t'),
        show_kthreads: true,
        selected_pid: None,
        scroll: 0,
        panel: Panel::None,
        search: String::new(),
        filter: String::new(),
        user: None,
        pids: Vec::new(),
        delay_ms: 1500,
        color: !p.has('C'),
        status: String::new(),
    };
    if let Some(d) = p.value('d') {
        match d.parse::<u64>() {
            Ok(t) => st.delay_ms = (t * 100).clamp(100, 100_000),
            Err(_) => return ctx.fail(alloc::format!("invalid delay value \"{d}\"")),
        }
    }
    if let Some(u) = p.value('u') {
        match u.parse::<u32>().ok().or_else(|| crate::users::by_name(u).map(|x| x.uid)) {
            Some(uid) => st.user = Some(uid),
            None => return ctx.fail(alloc::format!("invalid user \"{u}\"")),
        }
    }
    for v in p.values('p') {
        st.pids.extend(v.split(',').filter_map(|s| s.parse::<u32>().ok()));
    }
    if let Some(s) = p.value('s') {
        match SortBy::ALL.iter().find(|x| x.name().eq_ignore_ascii_case(s)).copied().or_else(|| SortBy::from_top_field(s)) {
            Some(k) => st.sort = k,
            None => return ctx.fail(alloc::format!("invalid column \"{s}\"")),
        }
    }
    let names = NameCache::new();
    let term = Terminal::open(tty, true);
    let mut screen = Screen::new();
    let mut prev = Sample::take(ctx);
    crate::sched::sleep_ms(200);
    let mut cur = Sample::take(ctx);
    let mut next_sample = crate::time::now_ns() + st.delay_ms * 1_000_000;
    loop {
        let mem = MemInfo::read(&ctx.fs());
        let (cols, height) = term.size();
        // ── rows ──
        let mut list: Vec<Row> = rows(&prev, &cur, mem.total())
            .into_iter()
            .filter(|r| st.show_kthreads || !r.p.is_kthread())
            .filter(|r| st.user.is_none_or(|u| r.p.uid == u))
            .filter(|r| st.pids.is_empty() || st.pids.contains(&r.p.pid))
            .filter(|r| st.filter.is_empty() || r.p.args().to_lowercase().contains(&st.filter.to_lowercase()))
            .collect();
        sort_rows(&mut list, st.sort, st.reverse, &names);
        let ordered: Vec<(Row, String)> = if st.tree {
            list.sort_by_key(|r| r.p.pid);
            tree_order(list)
        } else {
            list.into_iter().map(|r| (r, String::new())).collect()
        };
        let sel_idx = st.selected_pid.and_then(|pid| ordered.iter().position(|(r, _)| r.p.pid == pid)).unwrap_or(0);
        st.selected_pid = ordered.get(sel_idx).map(|(r, _)| r.p.pid);
        // ── header meters ──
        let half = cols / 2;
        let d = cur.cpu.since(&prev.cpu);
        let total = d.total().max(1);
        let busy = d.user + d.nice + d.system + d.irq + d.softirq + d.steal;
        let cpu_text = alloc::format!("{}%", tenths(busy * 1000 / total));
        let mut left = alloc::vec![meter("  0", half.saturating_sub(1), &[(d.nice, C_BLUE), (d.user, C_GREEN), (d.system + d.irq + d.softirq, C_RED)], total, &cpu_text)];
        let used = mem.used();
        left.push(meter(
            "Mem",
            half.saturating_sub(1),
            &[(used, C_GREEN), (mem.buffers(), C_BLUE), (mem.cache(), C_YELLOW)],
            mem.total(),
            &alloc::format!("{}/{}", htop_mem(used), htop_mem(mem.total())),
        ));
        let swap_used = mem.swap_total().saturating_sub(mem.swap_free());
        left.push(meter("Swp", half.saturating_sub(1), &[(swap_used, C_RED)], mem.swap_total(), &alloc::format!("{}/{}", htop_mem(swap_used), htop_mem(mem.swap_total()))));
        let (ntasks, running, _, _, _) = task_counts(&cur.procs);
        let kthr = cur.procs.iter().filter(|p| p.is_kthread()).count();
        let load = LoadAvg::read(&ctx.fs());
        let up = pi::uptime_centis(&ctx.fs()) / 100;
        let l = |v: u64| alloc::format!("{}.{:02}", v / 100, v % 100);
        let right = [
            alloc::format!(
                "{C_LABEL}Tasks: {C_VALUE}{}{C_LABEL}, {C_VALUE}{}{C_LABEL} kthr; {C_GREEN}\x1b[1m{}{C_RESET}{C_LABEL} running{C_RESET}",
                ntasks - kthr,
                kthr,
                running
            ),
            alloc::format!("{C_LABEL}Load average: {C_VALUE}{} {C_RESET}\x1b[37m{} {} {C_RESET}", l(load.avg[0]), l(load.avg[1]), l(load.avg[2])),
            alloc::format!("{C_LABEL}Uptime: {C_VALUE}{:02}:{:02}:{:02}{}{C_RESET}", up / 3600 % 24, up / 60 % 60, up % 60, if up >= 86400 { alloc::format!(" ({} days)", up / 86400) } else { String::new() }),
        ];
        let mut lines: Vec<String> = Vec::new();
        for i in 0..3 {
            let lft = if st.color { left[i].clone() } else { strip(&left[i]) };
            let rgt = if st.color { right[i].clone() } else { strip(&right[i]) };
            lines.push(alloc::format!("{}{}{}", tui::fit(&lft, half), " ", tui::fit(&rgt, cols.saturating_sub(half + 1))));
        }
        lines.push(String::new());
        // ── side panel (sort / signal) takes the left columns of the list ──
        let panel_w = match st.panel {
            Panel::Sort(_) => 16,
            Panel::Signal(_) => 16,
            _ => 0,
        };
        let list_cols = cols.saturating_sub(panel_w);
        let mut panel_lines: Vec<String> = Vec::new();
        match st.panel {
            Panel::Sort(i) => {
                panel_lines.push(alloc::format!("{C_HEADER}{}{C_RESET}", tui::fit("Sort by", panel_w)));
                for (k, s) in SortBy::ALL.iter().enumerate() {
                    let t = tui::fit(s.name(), panel_w);
                    panel_lines.push(if k == i { alloc::format!("{C_SELECTED}{t}{C_RESET}") } else { t });
                }
            }
            Panel::Signal(i) => {
                panel_lines.push(alloc::format!("{C_HEADER}{}{C_RESET}", tui::fit("Send signal:", panel_w)));
                for (k, s) in SIGNALS.iter().enumerate() {
                    let t = tui::fit(&alloc::format!("{:>2} SIG{}", s, signal::name(*s)), panel_w);
                    panel_lines.push(if k == i { alloc::format!("{C_SELECTED}{t}{C_RESET}") } else { t });
                }
            }
            _ => {}
        }
        let with_panel = |row: usize, s: String| -> String {
            if panel_w == 0 {
                s
            } else {
                let pl = panel_lines.get(row).cloned().unwrap_or_else(|| " ".repeat(panel_w));
                alloc::format!("{pl}{s}")
            }
        };
        lines.push(with_panel(0, htop_header_line(&st, list_cols)));
        let room = height.saturating_sub(lines.len() + 1);
        if sel_idx < st.scroll {
            st.scroll = sel_idx;
        } else if room > 0 && sel_idx >= st.scroll + room {
            st.scroll = sel_idx + 1 - room;
        }
        for (k, (r, branch)) in ordered.iter().skip(st.scroll).take(room).enumerate() {
            let selected = st.scroll + k == sel_idx;
            lines.push(with_panel(k + 1, htop_row(r, branch, &names, selected, &st, list_cols)));
        }
        while lines.len() < height - 1 {
            let k = lines.len() - 4;
            lines.push(with_panel(k, String::new()));
        }
        // ── bottom bar ──
        let bottom = match st.panel {
            Panel::Search => alloc::format!("{C_FKEY}F3{C_FLABEL}Next  {C_FKEY}S-F3{C_FLABEL}Prev   {C_FKEY}Esc{C_FLABEL}Cancel {C_RESET} Search: {}", st.search),
            Panel::Filter => alloc::format!("{C_FKEY}Enter{C_FLABEL}Done  {C_FKEY}Esc{C_FLABEL}Clear {C_RESET} Filter: {}", st.filter),
            Panel::Sort(_) | Panel::Signal(_) => function_bar(&[("Enter", "Select "), ("Esc", "Cancel ")], cols),
            _ if !st.status.is_empty() => tui::fit(&st.status, cols),
            _ => function_bar(
                &[("F1", "Help  "), ("F2", "Setup "), ("F3", "Search"), ("F4", "Filter"), ("F5", if st.tree { "List  " } else { "Tree  " }), ("F6", "SortBy"), ("F7", "Nice -"), ("F8", "Nice +"), ("F9", "Kill  "), ("F10", "Quit")],
                cols,
            ),
        };
        lines.push(if st.color { bottom } else { strip(&bottom) });
        if st.panel == Panel::Help {
            lines = htop_help(cols);
        }
        screen.present(&term, &lines);
        // ── input until the next sample ──
        let now = crate::time::now_ns();
        let wait_ms = if next_sample > now { (next_sample - now) / 1_000_000 + 1 } else { 0 };
        let key = if wait_ms == 0 {
            None
        } else {
            match term.read_key(wait_ms) {
                Ok(k) => k,
                Err(_) => {
                    if crate::proc::absorb_signals() && !term.tty().is_hung_up() {
                        continue;
                    }
                    return 0;
                }
            }
        };
        if crate::time::now_ns() >= next_sample {
            prev = cur;
            cur = Sample::take(ctx);
            next_sample = crate::time::now_ns() + st.delay_ms * 1_000_000;
        }
        let Some(key) = key else { continue };
        st.status.clear();
        let n = ordered.len();
        let move_to = |st: &mut HtopState, idx: usize| {
            if n > 0 {
                st.selected_pid = Some(ordered[idx.min(n - 1)].0.p.pid);
            }
        };
        match st.panel {
            Panel::Help => st.panel = Panel::None,
            Panel::Sort(i) => match key {
                Key::Up => st.panel = Panel::Sort(i.saturating_sub(1)),
                Key::Down => st.panel = Panel::Sort((i + 1).min(SortBy::ALL.len() - 1)),
                Key::Enter => {
                    st.sort = SortBy::ALL[i];
                    st.panel = Panel::None;
                }
                Key::Esc | Key::Char('q') | Key::F(10) => st.panel = Panel::None,
                _ => {}
            },
            Panel::Signal(i) => match key {
                Key::Up => st.panel = Panel::Signal(i.saturating_sub(1)),
                Key::Down => st.panel = Panel::Signal((i + 1).min(SIGNALS.len() - 1)),
                Key::Enter => {
                    if let Some(pid) = st.selected_pid {
                        if let Err(e) = crate::proc::kill(&ctx.proc, pid as i64, SIGNALS[i]) {
                            st.status = alloc::format!("Could not send signal {} to process {}: {}", SIGNALS[i], pid, e);
                        }
                    }
                    st.panel = Panel::None;
                }
                Key::Esc | Key::Char('q') | Key::F(10) => st.panel = Panel::None,
                _ => {}
            },
            Panel::Search => match key {
                Key::Esc | Key::Enter => st.panel = Panel::None,
                Key::Backspace => {
                    st.search.pop();
                }
                Key::F(3) => {
                    let s = st.search.to_lowercase();
                    if let Some(i) = (1..=n).map(|k| (sel_idx + k) % n.max(1)).find(|&i| ordered[i].0.p.args().to_lowercase().contains(&s)) {
                        move_to(&mut st, i);
                    }
                }
                Key::Char(c) => {
                    st.search.push(c);
                    let s = st.search.to_lowercase();
                    if let Some(i) = ordered.iter().position(|(r, _)| r.p.args().to_lowercase().contains(&s)) {
                        move_to(&mut st, i);
                    } else {
                        st.status = String::from("Search: no match");
                    }
                }
                _ => {}
            },
            Panel::Filter => match key {
                Key::Enter => st.panel = Panel::None,
                Key::Esc => {
                    st.filter.clear();
                    st.panel = Panel::None;
                }
                Key::Backspace => {
                    st.filter.pop();
                }
                Key::Char(c) => st.filter.push(c),
                _ => {}
            },
            Panel::None => match key {
                Key::Char('q') | Key::F(10) | Key::Ctrl('c') => return 0,
                Key::Up => move_to(&mut st, sel_idx.saturating_sub(1)),
                Key::Down => move_to(&mut st, sel_idx + 1),
                Key::PageUp => move_to(&mut st, sel_idx.saturating_sub(room.max(1))),
                Key::PageDown => move_to(&mut st, sel_idx + room.max(1)),
                Key::Home => move_to(&mut st, 0),
                Key::End => move_to(&mut st, n.saturating_sub(1)),
                Key::F(1) | Key::Char('h') | Key::Char('?') => st.panel = Panel::Help,
                Key::F(2) | Key::Char('S') => st.status = String::from("Setup is not available on FastROS yet"),
                Key::F(3) | Key::Char('/') => {
                    st.search.clear();
                    st.panel = Panel::Search;
                }
                Key::F(4) | Key::Char('\\') => st.panel = Panel::Filter,
                Key::F(5) | Key::Char('t') => st.tree = !st.tree,
                Key::F(6) | Key::Char('>') | Key::Char('<') | Key::Char('.') => {
                    st.panel = Panel::Sort(SortBy::ALL.iter().position(|s| *s == st.sort).unwrap_or(0));
                }
                Key::F(7) | Key::F(8) | Key::Char(']') | Key::Char('[') => st.status = String::from("Changing priority is not supported: FastROS schedules fairly"),
                Key::F(9) | Key::Char('k') => st.panel = Panel::Signal(0),
                Key::Char('P') => st.sort = SortBy::Cpu,
                Key::Char('M') => st.sort = SortBy::Mem,
                Key::Char('T') => st.sort = SortBy::Time,
                Key::Char('N') => st.sort = SortBy::Pid,
                Key::Char('I') => st.reverse = !st.reverse,
                Key::Char('K') => st.show_kthreads = !st.show_kthreads,
                Key::Char('u') => {
                    st.user = match st.user {
                        Some(_) => None,
                        None => Some(ctx.cred().uid),
                    };
                }
                Key::Ctrl('l') => screen.invalidate(),
                Key::Char(' ') => {
                    prev = cur;
                    cur = Sample::take(ctx);
                }
                _ => {}
            },
        }
    }
}

fn strip(s: &str) -> String {
    let mut out = String::new();
    let mut esc = false;
    for c in s.chars() {
        if esc {
            if c.is_ascii_alphabetic() {
                esc = false;
            }
        } else if c == '\x1b' {
            esc = true;
        } else {
            out.push(c);
        }
    }
    out
}

fn htop_help(cols: usize) -> Vec<String> {
    let text = [
        "htop 3.3.0 for FastROS - (C) 2004-2024 htop dev team, released under the GNU GPLv2+.",
        "",
        "CPU usage bar: [\x1b[34mlow-priority\x1b[0m/\x1b[32mnormal\x1b[0m/\x1b[31mkernel\x1b[0m        used%]",
        "Memory bar:    [\x1b[32mused\x1b[0m/\x1b[34mbuffers\x1b[0m/\x1b[33mcache\x1b[0m                used/total]",
        "",
        " Arrows: scroll process list          F5 t: tree view",
        " F3 /: incremental name search        F6 <>: select sort column",
        " F4 \\: incremental name filtering     P M T N: sort by CPU%, MEM%, TIME, PID",
        " K: hide/show kernel threads          I: invert sort order",
        " u: show only your processes          F9 k: kill process (sends signal)",
        " Space: refresh now                   F10 q: quit",
        "",
        "Press any key to return.",
    ];
    text.iter().map(|l| tui::fit(l, cols)).collect()
}
