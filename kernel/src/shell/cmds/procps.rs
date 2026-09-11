//! Process and system status commands (procps / psmisc / util-linux
//! equivalents): ps, kill, killall, pgrep, pkill, pidof, free, uptime, w,
//! who, users, last, nproc, vmstat. Output formats match the Linux tools.

use super::fmtutil::{self, NameCache};
use super::procinfo::{self as pi, LoadAvg, MemInfo, ProcEntry, SysStat, HZ};
use crate::proc::signal;
use crate::shell::ctx::{parse_opts, Ctx, OptSpec};
use crate::time::civil;
use crate::{out, outln};
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Snapshot of the clock and system values every formatter needs.
struct Env {
    now: u64,
    uptime_secs: u64,
    btime: u64,
    mem_total_kb: u64,
}

impl Env {
    fn read(ctx: &Ctx) -> Env {
        let fs = ctx.fs();
        let st = SysStat::read(&fs);
        let up = pi::uptime_centis(&fs) / 100;
        let now = crate::time::unix_now();
        let btime = if st.btime != 0 { st.btime } else { now.saturating_sub(up) };
        Env { now, uptime_secs: up, btime, mem_total_kb: MemInfo::read(&fs).total().max(1) }
    }
    fn start_unix(&self, p: &ProcEntry) -> u64 {
        self.btime + p.start_ticks / HZ
    }
    fn alive_secs(&self, p: &ProcEntry) -> u64 {
        self.uptime_secs.saturating_sub(p.start_ticks / HZ)
    }
    /// procps `pcpu`: lifetime CPU share in tenths of a percent.
    fn pcpu(&self, p: &ProcEntry) -> u64 {
        match self.alive_secs(p) {
            0 => 0,
            s => p.cpu_ticks() * 1000 / HZ / s,
        }
    }
    fn pmem(&self, p: &ProcEntry) -> u64 {
        p.rss_kb() * 1000 / self.mem_total_kb
    }
}

/// The calling process's effective uid and terminal (`/proc/self/stat`).
fn me(ctx: &Ctx) -> (u32, u64) {
    let fs = ctx.fs();
    let pid = ctx.proc.pid;
    let tty = pi::read_proc(&fs, pid).map(|p| p.tty_nr).unwrap_or(0);
    (ctx.cred().euid, tty)
}

// ── ps ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum Align {
    Left,
    Right,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Field {
    Pid,
    Ppid,
    Pgid,
    Sid,
    Tty,
    Time,
    BsdTime,
    Comm,
    Args,
    User,
    Uid,
    Group,
    Gid,
    Pcpu,
    Pmem,
    Vsz,
    Rss,
    Sz,
    Stat,
    State,
    StartTime,
    Stime,
    Lstart,
    Etime,
    Etimes,
    C,
    Pri,
    Ni,
    Flags,
    Nlwp,
    Tpgid,
}

struct FieldSpec {
    names: &'static [&'static str],
    header: &'static str,
    width: usize,
    align: Align,
    field: Field,
}

const fn spec(names: &'static [&'static str], header: &'static str, width: usize, align: Align, field: Field) -> FieldSpec {
    FieldSpec { names, header, width, align, field }
}

use Align::{Left as L, Right as R};

/// procps-ng 4 field names, headers and widths.
const FIELDS: &[FieldSpec] = &[
    spec(&["pid", "tgid"], "PID", 7, R, Field::Pid),
    spec(&["ppid"], "PPID", 7, R, Field::Ppid),
    spec(&["pgid", "pgrp"], "PGID", 7, R, Field::Pgid),
    spec(&["sid", "sess", "session"], "SID", 7, R, Field::Sid),
    spec(&["tname", "tty", "tt"], "TTY", 8, L, Field::Tty),
    spec(&["time", "cputime"], "TIME", 8, R, Field::Time),
    spec(&["bsdtime"], "TIME", 6, R, Field::BsdTime),
    spec(&["comm", "ucmd", "ucomm"], "COMMAND", 15, L, Field::Comm),
    spec(&["args", "cmd", "command"], "COMMAND", 27, L, Field::Args),
    spec(&["user", "euser", "uname", "ruser"], "USER", 8, L, Field::User),
    spec(&["uid", "euid", "ruid"], "UID", 5, R, Field::Uid),
    spec(&["group", "egroup", "rgroup"], "GROUP", 8, L, Field::Group),
    spec(&["gid", "egid", "rgid"], "GID", 5, R, Field::Gid),
    spec(&["%cpu", "pcpu"], "%CPU", 4, R, Field::Pcpu),
    spec(&["%mem", "pmem"], "%MEM", 4, R, Field::Pmem),
    spec(&["vsz", "vsize"], "VSZ", 6, R, Field::Vsz),
    spec(&["rss", "rssize", "rsz"], "RSS", 5, R, Field::Rss),
    spec(&["sz"], "SZ", 5, R, Field::Sz),
    spec(&["stat"], "STAT", 4, L, Field::Stat),
    spec(&["s", "state"], "S", 1, L, Field::State),
    spec(&["start_time", "bsdstart"], "START", 5, R, Field::StartTime),
    spec(&["stime", "start"], "STIME", 5, L, Field::Stime),
    spec(&["lstart"], "STARTED", 24, L, Field::Lstart),
    spec(&["etime"], "ELAPSED", 11, R, Field::Etime),
    spec(&["etimes"], "ELAPSED", 7, R, Field::Etimes),
    spec(&["c", "cp"], "C", 2, R, Field::C),
    spec(&["pri"], "PRI", 3, R, Field::Pri),
    spec(&["ni", "nice"], "NI", 3, R, Field::Ni),
    spec(&["f", "flag", "flags"], "F", 1, R, Field::Flags),
    spec(&["nlwp", "thcount"], "NLWP", 4, R, Field::Nlwp),
    spec(&["tpgid"], "TPGID", 5, R, Field::Tpgid),
];

#[derive(Clone)]
struct Column {
    field: Field,
    header: String,
    width: usize,
    align: Align,
}

/// Parse `pid,user=OWNER,args` (commas or spaces; `=` sets the header,
/// an empty one hides the header line when every header is empty).
fn parse_format(list: &str, out: &mut Vec<Column>) -> Result<(), String> {
    for item in list.split([',', ' ']).filter(|s| !s.is_empty()) {
        let (name, header) = match item.split_once('=') {
            Some((n, h)) => (n, Some(h)),
            None => (item, None),
        };
        let s = FIELDS.iter().find(|s| s.names.contains(&name)).ok_or_else(|| alloc::format!("unknown user-defined format specifier \"{name}\""))?;
        let header = header.map(|h| h.to_string()).unwrap_or_else(|| s.header.to_string());
        out.push(Column { field: s.field, width: s.width.max(header.chars().count()), header, align: s.align });
    }
    Ok(())
}

fn columns(list: &str) -> Vec<Column> {
    let mut v = Vec::new();
    parse_format(list, &mut v).expect("built-in formats are valid");
    v
}

fn cell(f: Field, p: &ProcEntry, env: &Env, names: &NameCache) -> String {
    match f {
        Field::Pid => p.pid.to_string(),
        Field::Ppid => p.ppid.to_string(),
        Field::Pgid => p.pgid.to_string(),
        Field::Sid => p.sid.to_string(),
        Field::Tty => p.tty().unwrap_or_else(|| String::from("?")),
        Field::Time => pi::fmt_time(p.cpu_ticks() / HZ),
        Field::BsdTime => pi::fmt_bsdtime(p.cpu_ticks() / HZ),
        Field::Comm => p.comm.clone(),
        Field::Args => p.args(),
        Field::User => pi::fit_name(&names.user(p.uid), 8),
        Field::Uid => p.uid.to_string(),
        Field::Group => pi::fit_name(&names.group(p.gid), 8),
        Field::Gid => p.gid.to_string(),
        Field::Pcpu => percent(env.pcpu(p)),
        Field::Pmem => percent(env.pmem(p)),
        Field::Vsz => (p.vsize / 1024).to_string(),
        Field::Rss => p.rss_kb().to_string(),
        Field::Sz => (p.vsize / 4096).to_string(),
        Field::Stat => p.stat_flags(),
        Field::State => p.state.to_string(),
        Field::StartTime | Field::Stime => pi::fmt_start(env.start_unix(p), env.now),
        Field::Lstart => lstart(env.start_unix(p)),
        Field::Etime => pi::fmt_etime(env.alive_secs(p)),
        Field::Etimes => env.alive_secs(p).to_string(),
        Field::C => (env.pcpu(p) / 10).min(99).to_string(),
        Field::Pri => (p.priority + 60).to_string(),
        Field::Ni => p.nice.to_string(),
        Field::Flags => ((p.flags >> 6) & 7).to_string(),
        Field::Nlwp => p.threads.to_string(),
        Field::Tpgid => p.tpgid.to_string(),
    }
}

/// Tenths as `0.3` / `12.5`; `100` and above without the decimal.
fn percent(tenths: u64) -> String {
    if tenths >= 1000 {
        (tenths / 10).to_string()
    } else {
        pi::fmt_tenths(tenths)
    }
}

/// `Fri Sep 11 09:21:05 2026` (ps lstart, ctime layout).
fn lstart(t: u64) -> String {
    let tm = civil::from_unix(t as i64);
    alloc::format!(
        "{} {} {:>2} {:02}:{:02}:{:02} {}",
        civil::WEEKDAYS[tm.weekday as usize],
        civil::MONTHS[(tm.month - 1) as usize],
        tm.day,
        tm.hour,
        tm.min,
        tm.sec,
        tm.year
    )
}

fn render_row(cols: &[Column], cells: &[String]) -> String {
    let mut line = String::new();
    for (i, (c, v)) in cols.iter().zip(cells).enumerate() {
        if i > 0 {
            line.push(' ');
        }
        let last = i + 1 == cols.len();
        match c.align {
            Align::Right => line.push_str(&fmtutil::pad_left(v, c.width)),
            Align::Left if last => line.push_str(v),
            Align::Left => line.push_str(&fmtutil::pad_right(v, c.width)),
        }
    }
    line
}

#[derive(Default)]
struct PsOpts {
    all: bool,
    bsd: bool,
    bsd_a: bool,
    bsd_x: bool,
    bsd_u: bool,
    dash_a: bool,
    dash_d: bool,
    full: bool,
    jobs: bool,
    forest: bool,
    no_header: bool,
    running: bool,
    negate: bool,
    wide: usize,
    format: Vec<Column>,
    pids: Vec<u32>,
    ppids: Vec<u32>,
    sids: Vec<u32>,
    pgids: Vec<u32>,
    users: Vec<u32>,
    ttys: Vec<String>,
    cmds: Vec<String>,
    sort: Vec<(bool, String)>,
}

impl PsOpts {
    fn has_lists(&self) -> bool {
        !(self.pids.is_empty() && self.ppids.is_empty() && self.sids.is_empty() && self.pgids.is_empty() && self.users.is_empty() && self.ttys.is_empty() && self.cmds.is_empty())
    }
}

fn split_list(v: &str) -> impl Iterator<Item = &str> {
    v.split([',', ' ']).filter(|s| !s.is_empty())
}

fn parse_ids(v: &str, what: &str) -> Result<Vec<u32>, String> {
    split_list(v).map(|s| s.parse::<u32>().map_err(|_| alloc::format!("process ID list syntax error ({what} '{s}')"))).collect()
}

fn parse_users(v: &str) -> Result<Vec<u32>, String> {
    split_list(v)
        .map(|s| match s.parse::<u32>() {
            Ok(n) => Ok(n),
            Err(_) => crate::users::by_name(s).map(|u| u.uid).ok_or_else(|| alloc::format!("user name does not exist: {s}")),
        })
        .collect()
}

fn parse_ps_args(args: &[String]) -> Result<PsOpts, String> {
    let mut o = PsOpts::default();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        i += 1;
        if let Some(long) = a.strip_prefix("--") {
            let (k, inline) = match long.split_once('=') {
                Some((k, v)) => (k, Some(v.to_string())),
                None => (long, None),
            };
            let mut value = || -> Result<String, String> {
                if let Some(v) = &inline {
                    return Ok(v.clone());
                }
                let v = args.get(i).cloned().ok_or_else(|| alloc::format!("option --{k} requires an argument"))?;
                i += 1;
                Ok(v)
            };
            match k {
                "forest" => o.forest = true,
                "no-headers" | "no-heading" | "no-header" => o.no_header = true,
                "sort" => {
                    for key in split_list(&value()?) {
                        let (desc, name) = match key.as_bytes()[0] {
                            b'-' => (true, &key[1..]),
                            b'+' => (false, &key[1..]),
                            _ => (false, key),
                        };
                        o.sort.push((desc, name.to_string()));
                    }
                }
                "pid" => o.pids.extend(parse_ids(&value()?, "pid")?),
                "ppid" => o.ppids.extend(parse_ids(&value()?, "ppid")?),
                "sid" => o.sids.extend(parse_ids(&value()?, "sid")?),
                "user" | "User" => o.users.extend(parse_users(&value()?)?),
                "tty" => o.ttys.extend(split_list(&value()?).map(|s| s.to_string())),
                "format" => parse_format(&value()?, &mut o.format)?,
                "cols" | "columns" | "width" => {
                    let _ = value()?;
                    o.wide = 2;
                }
                _ => return Err(alloc::format!("unknown long option '--{k}'")),
            }
        } else if let Some(u) = a.strip_prefix('-') {
            if u.is_empty() {
                return Err(String::from("unsupported option '-'"));
            }
            let chars: Vec<char> = u.chars().collect();
            let mut j = 0;
            while j < chars.len() {
                let c = chars[j];
                j += 1;
                match c {
                    'e' | 'A' => o.all = true,
                    'a' => o.dash_a = true,
                    'd' => o.dash_d = true,
                    'f' => o.full = true,
                    'j' => o.jobs = true,
                    'H' => o.forest = true,
                    'w' => o.wide += 1,
                    'N' => o.negate = true,
                    'o' | 'p' | 'u' | 'U' | 't' | 'C' | 'g' | 's' | 'q' | 'O' => {
                        let v: String = if j < chars.len() {
                            let v = chars[j..].iter().collect();
                            j = chars.len();
                            v
                        } else {
                            let v = args.get(i).cloned().ok_or_else(|| alloc::format!("option -{c} requires an argument"))?;
                            i += 1;
                            v
                        };
                        match c {
                            'o' | 'O' => parse_format(&v, &mut o.format)?,
                            'p' | 'q' => o.pids.extend(parse_ids(&v, "pid")?),
                            'u' | 'U' => o.users.extend(parse_users(&v)?),
                            't' => o.ttys.extend(split_list(&v).map(|s| s.to_string())),
                            'C' => o.cmds.extend(split_list(&v).map(|s| s.to_string())),
                            'g' => o.pgids.extend(parse_ids(&v, "pgid")?),
                            _ => o.sids.extend(parse_ids(&v, "sid")?),
                        }
                    }
                    _ => return Err(alloc::format!("unsupported option (BSD syntax) -- '{c}'")),
                }
            }
        } else if a.bytes().all(|b| b.is_ascii_digit() || b == b',') {
            // `ps 1234` — a BSD-style process list.
            o.pids.extend(parse_ids(a, "pid")?);
        } else {
            o.bsd = true;
            for c in a.chars() {
                match c {
                    'a' => o.bsd_a = true,
                    'x' => o.bsd_x = true,
                    'u' => o.bsd_u = true,
                    'f' => o.forest = true,
                    'w' => o.wide += 1,
                    'h' => o.no_header = true,
                    'r' => o.running = true,
                    'e' => {}
                    'j' => o.jobs = true,
                    _ => return Err(alloc::format!("unsupported SysV option -- '{c}'")),
                }
            }
        }
    }
    Ok(o)
}

/// Order processes as a tree (children after their parent) with the
/// `\_` prefixes procps draws in the command column.
fn forest_order(procs: Vec<ProcEntry>) -> Vec<(ProcEntry, String)> {
    let pids: Vec<u32> = procs.iter().map(|p| p.pid).collect();
    let mut kids: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    let mut roots = Vec::new();
    for (i, p) in procs.iter().enumerate() {
        if p.ppid != 0 && p.ppid != p.pid && pids.contains(&p.ppid) {
            kids.entry(p.ppid).or_default().push(i);
        } else {
            roots.push(i);
        }
    }
    let mut out: Vec<(usize, String)> = Vec::new();
    // (index, depth, ancestors-have-more-siblings)
    let mut stack: Vec<(usize, Vec<bool>)> = roots.iter().rev().map(|&r| (r, Vec::new())).collect();
    while let Some((i, bars)) = stack.pop() {
        let mut prefix = String::new();
        if !bars.is_empty() {
            prefix.push(' ');
            for &more in &bars[..bars.len() - 1] {
                prefix.push_str(if more { "|   " } else { "    " });
            }
            prefix.push_str("\\_ ");
        }
        out.push((i, prefix));
        if let Some(ch) = kids.get(&procs[i].pid) {
            for (k, &c) in ch.iter().enumerate().rev() {
                let mut b = bars.clone();
                b.push(k + 1 < ch.len());
                stack.push((c, b));
            }
        }
    }
    let mut slots: Vec<Option<ProcEntry>> = procs.into_iter().map(Some).collect();
    out.into_iter().filter_map(|(i, pre)| slots[i].take().map(|p| (p, pre))).collect()
}

fn sort_key_cmp(key: &str, a: &ProcEntry, b: &ProcEntry, env: &Env, names: &NameCache) -> Option<core::cmp::Ordering> {
    Some(match key {
        "pid" => a.pid.cmp(&b.pid),
        "ppid" => a.ppid.cmp(&b.ppid),
        "pgid" | "pgrp" => a.pgid.cmp(&b.pgid),
        "sid" | "sess" => a.sid.cmp(&b.sid),
        "%cpu" | "pcpu" => env.pcpu(a).cmp(&env.pcpu(b)),
        "%mem" | "pmem" | "rss" | "rssize" | "rsz" => a.rss_pages.cmp(&b.rss_pages),
        "vsz" | "vsize" | "sz" => a.vsize.cmp(&b.vsize),
        "time" | "cputime" | "bsdtime" => a.cpu_ticks().cmp(&b.cpu_ticks()),
        "start_time" | "start" | "stime" | "lstart" | "etime" | "etimes" => a.start_ticks.cmp(&b.start_ticks),
        "comm" | "ucmd" | "cmd" | "args" | "command" => a.comm.cmp(&b.comm),
        "user" | "euser" | "uname" => names.user(a.uid).cmp(&names.user(b.uid)),
        "uid" | "euid" => a.uid.cmp(&b.uid),
        "tty" | "tname" | "tt" => a.tty_nr.cmp(&b.tty_nr),
        "nlwp" => a.threads.cmp(&b.threads),
        _ => return None,
    })
}

pub fn ps(ctx: &mut Ctx) -> i32 {
    let args = ctx.args[1..].to_vec();
    let o = match parse_ps_args(&args) {
        Ok(o) => o,
        Err(e) => {
            ctx.eprint(&alloc::format!("error: {e}\n\nUsage:\n ps [options]\n"));
            return 1;
        }
    };
    let env = Env::read(ctx);
    let names = NameCache::new();
    let (my_uid, my_tty) = me(ctx);
    let any_crit = o.all || o.bsd_a || o.bsd_x || o.dash_a || o.dash_d || o.has_lists() || o.running;
    let tty_matches = |p: &ProcEntry| {
        o.ttys.iter().any(|t| {
            let t = t.strip_prefix("/dev/").unwrap_or(t);
            p.tty().is_some_and(|n| n == t || n.strip_prefix("tty") == Some(t)) || (t == "-" || t == "?") && p.tty_nr == 0
        })
    };
    let selected = |p: &ProcEntry| -> bool {
        let base = if !any_crit || (o.running && !(o.all || o.bsd_a || o.bsd_x || o.dash_a || o.dash_d || o.has_lists())) {
            if o.bsd {
                p.uid == my_uid && p.tty_nr != 0
            } else {
                p.uid == my_uid && p.tty_nr == my_tty
            }
        } else {
            o.all
                || ((o.bsd_a || o.bsd_x) && (o.bsd_a || p.uid == my_uid) && (o.bsd_x || p.tty_nr != 0))
                || (o.dash_a && p.tty_nr != 0 && !p.is_session_leader())
                || (o.dash_d && !p.is_session_leader())
                || o.pids.contains(&p.pid)
                || o.ppids.contains(&p.ppid)
                || o.sids.contains(&p.sid)
                || o.pgids.contains(&p.pgid)
                || o.users.contains(&p.uid)
                || o.cmds.iter().any(|c| *c == p.comm)
                || tty_matches(p)
        };
        let base = base && (!o.running || p.state == 'R');
        base != o.negate
    };
    let mut procs: Vec<ProcEntry> = pi::list(&ctx.fs()).into_iter().filter(|p| selected(p)).collect();
    if !o.sort.is_empty() {
        for (_, k) in &o.sort {
            if sort_key_cmp(k, &procs.first().cloned().unwrap_or_default(), &ProcEntry::default(), &env, &names).is_none() {
                ctx.eprint(&alloc::format!("error: unknown sort specifier\n"));
                return 1;
            }
        }
        procs.sort_by(|a, b| {
            for (desc, k) in &o.sort {
                let ord = sort_key_cmp(k, a, b, &env, &names).unwrap_or(core::cmp::Ordering::Equal);
                let ord = if *desc { ord.reverse() } else { ord };
                if ord != core::cmp::Ordering::Equal {
                    return ord;
                }
            }
            a.pid.cmp(&b.pid)
        });
    }
    let cols = if !o.format.is_empty() {
        o.format.clone()
    } else if o.bsd_u {
        columns("user,pid,%cpu,%mem,vsz,rss,tname=TTY,stat,start_time=START,bsdtime=TIME,args=COMMAND")
    } else if o.full {
        columns("user=UID,pid,ppid,c,stime,tname=TTY,time,args=CMD")
    } else if o.jobs {
        columns("pid,pgid,sid,tname=TTY,time,comm=CMD")
    } else if o.bsd {
        columns("pid,tname=TTY,stat,bsdtime=TIME,args=COMMAND")
    } else {
        columns("pid,tname=TTY,time,comm=CMD")
    };
    let empty = procs.is_empty();
    let rows: Vec<(ProcEntry, String)> = if o.forest && o.sort.is_empty() { forest_order(procs) } else { procs.into_iter().map(|p| (p, String::new())).collect() };
    let limit = match (ctx.stdout_tty().is_some(), o.wide) {
        (_, w) if w >= 2 => usize::MAX,
        (true, 1) => ctx.term_size().0.max(132),
        (true, _) => ctx.term_size().0,
        (false, _) => usize::MAX,
    };
    let emit = |ctx: &mut Ctx, line: String| {
        if line.chars().count() > limit {
            let cut: String = line.chars().take(limit).collect();
            outln!(ctx, "{cut}");
        } else {
            outln!(ctx, "{line}");
        }
    };
    if !o.no_header && cols.iter().any(|c| !c.header.is_empty()) {
        let headers: Vec<String> = cols.iter().map(|c| c.header.clone()).collect();
        emit(ctx, render_row(&cols, &headers));
    }
    for (p, prefix) in rows {
        let cells: Vec<String> = cols
            .iter()
            .map(|c| {
                let v = cell(c.field, &p, &env, &names);
                if matches!(c.field, Field::Args | Field::Comm) && !prefix.is_empty() {
                    alloc::format!("{prefix}{v}")
                } else {
                    v
                }
            })
            .collect();
        emit(ctx, render_row(&cols, &cells));
        if ctx.should_stop() {
            break;
        }
    }
    if empty {
        1
    } else {
        0
    }
}

// ── kill / killall / pgrep / pkill / pidof ─────────────────────────────────

/// bash `kill -l`: `%2d) SIG%s` in five tab-separated columns.
fn signal_table() -> String {
    let mut items = Vec::new();
    for n in 1..=31u32 {
        items.push(alloc::format!("{n:2}) SIG{}", signal::name(n)));
    }
    for n in 34..=64u32 {
        let name = match n {
            34 => String::from("RTMIN"),
            64 => String::from("RTMAX"),
            n if n <= 49 => alloc::format!("RTMIN+{}", n - 34),
            n => alloc::format!("RTMAX-{}", 64 - n),
        };
        items.push(alloc::format!("{n:2}) SIG{name}"));
    }
    let mut s = String::new();
    for (i, it) in items.iter().enumerate() {
        s.push_str(it);
        s.push(if i % 5 == 4 || i + 1 == items.len() { '\n' } else { '\t' });
    }
    s
}

/// Signal from `9`, `-9`, `KILL`, `-SIGKILL`, `rtmin+2`...
fn parse_signal(s: &str) -> Option<u32> {
    let s = s.strip_prefix('-').unwrap_or(s);
    if let Ok(n) = s.parse::<u32>() {
        return (n <= 64).then_some(n);
    }
    let up = s.to_ascii_uppercase();
    let name = up.strip_prefix("SIG").unwrap_or(&up);
    match name {
        "RTMIN" => return Some(34),
        "RTMAX" => return Some(64),
        "POLL" => return Some(signal::SIGIO),
        "IOT" => return Some(signal::SIGABRT),
        _ => {}
    }
    if let Some(n) = name.strip_prefix("RTMIN+").and_then(|n| n.parse::<u32>().ok()) {
        return (n <= 30).then_some(34 + n);
    }
    if let Some(n) = name.strip_prefix("RTMAX-").and_then(|n| n.parse::<u32>().ok()) {
        return (n <= 30).then_some(64 - n);
    }
    signal::parse(name)
}

/// A leading `-9` / `-KILL` / `-hup` of pkill and killall; a word made only
/// of the command's option letters stays an option.
fn leading_signal(a: &str, option_letters: &str) -> Option<u32> {
    let body = a.strip_prefix('-')?;
    if body.is_empty() || body.starts_with('-') {
        return None;
    }
    if !body.bytes().all(|b| b.is_ascii_digit()) && body.chars().all(|c| option_letters.contains(c)) {
        return None;
    }
    parse_signal(body)
}

fn signal_name_for_list(n: u32) -> String {
    match n {
        34 => String::from("RTMIN"),
        64 => String::from("RTMAX"),
        35..=49 => alloc::format!("RTMIN+{}", n - 34),
        50..=63 => alloc::format!("RTMAX-{}", 64 - n),
        _ => signal::name(n),
    }
}

pub fn kill(ctx: &mut Ctx) -> i32 {
    let args = ctx.args[1..].to_vec();
    let mut sig = signal::SIGTERM;
    let mut i = 0;
    if args.is_empty() {
        ctx.eprint("kill: usage: kill [-s sigspec | -n signum | -sigspec] pid | jobspec ... or kill -l [sigspec]\n");
        return 2;
    }
    match args[0].as_str() {
        "-l" | "-L" | "--list" | "--table" => {
            if args.len() == 1 {
                let t = signal_table();
                ctx.print(&t);
                return 0;
            }
            let mut st = 0;
            for a in args[1..].iter().filter(|a| *a != "--") {
                match a.parse::<u32>() {
                    Ok(n) => {
                        let n = if n > 128 { n - 128 } else { n };
                        if (1..=64).contains(&n) && !(32..34).contains(&n) {
                            outln!(ctx, "{}", signal_name_for_list(n));
                        } else {
                            st = ctx.fail(alloc::format!("{a}: invalid signal specification"));
                        }
                    }
                    Err(_) => match parse_signal(a) {
                        Some(n) => outln!(ctx, "{n}"),
                        None => st = ctx.fail(alloc::format!("{a}: invalid signal specification")),
                    },
                }
            }
            return st;
        }
        "-s" | "-n" => {
            let Some(v) = args.get(1) else {
                return ctx.fail(alloc::format!("{}: option requires an argument", args[0]));
            };
            match parse_signal(v) {
                Some(n) => sig = n,
                None => return ctx.fail(alloc::format!("{v}: invalid signal specification")),
            }
            i = 2;
        }
        "--" => i = 1,
        a if a.starts_with('-') && a.len() > 1 => {
            match parse_signal(a) {
                Some(n) => sig = n,
                None => return ctx.fail(alloc::format!("{}: invalid signal specification", &a[1..])),
            }
            i = 1;
        }
        _ => {}
    }
    if args.get(i).is_some_and(|a| a == "--") {
        i += 1;
    }
    if i >= args.len() {
        ctx.eprint("kill: usage: kill [-s sigspec | -n signum | -sigspec] pid | jobspec ... or kill -l [sigspec]\n");
        return 2;
    }
    let mut st = 0;
    for a in &args[i..] {
        let Ok(pid) = a.parse::<i64>() else {
            st = ctx.fail(alloc::format!("{a}: arguments must be process or job IDs"));
            continue;
        };
        if let Err(e) = crate::proc::kill(&ctx.proc, pid, sig) {
            st = ctx.fail(alloc::format!("({pid}) - {e}"));
        }
    }
    st
}

/// Process-matching options shared by pgrep, pkill, killall, pidof.
struct Matcher {
    re: Option<regex::Regex>,
    full: bool,
    exact_name: Option<String>,
    ppids: Vec<u32>,
    pgids: Vec<u32>,
    sids: Vec<u32>,
    euids: Vec<u32>,
    ttys: Vec<String>,
    invert: bool,
    exclude: Vec<u32>,
}

impl Matcher {
    fn matches(&self, p: &ProcEntry) -> bool {
        if self.exclude.contains(&p.pid) || p.state == 'Z' {
            return false;
        }
        let text = if self.full { p.args() } else { p.comm.clone() };
        let name_ok = match (&self.re, &self.exact_name) {
            (Some(re), _) => re.is_match(&text),
            (None, Some(n)) => *n == text,
            (None, None) => true,
        };
        let ok = name_ok
            && (self.ppids.is_empty() || self.ppids.contains(&p.ppid))
            && (self.pgids.is_empty() || self.pgids.contains(&p.pgid))
            && (self.sids.is_empty() || self.sids.contains(&p.sid))
            && (self.euids.is_empty() || self.euids.contains(&p.uid))
            && (self.ttys.is_empty() || p.tty().is_some_and(|t| self.ttys.iter().any(|x| x.strip_prefix("/dev/").unwrap_or(x) == t)));
        ok != self.invert
    }
}

fn build_regex(pat: &str, icase: bool, exact: bool) -> Result<regex::Regex, String> {
    let p = if exact { alloc::format!("^(?:{pat})$") } else { String::from(pat) };
    regex::RegexBuilder::new(&p).case_insensitive(icase).build().map_err(|e| alloc::format!("{e}"))
}

/// pgrep and pkill share everything but the action.
fn pgrep_common(ctx: &mut Ctx, kill_mode: bool) -> i32 {
    let mut args = ctx.args.clone();
    let mut sig = signal::SIGTERM;
    // `pkill -9 name` / `pkill -KILL name`: a leading signal option.
    if kill_mode {
        if let Some(n) = args.get(1).and_then(|a| leading_signal(a, "flcnoxvieaAr")) {
            sig = n;
            args.remove(1);
        }
    }
    const SPEC: OptSpec = OptSpec {
        flags: "flcnoxvieaAr",
        values: "dPgsuUtFG",
        long: &[
            ("full", 'f', false),
            ("list-name", 'l', false),
            ("list-full", 'a', false),
            ("count", 'c', false),
            ("newest", 'n', false),
            ("oldest", 'o', false),
            ("exact", 'x', false),
            ("inverse", 'v', false),
            ("ignore-case", 'i', false),
            ("echo", 'e', false),
            ("delimiter", 'd', true),
            ("parent", 'P', true),
            ("pgroup", 'g', true),
            ("session", 's', true),
            ("euid", 'u', true),
            ("uid", 'U', true),
            ("terminal", 't', true),
            ("signal", 'S', true),
        ],
    };
    let p = match parse_opts(&args, &SPEC) {
        Ok(p) => p,
        Err(e) => {
            ctx.eprint(&alloc::format!("{}: {e}\n", ctx.name()));
            return 2;
        }
    };
    if let Some(s) = p.value('S') {
        match parse_signal(s) {
            Some(n) => sig = n,
            None => {
                ctx.eprint(&alloc::format!("{}: Unknown signal \"{s}\".\n", ctx.name()));
                return 2;
            }
        }
    }
    if p.operands.len() > 1 {
        ctx.eprint(&alloc::format!("{}: only one pattern can be provided\n", ctx.name()));
        return 2;
    }
    let criteria = ['P', 'g', 's', 'u', 'U', 't'].iter().any(|&c| p.has(c));
    if p.operands.is_empty() && !criteria {
        ctx.eprint(&alloc::format!("{}: no matching criteria specified\nTry `{} --help' for more information.\n", ctx.name(), ctx.name()));
        return 2;
    }
    let re = match p.operands.first() {
        Some(pat) => match build_regex(pat, p.has('i'), p.has('x')) {
            Ok(r) => Some(r),
            Err(e) => {
                ctx.eprint(&alloc::format!("{}: {e}\n", ctx.name()));
                return 2;
            }
        },
        None => None,
    };
    let ids = |c: char| -> Vec<u32> { p.values(c).iter().flat_map(|v| split_list(v).filter_map(|s| s.parse().ok()).collect::<Vec<u32>>()).collect() };
    let mut euids = Vec::new();
    for c in ['u', 'U'] {
        for v in p.values(c) {
            match parse_users(v) {
                Ok(u) => euids.extend(u),
                Err(e) => {
                    ctx.eprint(&alloc::format!("{}: {e}\n", ctx.name()));
                    return 2;
                }
            }
        }
    }
    let m = Matcher {
        re,
        full: p.has('f'),
        exact_name: None,
        ppids: ids('P'),
        pgids: ids('g'),
        sids: ids('s'),
        euids,
        ttys: p.values('t').iter().flat_map(|v| split_list(v).map(|s| s.to_string()).collect::<Vec<_>>()).collect(),
        invert: p.has('v'),
        exclude: alloc::vec![ctx.proc.pid],
    };
    let mut found: Vec<ProcEntry> = pi::list(&ctx.fs()).into_iter().filter(|e| !e.is_kthread() && m.matches(e)).collect();
    if p.has('n') {
        found.sort_by_key(|e| e.start_ticks);
        found = found.pop().into_iter().collect();
    } else if p.has('o') {
        found.sort_by_key(|e| e.start_ticks);
        found.truncate(1);
    }
    if kill_mode {
        let mut hit = 0;
        for e in &found {
            match crate::proc::kill(&ctx.proc, e.pid as i64, sig) {
                Ok(()) => {
                    hit += 1;
                    if p.has('e') {
                        outln!(ctx, "{} killed (pid {})", e.comm, e.pid);
                    }
                }
                Err(err) => {
                    ctx.eprint(&alloc::format!("pkill: killing pid {} failed: {}\n", e.pid, err));
                }
            }
        }
        if p.has('c') {
            outln!(ctx, "{}", hit);
        }
        return if hit > 0 { 0 } else { 1 };
    }
    if p.has('c') {
        outln!(ctx, "{}", found.len());
        return if found.is_empty() { 1 } else { 0 };
    }
    let delim = p.value('d').unwrap_or("\n").to_string();
    let items: Vec<String> = found
        .iter()
        .map(|e| {
            if p.has('a') {
                alloc::format!("{} {}", e.pid, e.args())
            } else if p.has('l') {
                alloc::format!("{} {}", e.pid, e.comm)
            } else {
                e.pid.to_string()
            }
        })
        .collect();
    if !items.is_empty() {
        ctx.print(&items.join(&delim));
        ctx.print("\n");
    }
    if found.is_empty() {
        1
    } else {
        0
    }
}

pub fn pgrep(ctx: &mut Ctx) -> i32 {
    pgrep_common(ctx, false)
}

pub fn pkill(ctx: &mut Ctx) -> i32 {
    pgrep_common(ctx, true)
}

/// Does `name` name process `p`? (comm, or the basename of argv[0]).
fn name_matches(p: &ProcEntry, name: &str) -> bool {
    if p.comm == name {
        return true;
    }
    // comm is truncated to 15 bytes; compare argv[0] for longer names.
    p.cmdline.first().is_some_and(|a0| {
        let a0 = a0.trim_start_matches('-');
        a0 == name || a0.rsplit('/').next() == Some(name)
    })
}

pub fn pidof(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "sqcnx", values: "o", long: &[("single-shot", 's', false), ("quiet", 'q', false), ("omit-pid", 'o', true)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(e) => {
            ctx.fail(e);
            return 2;
        }
    };
    let mut omit: Vec<u32> = alloc::vec![ctx.proc.pid];
    for v in p.values('o') {
        for s in split_list(v) {
            match s {
                "%PPID" => omit.push(ctx.proc.ppid.load(core::sync::atomic::Ordering::Relaxed)),
                _ => omit.extend(s.parse::<u32>().ok()),
            }
        }
    }
    let procs = pi::list(&ctx.fs());
    let mut pids: Vec<u32> = Vec::new();
    for name in &p.operands {
        let mut hits: Vec<u32> = procs.iter().filter(|e| !e.is_kthread() && e.state != 'Z' && !omit.contains(&e.pid) && name_matches(e, name)).map(|e| e.pid).collect();
        hits.sort_unstable_by(|a, b| b.cmp(a));
        if p.has('s') {
            hits.truncate(1);
        }
        pids.extend(hits);
    }
    if pids.is_empty() {
        return 1;
    }
    if !p.has('q') {
        let v: Vec<String> = pids.iter().map(|x| x.to_string()).collect();
        outln!(ctx, "{}", v.join(" "));
    }
    0
}

pub fn killall(ctx: &mut Ctx) -> i32 {
    let mut args = ctx.args.clone();
    let mut sig = signal::SIGTERM;
    // A leading `-SIGNAL` (psmisc accepts it anywhere before the names).
    let mut k = 1;
    while k < args.len() {
        let a = args[k].clone();
        if a == "--" {
            break;
        }
        if let Some(n) = leading_signal(&a, "eIgiqrvwyol") {
            sig = n;
            args.remove(k);
            continue;
        }
        if a == "-s" || a == "-u" {
            k += 1; // skip the option's value
        }
        k += 1;
    }
    const SPEC: OptSpec = OptSpec {
        flags: "eIgiqrvwyo",
        values: "su",
        long: &[
            ("exact", 'e', false),
            ("ignore-case", 'I', false),
            ("interactive", 'i', false),
            ("quiet", 'q', false),
            ("regexp", 'r', false),
            ("verbose", 'v', false),
            ("wait", 'w', false),
            ("signal", 's', true),
            ("user", 'u', true),
            ("list", 'l', false),
        ],
    };
    let p = match parse_opts(&args, &SPEC) {
        Ok(p) => p,
        Err(e) => {
            ctx.fail(e);
            return 1;
        }
    };
    if p.has('l') {
        let t = signal_table();
        ctx.print(&t);
        return 0;
    }
    if let Some(s) = p.value('s') {
        match parse_signal(s) {
            Some(n) => sig = n,
            None => return ctx.fail(alloc::format!("{s}: unknown signal; killall -l lists signals.")),
        }
    }
    if p.operands.is_empty() && !p.has('u') {
        ctx.eprint("Usage: killall [OPTION]... [--] NAME...\n");
        return 1;
    }
    let uid = match p.value('u') {
        Some(u) => match parse_users(u) {
            Ok(v) => v.first().copied(),
            Err(e) => return ctx.fail(e),
        },
        None => None,
    };
    let procs = pi::list(&ctx.fs());
    let me_pid = ctx.proc.pid;
    let mut st = 0;
    let mut killed_pids = Vec::new();
    let names: Vec<String> = if p.operands.is_empty() { alloc::vec![String::new()] } else { p.operands.clone() };
    for name in &names {
        let re = if p.has('r') && !name.is_empty() {
            match build_regex(name, p.has('I'), false) {
                Ok(r) => Some(r),
                Err(e) => return ctx.fail(e),
            }
        } else {
            None
        };
        let mut hit = false;
        for e in procs.iter().filter(|e| !e.is_kthread() && e.pid != me_pid && e.state != 'Z') {
            if uid.is_some_and(|u| u != e.uid) {
                continue;
            }
            let ok = if name.is_empty() {
                true
            } else if let Some(re) = &re {
                re.is_match(&e.comm)
            } else if p.has('I') {
                e.comm.eq_ignore_ascii_case(name)
            } else {
                name_matches(e, name)
            };
            if !ok {
                continue;
            }
            hit = true;
            match crate::proc::kill(&ctx.proc, e.pid as i64, sig) {
                Ok(()) => {
                    killed_pids.push(e.pid);
                    if p.has('v') {
                        ctx.eprint(&alloc::format!("Killed {}({}) with signal {}\n", e.comm, e.pid, sig));
                    }
                }
                Err(err) => {
                    if !p.has('q') {
                        ctx.eprint(&alloc::format!("{}({}): {}\n", e.comm, e.pid, err));
                    }
                    st = 1;
                }
            }
        }
        if !hit {
            if !p.has('q') {
                ctx.eprint(&alloc::format!("{}: no process found\n", if name.is_empty() { "killall" } else { name.as_str() }));
            }
            st = 1;
        }
    }
    if p.has('w') {
        // Wait (up to a minute) until every signalled process is gone.
        for _ in 0..600 {
            if killed_pids.iter().all(|&pid| crate::proc::find(pid).is_none_or(|x| x.is_zombie())) {
                break;
            }
            if !ctx.sleep_ms(100) {
                return 130;
            }
        }
    }
    st
}

// ── free ───────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum Unit {
    Bytes,
    Kibi,
    Mebi,
    Gibi,
    Tebi,
    Kilo,
    Mega,
    Giga,
    Human,
    HumanSi,
}

/// `free -h`: at most four characters before the `i` (procps scale_size).
fn human_free(bytes: u64, si: bool) -> String {
    let base: u64 = if si { 1000 } else { 1024 };
    let units = ['B', 'K', 'M', 'G', 'T', 'P'];
    if bytes < base {
        return alloc::format!("{bytes}B");
    }
    let mut div = base;
    for (i, u) in units.iter().enumerate().skip(1) {
        let suffix = if si { String::from(*u) } else { alloc::format!("{u}i") };
        // One decimal, rounded half up.
        let tenths = (bytes * 10 + div / 2) / div;
        let s = alloc::format!("{}.{}{}", tenths / 10, tenths % 10, u);
        if s.len() <= 4 {
            return alloc::format!("{}.{}{}", tenths / 10, tenths % 10, suffix);
        }
        let whole = bytes / div;
        let s = alloc::format!("{whole}{u}");
        if s.len() <= 4 {
            return alloc::format!("{whole}{suffix}");
        }
        if i + 1 == units.len() {
            return alloc::format!("{whole}{suffix}");
        }
        div *= base;
    }
    alloc::format!("{bytes}B")
}

fn scale(kb: u64, unit: Unit) -> String {
    let b = kb * 1024;
    match unit {
        Unit::Bytes => b.to_string(),
        Unit::Kibi => kb.to_string(),
        Unit::Mebi => (kb / 1024).to_string(),
        Unit::Gibi => (kb / (1024 * 1024)).to_string(),
        Unit::Tebi => (kb / (1024 * 1024 * 1024)).to_string(),
        Unit::Kilo => (b / 1000).to_string(),
        Unit::Mega => (b / 1_000_000).to_string(),
        Unit::Giga => (b / 1_000_000_000).to_string(),
        Unit::Human => human_free(b, false),
        Unit::HumanSi => human_free(b, true),
    }
}

pub fn free(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "bkmghltvw",
        values: "sc",
        long: &[
            ("bytes", 'b', false),
            ("kibi", 'k', false),
            ("mebi", 'm', false),
            ("gibi", 'g', false),
            ("tebi", 'T', false),
            ("kilo", 'K', false),
            ("mega", 'M', false),
            ("giga", 'G', false),
            ("human", 'h', false),
            ("si", 'S', false),
            ("lohi", 'l', false),
            ("total", 't', false),
            ("wide", 'w', false),
            ("seconds", 's', true),
            ("count", 'c', true),
            ("committed", 'v', false),
            ("help", 'H', false),
        ],
    };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(e) => {
            ctx.fail(e);
            ctx.eprint("Usage:\n free [options]\n");
            return 1;
        }
    };
    let si = p.has('S');
    let unit = if p.has('h') {
        if si {
            Unit::HumanSi
        } else {
            Unit::Human
        }
    } else if p.has('b') {
        Unit::Bytes
    } else if p.has('m') {
        Unit::Mebi
    } else if p.has('g') {
        Unit::Gibi
    } else if p.has('T') {
        Unit::Tebi
    } else if p.has('K') {
        Unit::Kilo
    } else if p.has('M') {
        Unit::Mega
    } else if p.has('G') {
        Unit::Giga
    } else {
        Unit::Kibi
    };
    let delay = p.value('s').and_then(|s| s.parse::<u64>().ok());
    let mut count = p.value('c').and_then(|s| s.parse::<u64>().ok());
    if delay.is_some() && count.is_none() {
        count = Some(u64::MAX);
    }
    let mut iter = 0u64;
    loop {
        let m = MemInfo::read(&ctx.fs());
        if p.has('w') {
            outln!(ctx, "               total        used        free      shared     buffers       cache   available");
        } else {
            outln!(ctx, "               total        used        free      shared  buff/cache   available");
        }
        let mut row = alloc::format!("{:<9}{:>11}", "Mem:", scale(m.total(), unit));
        row.push_str(&alloc::format!(" {:>11} {:>11} {:>11}", scale(m.used(), unit), scale(m.free(), unit), scale(m.shared(), unit)));
        if p.has('w') {
            row.push_str(&alloc::format!(" {:>11} {:>11}", scale(m.buffers(), unit), scale(m.cache(), unit)));
        } else {
            row.push_str(&alloc::format!(" {:>11}", scale(m.buffers() + m.cache(), unit)));
        }
        row.push_str(&alloc::format!(" {:>11}", scale(m.available(), unit)));
        outln!(ctx, "{row}");
        let swap_used = m.swap_total().saturating_sub(m.swap_free());
        outln!(ctx, "{:<9}{:>11} {:>11} {:>11}", "Swap:", scale(m.swap_total(), unit), scale(swap_used, unit), scale(m.swap_free(), unit));
        if p.has('t') {
            outln!(
                ctx,
                "{:<9}{:>11} {:>11} {:>11}",
                "Total:",
                scale(m.total() + m.swap_total(), unit),
                scale(m.used() + swap_used, unit),
                scale(m.free() + m.swap_free(), unit)
            );
        }
        iter += 1;
        let Some(c) = count else { break };
        if iter >= c {
            break;
        }
        outln!(ctx);
        if !ctx.sleep_ms(delay.unwrap_or(1) * 1000) {
            return 130;
        }
    }
    0
}

// ── uptime / w / who / users / last ────────────────────────────────────────

fn clock(now: u64) -> String {
    let t = civil::from_unix(now as i64);
    alloc::format!("{:02}:{:02}:{:02}", t.hour, t.min, t.sec)
}

/// The first line of `uptime`, `w` and `top`.
fn uptime_line(ctx: &Ctx, with_clock: bool) -> String {
    let fs = ctx.fs();
    let up = pi::uptime_centis(&fs) / 100;
    let users = crate::utmp::sessions().len();
    let load = LoadAvg::read(&fs);
    let head = if with_clock { alloc::format!(" {} ", clock(crate::time::unix_now())) } else { String::new() };
    alloc::format!(
        "{head}{},  {} user{},  load average: {}",
        pi::fmt_uptime(up),
        users,
        if users == 1 { "" } else { "s" },
        load.text(", ")
    )
}

pub fn uptime(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "psV", values: "", long: &[("pretty", 'p', false), ("since", 's', false), ("version", 'V', false)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(e) => {
            ctx.fail(e);
            return 1;
        }
    };
    let up = pi::uptime_centis(&ctx.fs()) / 100;
    if p.has('s') {
        let t = crate::time::unix_now().saturating_sub(up);
        outln!(ctx, "{}", fmtutil::iso_time(t as i64));
    } else if p.has('p') {
        let (w, d, h, m) = (up / 604800, up / 86400 % 7, up / 3600 % 24, up / 60 % 60);
        let mut parts = Vec::new();
        for (n, unit) in [(w, "week"), (d, "day"), (h, "hour"), (m, "minute")] {
            if n > 0 {
                parts.push(alloc::format!("{n} {unit}{}", if n == 1 { "" } else { "s" }));
            }
        }
        if parts.is_empty() {
            parts.push(String::from("0 minutes"));
        }
        outln!(ctx, "up {}", parts.join(", "));
    } else if p.has('V') {
        outln!(ctx, "uptime from FastROS {}", crate::VERSION);
    } else {
        let l = uptime_line(ctx, true);
        outln!(ctx, "{l}");
    }
    0
}

/// `w` idle column: `3days`, `1:02m`, `4:05`, `12.00s`.
fn fmt_idle(ns: u64) -> String {
    let secs = ns / 1_000_000_000;
    if secs >= 172800 {
        alloc::format!("{}days", secs / 86400)
    } else if secs >= 3600 {
        alloc::format!("{}:{:02}m", secs / 3600, secs / 60 % 60)
    } else if secs >= 60 {
        alloc::format!("{}:{:02}", secs / 60, secs % 60)
    } else {
        alloc::format!("{}.{:02}s", secs, ns / 10_000_000 % 100)
    }
}

/// `w` CPU columns: `1:02` (min:sec) or `0.10s`.
fn fmt_cpu(ticks: u64) -> String {
    let centis = ticks * 100 / HZ;
    if centis >= 6000 {
        alloc::format!("{}:{:02}", centis / 6000, centis / 100 % 60)
    } else {
        alloc::format!("{}.{:02}s", centis / 100, centis % 100)
    }
}

/// `w` LOGIN@: `09:21` today, `Tue09` this week, `11Sep26` older.
fn fmt_login(t: u64, now: u64) -> String {
    let tm = civil::from_unix(t as i64);
    if now.saturating_sub(t) < 86400 && civil::from_unix(now as i64).day == tm.day {
        alloc::format!("{:02}:{:02}", tm.hour, tm.min)
    } else if now.saturating_sub(t) < 7 * 86400 {
        alloc::format!("{}{:02}", civil::WEEKDAYS[tm.weekday as usize], tm.hour)
    } else {
        alloc::format!("{:02}{}{:02}", tm.day, civil::MONTHS[(tm.month - 1) as usize], tm.year % 100)
    }
}

pub fn w(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "hsfiou", values: "", long: &[("no-header", 'h', false), ("short", 's', false), ("from", 'f', false)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(e) => {
            ctx.fail(e);
            return 1;
        }
    };
    let now = crate::time::unix_now();
    if !p.has('h') {
        let l = uptime_line(ctx, true);
        outln!(ctx, "{l}");
        if p.has('s') {
            outln!(ctx, "USER     TTY      FROM              IDLE WHAT");
        } else {
            outln!(ctx, "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT");
        }
    }
    let procs = pi::list(&ctx.fs());
    let filter = p.operands.first().cloned();
    for s in crate::utmp::sessions() {
        if filter.as_ref().is_some_and(|u| *u != s.user) {
            continue;
        }
        let tty = crate::tty::by_name(&s.tty);
        let idle = tty.as_ref().map(|t| t.idle_ns()).unwrap_or(0);
        let dev = crate::fs::procfs::tty_devno(&s.tty);
        let on_tty: Vec<&ProcEntry> = procs.iter().filter(|e| e.tty_nr == dev && dev != 0).collect();
        let jcpu: u64 = on_tty.iter().map(|e| e.cpu_ticks()).sum();
        let fg = tty.as_ref().map(|t| t.fg_pgrp()).unwrap_or(0);
        // WHAT: the foreground process group's leader, else the session leader.
        let current = on_tty
            .iter()
            .filter(|e| e.pgid == fg)
            .max_by_key(|e| e.start_ticks)
            .or_else(|| on_tty.iter().find(|e| e.pid == s.pid))
            .copied();
        let what = current.map(|e| e.args()).unwrap_or_else(|| String::from("-"));
        let pcpu = current.map(|e| e.cpu_ticks()).unwrap_or(0);
        let from = if s.from.is_empty() { String::from("-") } else { s.from.clone() };
        let line = if p.has('s') {
            alloc::format!("{:<9}{:<9}{:<17}{:>5} {}", pi::fit_name(&s.user, 8), s.tty, pi::fit_name(&from, 16), fmt_idle(idle), what)
        } else {
            alloc::format!(
                "{:<9}{:<9}{:<17}{:<6}{:>7}{:>7}{:>7} {}",
                pi::fit_name(&s.user, 8),
                s.tty,
                pi::fit_name(&from, 16),
                fmt_login(s.login_unix, now),
                fmt_idle(idle),
                fmt_cpu(jcpu),
                fmt_cpu(pcpu),
                what
            )
        };
        let (cols, _) = ctx.term_size();
        let line: String = if ctx.stdout_tty().is_some() { line.chars().take(cols).collect() } else { line };
        outln!(ctx, "{line}");
    }
    0
}

/// `2026-09-11 09:21` (who's time column).
fn who_time(t: u64) -> String {
    let tm = civil::from_unix(t as i64);
    alloc::format!("{:04}-{:02}-{:02} {:02}:{:02}", tm.year, tm.month, tm.day, tm.hour, tm.min)
}

pub fn who(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "abdHlmpqrsTuw",
        values: "",
        long: &[
            ("all", 'a', false),
            ("boot", 'b', false),
            ("heading", 'H', false),
            ("count", 'q', false),
            ("short", 's', false),
            ("users", 'u', false),
            ("mesg", 'T', false),
        ],
    };
    let mut p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(e) => {
            ctx.fail(e);
            return 1;
        }
    };
    // `who am i` == `who -m`.
    let am_i = p.operands.len() == 2 && p.operands[0] == "am" && (p.operands[1] == "i" || p.operands[1] == "I");
    if am_i {
        p.operands.clear();
    }
    let only_mine = am_i || p.has('m');
    let sessions = crate::utmp::sessions();
    if p.has('q') {
        let names: Vec<&str> = sessions.iter().map(|s| s.user.as_str()).collect();
        outln!(ctx, "{}", names.join(" "));
        outln!(ctx, "# users={}", names.len());
        return 0;
    }
    let all = p.has('a');
    let with_idle = p.has('u') || all;
    if p.has('H') {
        if with_idle {
            outln!(ctx, "NAME     LINE         TIME             IDLE          PID COMMENT");
        } else {
            outln!(ctx, "NAME     LINE         TIME             COMMENT");
        }
    }
    if p.has('b') || all {
        let boot = crate::time::unix_now().saturating_sub(crate::time::uptime_secs());
        outln!(ctx, "         system boot  {}", who_time(boot));
        if p.has('b') && !all {
            return 0;
        }
    }
    let my_tty = ctx.proc.ctty.lock().as_ref().map(|t| t.name.clone());
    for s in sessions {
        if only_mine && my_tty.as_deref() != Some(s.tty.as_str()) {
            continue;
        }
        let comment = if s.from.is_empty() { String::new() } else { alloc::format!(" ({})", s.from) };
        if with_idle {
            let idle = crate::tty::by_name(&s.tty).map(|t| t.idle_ns() / 1_000_000_000).unwrap_or(0);
            let idle_s = if idle < 60 {
                String::from("  .  ")
            } else if idle < 86400 {
                alloc::format!("{:02}:{:02}", idle / 3600, idle / 60 % 60)
            } else {
                String::from(" old ")
            };
            outln!(ctx, "{:<8} {:<12} {} {:<11} {:>5}{}", s.user, s.tty, who_time(s.login_unix), idle_s, s.pid, comment);
        } else {
            outln!(ctx, "{:<8} {:<12} {}{}", s.user, s.tty, who_time(s.login_unix), comment);
        }
    }
    0
}

pub fn users(ctx: &mut Ctx) -> i32 {
    let mut names: Vec<String> = crate::utmp::sessions().into_iter().map(|s| s.user).collect();
    names.sort();
    if !names.is_empty() {
        outln!(ctx, "{}", names.join(" "));
    }
    0
}

/// `Fri Sep 11 09:21` (last's login column).
fn last_time(t: u64) -> String {
    let tm = civil::from_unix(t as i64);
    alloc::format!("{} {} {:>2} {:02}:{:02}", civil::WEEKDAYS[tm.weekday as usize], civil::MONTHS[(tm.month - 1) as usize], tm.day, tm.hour, tm.min)
}

fn last_duration(secs: u64) -> String {
    let (d, h, m) = (secs / 86400, secs / 3600 % 24, secs / 60 % 60);
    if d > 0 {
        alloc::format!("({d}+{h:02}:{m:02})")
    } else {
        alloc::format!("({h:02}:{m:02})")
    }
}

pub fn last(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "xFaiwR", values: "nf", long: &[("limit", 'n', true), ("file", 'f', true), ("system", 'x', false)] };
    let args: Vec<String> = ctx
        .args
        .iter()
        .map(|a| if a.len() > 1 && a.starts_with('-') && a[1..].bytes().all(|b| b.is_ascii_digit()) { alloc::format!("-n{}", &a[1..]) } else { a.clone() })
        .collect();
    let p = match parse_opts(&args, &SPEC) {
        Ok(p) => p,
        Err(e) => {
            ctx.fail(e);
            return 1;
        }
    };
    let path = p.value('f').unwrap_or(crate::utmp::WTMP).to_string();
    let fs = ctx.fs();
    let data = match crate::fs::ops::read_file(&fs, &path) {
        Ok(d) => d,
        Err(e) => return ctx.fail_errno(&path, e),
    };
    let recs: Vec<crate::utmp::Record> = data.chunks_exact(crate::utmp::RECORD_SIZE).filter_map(crate::utmp::Record::decode).collect();
    let limit = p.value('n').and_then(|n| n.parse::<usize>().ok()).unwrap_or(usize::MAX);
    let filters = &p.operands;
    let now = crate::time::unix_now();
    let live: Vec<u32> = crate::utmp::sessions().iter().map(|s| s.pid).collect();
    let mut shown = 0;
    // Walk newest first; a login ends at its DEAD_PROCESS record, or at the
    // next boot/shutdown record after it.
    let mut lines = Vec::new();
    let mut ended: BTreeMap<String, u64> = BTreeMap::new(); // line → logout time
    let mut last_down: Option<(u64, bool)> = None; // (time, was a clean shutdown)
    for r in recs.iter().rev() {
        match r.kind {
            crate::utmp::DEAD_PROCESS => {
                ended.insert(r.line.clone(), r.time);
            }
            crate::utmp::USER_PROCESS => {
                let status = if let Some(t) = ended.remove(&r.line) {
                    alloc::format!("- {:<5}  {}", clock(t).get(..5).unwrap_or(""), last_duration(t.saturating_sub(r.time)))
                } else if live.contains(&r.pid) && last_down.is_none() {
                    String::from("  still logged in")
                } else if let Some((t, clean)) = last_down {
                    alloc::format!("- {:<5}  {}", if clean { "down" } else { "crash" }, last_duration(t.saturating_sub(r.time)))
                } else {
                    String::from("  gone - no logout")
                };
                if filters.is_empty() || filters.iter().any(|f| *f == r.user || *f == r.line) {
                    lines.push(alloc::format!("{:<8} {:<12} {:<16} {} {}", pi::fit_name(&r.user, 8), r.line, pi::fit_name(&r.host, 16), last_time(r.time), status));
                }
            }
            crate::utmp::BOOT_TIME => {
                let status = match last_down {
                    Some((t, _)) => alloc::format!("- {:<5}  {}", clock(t).get(..5).unwrap_or(""), last_duration(t.saturating_sub(r.time))),
                    None => String::from("  still running"),
                };
                if filters.is_empty() || filters.iter().any(|f| f == "reboot") || p.has('x') {
                    lines.push(alloc::format!("{:<8} {:<12} {:<16} {} {}", "reboot", "system boot", r.host, last_time(r.time), status));
                }
                // Logins before this boot that never logged out crashed.
                last_down = Some((r.time, false));
                ended.clear();
            }
            crate::utmp::RUN_LVL => {
                if p.has('x') {
                    lines.push(alloc::format!("{:<8} {:<12} {:<16} {} {}", "shutdown", "system down", r.host, last_time(r.time), "  -"));
                }
                last_down = Some((r.time, true));
            }
            _ => {}
        }
    }
    let _ = now;
    for l in lines {
        if shown >= limit {
            break;
        }
        outln!(ctx, "{}", l.trim_end());
        shown += 1;
    }
    let begins = recs.first().map(|r| r.time).unwrap_or_else(crate::time::unix_now);
    outln!(ctx);
    outln!(ctx, "{} begins {}", path.rsplit('/').next().unwrap_or("wtmp"), fmtutil::date_string(begins as i64).replace(" UTC", ""));
    0
}

pub fn nproc(ctx: &mut Ctx) -> i32 {
    let n = SysStat::read(&ctx.fs()).cpus.len().max(1);
    outln!(ctx, "{n}");
    0
}

// ── vmstat ─────────────────────────────────────────────────────────────────

struct VmSample {
    cpu: pi::CpuTimes,
    intr: u64,
    ctxt: u64,
    pgin: u64,
    pgout: u64,
    running: u64,
    blocked: u64,
}

fn vm_sample(ctx: &Ctx) -> VmSample {
    let fs = ctx.fs();
    let st = SysStat::read(&fs);
    let text = crate::fs::ops::read_file(&fs, "/proc/stat").map(|d| String::from_utf8_lossy(&d).into_owned()).unwrap_or_default();
    let intr = text.lines().find(|l| l.starts_with("intr ")).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse().ok()).unwrap_or(0);
    let vm = crate::fs::ops::read_file(&fs, "/proc/vmstat").map(|d| String::from_utf8_lossy(&d).into_owned()).unwrap_or_default();
    let get = |k: &str| vm.lines().find_map(|l| l.strip_prefix(k).and_then(|v| v.trim().parse::<u64>().ok())).unwrap_or(0);
    VmSample { cpu: st.cpu, intr, ctxt: st.ctxt, pgin: get("pgpgin "), pgout: get("pgpgout "), running: st.running, blocked: st.blocked }
}

pub fn vmstat(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "anwsSt", values: "", long: &[("active", 'a', false), ("one-header", 'n', false), ("wide", 'w', false), ("timestamp", 't', false)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(e) => {
            ctx.fail(e);
            return 1;
        }
    };
    let delay = p.operands.first().and_then(|d| d.parse::<u64>().ok());
    let count = p.operands.get(1).and_then(|c| c.parse::<u64>().ok()).or(if delay.is_some() { None } else { Some(1) });
    let up_secs = (pi::uptime_centis(&ctx.fs()) / 100).max(1);
    let mut prev = VmSample { cpu: pi::CpuTimes::default(), intr: 0, ctxt: 0, pgin: 0, pgout: 0, running: 0, blocked: 0 };
    let mut interval = up_secs;
    let mut n = 0u64;
    outln!(ctx, "procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----");
    outln!(ctx, " r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st");
    loop {
        let s = vm_sample(ctx);
        let m = MemInfo::read(&ctx.fs());
        let d = s.cpu.since(&prev.cpu);
        let total = d.total().max(1);
        let pct = |v: u64| v * 100 / total;
        let rate = |now: u64, old: u64| now.saturating_sub(old) / interval.max(1);
        outln!(
            ctx,
            "{:>2} {:>2} {:>6} {:>6} {:>6} {:>6} {:>4} {:>4} {:>5} {:>5} {:>4} {:>4} {:>2} {:>2} {:>2} {:>2} {:>2}",
            s.running,
            s.blocked,
            m.swap_total().saturating_sub(m.swap_free()),
            m.free(),
            m.buffers(),
            m.cache(),
            0,
            0,
            rate(s.pgin, prev.pgin),
            rate(s.pgout, prev.pgout),
            rate(s.intr, prev.intr),
            rate(s.ctxt, prev.ctxt),
            pct(d.user + d.nice),
            pct(d.system + d.irq + d.softirq),
            pct(d.idle),
            pct(d.iowait),
            pct(d.steal)
        );
        n += 1;
        if count.is_some_and(|c| n >= c) {
            break;
        }
        let Some(dl) = delay else { break };
        prev = s;
        interval = dl.max(1);
        if !ctx.sleep_ms(dl.max(1) * 1000) {
            return 130;
        }
    }
    0
}
