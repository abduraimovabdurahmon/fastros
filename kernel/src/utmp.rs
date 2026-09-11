//! Login accounting: who is logged in now (`who`, `w`, `users`) and the
//! login history in `/var/log/wtmp` (`last`).
//!
//! `/var/log/wtmp` uses the exact glibc x86_64 `struct utmp` layout (384
//! bytes per record), so Linux tools inside containers can read it too.

use crate::fs::ops;
use crate::sync::SpinLock;
use alloc::string::String;
use alloc::vec::Vec;

pub const WTMP: &str = "/var/log/wtmp";

/// `ut_type` values.
pub const BOOT_TIME: i16 = 2;
pub const RUN_LVL: i16 = 1;
pub const USER_PROCESS: i16 = 7;
pub const DEAD_PROCESS: i16 = 8;

pub const RECORD_SIZE: usize = 384;

/// A current login session.
#[derive(Clone, Debug)]
pub struct Session {
    pub user: String,
    /// Terminal name without `/dev/` (`pts/0`, `console`).
    pub tty: String,
    /// Remote host, empty for local logins.
    pub from: String,
    pub login_unix: u64,
    /// The session leader (login shell).
    pub pid: u32,
}

static SESSIONS: SpinLock<Vec<Session>> = SpinLock::new(Vec::new());

/// Record a login: add it to the live table and append to wtmp.
pub fn login(s: Session) {
    append(&Record {
        kind: USER_PROCESS,
        pid: s.pid,
        line: s.tty.clone(),
        user: s.user.clone(),
        host: s.from.clone(),
        time: s.login_unix,
    });
    SESSIONS.lock().push(s);
}

/// Record the end of the session led by `pid`.
pub fn logout(pid: u32) {
    let gone = {
        let mut v = SESSIONS.lock();
        let i = v.iter().position(|s| s.pid == pid);
        i.map(|i| v.remove(i))
    };
    if let Some(s) = gone {
        append(&Record { kind: DEAD_PROCESS, pid, line: s.tty, user: String::new(), host: String::new(), time: crate::time::unix_now() });
    }
}

/// Live sessions whose leader is still running.
pub fn sessions() -> Vec<Session> {
    let mut v = SESSIONS.lock().clone();
    v.retain(|s| crate::proc::find(s.pid).is_some_and(|p| !p.is_zombie()));
    v
}

/// Boot and shutdown markers (`last reboot`).
pub fn boot() {
    append(&Record {
        kind: BOOT_TIME,
        pid: 0,
        line: String::from("~"),
        user: String::from("reboot"),
        host: String::from(crate::VERSION),
        time: crate::time::unix_now().saturating_sub(crate::time::uptime_secs()),
    });
}

pub fn shutdown() {
    append(&Record {
        kind: RUN_LVL,
        pid: 0,
        line: String::from("~"),
        user: String::from("shutdown"),
        host: String::from(crate::VERSION),
        time: crate::time::unix_now(),
    });
}

/// One wtmp record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub kind: i16,
    pub pid: u32,
    pub line: String,
    pub user: String,
    pub host: String,
    pub time: u64,
}

fn put_str(buf: &mut [u8], s: &str) {
    let b = s.as_bytes();
    let n = b.len().min(buf.len());
    buf[..n].copy_from_slice(&b[..n]);
}

fn get_str(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

impl Record {
    pub fn encode(&self) -> [u8; RECORD_SIZE] {
        let mut r = [0u8; RECORD_SIZE];
        r[0..2].copy_from_slice(&self.kind.to_le_bytes());
        r[4..8].copy_from_slice(&self.pid.to_le_bytes());
        put_str(&mut r[8..40], &self.line);
        // ut_id: the last four characters of the line, as login(1) does.
        let id = self.line.strip_prefix("pts/").unwrap_or(&self.line);
        put_str(&mut r[40..44], &id[id.len().saturating_sub(4)..]);
        put_str(&mut r[44..76], &self.user);
        put_str(&mut r[76..332], &self.host);
        r[336..340].copy_from_slice(&(self.pid as i32).to_le_bytes());
        r[340..344].copy_from_slice(&(self.time as i32).to_le_bytes());
        r
    }

    pub fn decode(r: &[u8]) -> Option<Record> {
        if r.len() < RECORD_SIZE {
            return None;
        }
        Some(Record {
            kind: i16::from_le_bytes([r[0], r[1]]),
            pid: u32::from_le_bytes([r[4], r[5], r[6], r[7]]),
            line: get_str(&r[8..40]),
            user: get_str(&r[44..76]),
            host: get_str(&r[76..332]),
            time: u32::from_le_bytes([r[340], r[341], r[342], r[343]]) as u64,
        })
    }
}

fn append(rec: &Record) {
    let ctx = ops::Ctx::of(&crate::proc::kernel());
    let fl = crate::fs::file::flags::O_WRONLY | crate::fs::file::flags::O_CREAT | crate::fs::file::flags::O_APPEND;
    match ops::open(&ctx, WTMP, fl, 0o664) {
        Ok(f) => {
            let _ = f.write_all(&rec.encode());
        }
        Err(e) => crate::kdebug!("utmp", "{WTMP}: {e}"),
    }
}

/// Every record in wtmp, oldest first.
pub fn read_wtmp(ctx: &ops::Ctx) -> crate::errno::KResult<Vec<Record>> {
    let data = ops::read_file(ctx, WTMP)?;
    Ok(data.chunks_exact(RECORD_SIZE).filter_map(Record::decode).collect())
}
