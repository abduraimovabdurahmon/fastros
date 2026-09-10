//! Kernel user/group management subsystem
//!
//! Equivalent of Linux include/linux/cred.h + kernel/cred.c
//!
//! Global databases:
//!   USER_DB  — all user accounts  (/etc/passwd + /etc/shadow combined)
//!   GROUP_DB — all groups         (/etc/group)
//!
//! Both are protected by a single SpinLock and accessed via
//! with_users() / with_groups() closures.

pub mod auth;
pub mod group;
pub mod permission;
pub mod user;

use user::UserTable;
use group::GroupTable;
use crate::kernel::sync::spinlock::SpinLock;

static     DB_LOCK:  SpinLock   = SpinLock::new();
static mut USER_DB:  UserTable  = UserTable::new();
static mut GROUP_DB: GroupTable = GroupTable::new();

// ── Boot initialization ────────────────────────────────────────────────────────

/// Populate default users and groups. Called once from kernel_main() before
/// the shell starts. Mirrors what Linux reads from /etc/passwd at boot.
pub fn init() {
    DB_LOCK.lock();
    unsafe {
        // ── Users (/etc/passwd equivalent) ────────────────────────────────────
        // root: uid=0 gid=0 home=/root shell=/bin/sh passwd="root"
        USER_DB.add(0,     0,     b"root",   b"root",   b"/root",  b"/bin/sh");
        // nobody: uid=65534 — unprivileged service account
        USER_DB.add(65534, 65534, b"nobody", b"",       b"/",      b"/bin/false");

        // ── Groups (/etc/group equivalent) ────────────────────────────────────
        GROUP_DB.add(0,     b"root");    // gid=0
        GROUP_DB.add_member(0, 0);       // root is in root group

        GROUP_DB.add(100,   b"users");   // gid=100  — default group for new users
        GROUP_DB.add(65534, b"nobody");  // gid=65534
        GROUP_DB.add_member(65534, 65534);

        // Supplementary groups root belongs to (mirror real Linux)
        GROUP_DB.add(4,  b"adm");
        GROUP_DB.add_member(4, 0);
        GROUP_DB.add(27, b"sudo");
        GROUP_DB.add_member(27, 0);
    }
    DB_LOCK.unlock();
}

// ── Locked accessors ──────────────────────────────────────────────────────────

pub fn with_users<F, R>(f: F) -> R where F: FnOnce(&UserTable) -> R {
    DB_LOCK.lock();
    let r = unsafe { f(&USER_DB) };
    DB_LOCK.unlock();
    r
}

pub fn with_users_mut<F, R>(f: F) -> R where F: FnOnce(&mut UserTable) -> R {
    DB_LOCK.lock();
    let r = unsafe { f(&mut USER_DB) };
    DB_LOCK.unlock();
    r
}

pub fn with_groups<F, R>(f: F) -> R where F: FnOnce(&GroupTable) -> R {
    DB_LOCK.lock();
    let r = unsafe { f(&GROUP_DB) };
    DB_LOCK.unlock();
    r
}

pub fn with_groups_mut<F, R>(f: F) -> R where F: FnOnce(&mut GroupTable) -> R {
    DB_LOCK.lock();
    let r = unsafe { f(&mut GROUP_DB) };
    DB_LOCK.unlock();
    r
}

// ── Convenience helpers ────────────────────────────────────────────────────────

/// Verify username + password. Returns true on success.
/// Locked accounts (empty password) always fail.
pub fn verify(username: &[u8], password: &[u8]) -> bool {
    with_users(|db| {
        match db.find_by_name(username) {
            Some(u) if !u.locked => auth::verify_password(password, u.passwd_hash),
            _ => false,
        }
    })
}

/// Look up username → (uid, gid, home).
/// Returns None if user not found.
pub fn lookup_user(username: &[u8]) -> Option<(u32, u32, [u8; 64], usize)> {
    with_users(|db| {
        db.find_by_name(username).map(|u| {
            let mut home = [0u8; 64];
            let hn = u.home_len.min(64);
            home[..hn].copy_from_slice(&u.home[..hn]);
            (u.uid, u.gid, home, hn)
        })
    })
}

/// Look up uid → username bytes (copied into `out`). Returns length.
pub fn uid_to_name(uid: u32, out: &mut [u8; 32]) -> usize {
    with_users(|db| {
        match db.find_by_uid(uid) {
            Some(u) => {
                let n = u.name_len.min(32);
                out[..n].copy_from_slice(&u.name[..n]);
                n
            }
            None => {
                // Fall back to numeric uid
                let mut tmp = [0u8; 10];
                let n = u32_to_dec(uid, &mut tmp);
                let n2 = n.min(32);
                out[..n2].copy_from_slice(&tmp[..n2]);
                n2
            }
        }
    })
}

/// Look up gid → group name (copied into `out`). Returns length.
pub fn gid_to_name(gid: u32, out: &mut [u8; 32]) -> usize {
    with_groups(|db| {
        match db.find_by_gid(gid) {
            Some(g) => {
                let n = g.name_len.min(32);
                out[..n].copy_from_slice(&g.name[..n]);
                n
            }
            None => {
                let mut tmp = [0u8; 10];
                let n = u32_to_dec(gid, &mut tmp);
                let n2 = n.min(32);
                out[..n2].copy_from_slice(&tmp[..n2]);
                n2
            }
        }
    })
}

fn u32_to_dec(mut n: u32, buf: &mut [u8; 10]) -> usize {
    if n == 0 { buf[0] = b'0'; return 1; }
    let mut tmp = [0u8; 10];
    let mut len = 0;
    while n > 0 { tmp[len] = b'0' + (n % 10) as u8; n /= 10; len += 1; }
    for i in 0..len { buf[i] = tmp[len - 1 - i]; }
    len
}
