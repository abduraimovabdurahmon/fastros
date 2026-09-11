//! User and group databases (`/etc/passwd`, `/etc/group`, `/etc/shadow`)
//! in the standard Linux formats, and authentication.
//!
//! Passwords are hashed with Argon2id (memory-hard; far stronger against
//! GPU cracking than the SHA-512 crypt most Linux systems still use),
//! stored in PHC format: `$argon2id$v=19$m=8192,t=2,p=1$<salt>$<hash>`.
//! Verification is constant-time and every failure costs a fixed delay.

use crate::errno::{Errno, KResult};
use crate::fs::ops::{self, Ctx};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use fastros_codec::base64;

pub const PASSWD: &str = "/etc/passwd";
pub const GROUP: &str = "/etc/group";
pub const SHADOW: &str = "/etc/shadow";

const ARGON_M_KIB: u32 = 8192;
const ARGON_T: u32 = 2;
const ARGON_P: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub home: String,
    pub shell: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

fn root_ctx() -> Ctx {
    let k = crate::proc::kernel();
    Ctx::of(&k)
}

fn read_lines(path: &str) -> Vec<String> {
    match ops::read_file(&root_ctx(), path) {
        Ok(d) => String::from_utf8_lossy(&d).lines().map(|l| l.to_string()).collect(),
        Err(_) => Vec::new(),
    }
}

fn write_lines(path: &str, lines: &[String], mode: u16) -> KResult<()> {
    let mut s = lines.join("\n");
    s.push('\n');
    // Write a sibling then rename: a crash never leaves a half-written database.
    let tmp = format!("{path}+");
    let ctx = root_ctx();
    ops::write_file(&ctx, &tmp, s.as_bytes(), mode)?;
    ops::chmod(&ctx, &tmp, mode, true)?;
    ops::rename(&ctx, &tmp, path)
}

fn parse_user(l: &str) -> Option<User> {
    let f: Vec<&str> = l.split(':').collect();
    if f.len() < 7 {
        return None;
    }
    Some(User {
        name: f[0].to_string(),
        uid: f[2].parse().ok()?,
        gid: f[3].parse().ok()?,
        gecos: f[4].to_string(),
        home: f[5].to_string(),
        shell: f[6].to_string(),
    })
}

fn parse_group(l: &str) -> Option<Group> {
    let f: Vec<&str> = l.split(':').collect();
    if f.len() < 4 {
        return None;
    }
    Some(Group {
        name: f[0].to_string(),
        gid: f[2].parse().ok()?,
        members: f[3].split(',').filter(|m| !m.is_empty()).map(|m| m.to_string()).collect(),
    })
}

pub fn users() -> Vec<User> {
    read_lines(PASSWD).iter().filter_map(|l| parse_user(l)).collect()
}

pub fn groups() -> Vec<Group> {
    read_lines(GROUP).iter().filter_map(|l| parse_group(l)).collect()
}

pub fn by_name(name: &str) -> Option<User> {
    users().into_iter().find(|u| u.name == name)
}

pub fn by_uid(uid: u32) -> Option<User> {
    users().into_iter().find(|u| u.uid == uid)
}

pub fn group_by_gid(gid: u32) -> Option<Group> {
    groups().into_iter().find(|g| g.gid == gid)
}

pub fn group_by_name(name: &str) -> Option<Group> {
    groups().into_iter().find(|g| g.name == name)
}

pub fn user_name(uid: u32) -> String {
    by_uid(uid).map(|u| u.name).unwrap_or_else(|| uid.to_string())
}

pub fn group_name(gid: u32) -> String {
    group_by_gid(gid).map(|g| g.name).unwrap_or_else(|| gid.to_string())
}

/// Supplementary groups of `user` (from /etc/group membership).
pub fn supplementary(user: &str) -> Vec<u32> {
    groups().into_iter().filter(|g| g.members.iter().any(|m| m == user)).map(|g| g.gid).collect()
}

/// Credentials for a login as `u`.
pub fn cred_for(u: &User) -> crate::fs::perm::Cred {
    crate::fs::perm::Cred::user(u.uid, u.gid, supplementary(&u.name))
}

/// May `u` use sudo? (member of `sudo` or `wheel`, or root)
pub fn is_admin(u: &User) -> bool {
    u.uid == 0 || groups().iter().any(|g| (g.name == "sudo" || g.name == "wheel") && g.members.iter().any(|m| m == &u.name))
}

pub fn valid_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 32
        && n.bytes().next().is_some_and(|b| b.is_ascii_lowercase() || b == b'_')
        && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

// ── password hashing ───────────────────────────────────────────────────────

fn argon2(password: &[u8], salt: &[u8], m: u32, t: u32, p: u32) -> Option<[u8; 32]> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(m, t, p, Some(32)).ok()?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    a.hash_password_into(password, salt, &mut out).ok()?;
    Some(out)
}

pub fn hash_password(password: &str) -> String {
    let salt: [u8; 16] = crate::crypto::rng::array();
    let h = argon2(password.as_bytes(), &salt, ARGON_M_KIB, ARGON_T, ARGON_P).expect("argon2 parameters are valid");
    format!(
        "$argon2id$v=19$m={ARGON_M_KIB},t={ARGON_T},p={ARGON_P}${}${}",
        base64::encode_nopad(&salt),
        base64::encode_nopad(&h)
    )
}

/// Verify against a PHC argon2id string. Locked (`!`, `*`) or empty
/// hashes never match.
pub fn verify_hash(password: &str, phc: &str) -> bool {
    let parts: Vec<&str> = phc.split('$').collect();
    // ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash]
    if parts.len() != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
        return false;
    }
    let mut m = 0;
    let mut t = 0;
    let mut p = 0;
    for kv in parts[3].split(',') {
        match kv.split_once('=') {
            Some(("m", v)) => m = v.parse().unwrap_or(0),
            Some(("t", v)) => t = v.parse().unwrap_or(0),
            Some(("p", v)) => p = v.parse().unwrap_or(0),
            _ => return false,
        }
    }
    if !(8..=1 << 20).contains(&m) || !(1..=16).contains(&t) || !(1..=4).contains(&p) {
        return false;
    }
    let (Some(salt), Some(want)) = (base64::decode(parts[4]), base64::decode(parts[5])) else { return false };
    match argon2(password.as_bytes(), &salt, m, t, p) {
        Some(h) => crate::crypto::ct_eq(&h, &want),
        None => false,
    }
}

fn shadow_entry(name: &str) -> Option<Vec<String>> {
    read_lines(SHADOW)
        .into_iter()
        .map(|l| l.split(':').map(|s| s.to_string()).collect::<Vec<_>>())
        .find(|f| f.first().is_some_and(|n| n == name))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    BadCredentials,
    Locked,
}

/// Check a password. On failure the caller should not reveal which part
/// was wrong; unknown users cost the same time as wrong passwords.
pub fn authenticate(name: &str, password: &str) -> Result<User, AuthError> {
    let user = by_name(name);
    let hash = shadow_entry(name).and_then(|f| f.get(1).cloned());
    let ok = match (&user, &hash) {
        (Some(_), Some(h)) if h.starts_with('!') || h == "*" => {
            let _ = verify_hash(password, DUMMY_HASH);
            return Err(AuthError::Locked);
        }
        (Some(_), Some(h)) => verify_hash(password, h),
        _ => {
            let _ = verify_hash(password, DUMMY_HASH);
            false
        }
    };
    if ok {
        Ok(user.expect("matched above"))
    } else {
        Err(AuthError::BadCredentials)
    }
}

/// Burns the same argon2 work for unknown users (no timing oracle).
const DUMMY_HASH: &str = "$argon2id$v=19$m=8192,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn days_since_epoch() -> u64 {
    crate::time::unix_now() / 86400
}

fn set_password_unlocked(name: &str, password: &str) -> KResult<()> {
    if by_name(name).is_none() {
        return Err(Errno::ENOENT);
    }
    let hash = hash_password(password);
    let mut lines = read_lines(SHADOW);
    let entry = format!("{name}:{hash}:{}:0:99999:7:::", days_since_epoch());
    match lines.iter_mut().find(|l| l.split(':').next() == Some(name)) {
        Some(l) => *l = entry,
        None => lines.push(entry),
    }
    write_lines(SHADOW, &lines, 0o600)
}

fn lock_password_unlocked(name: &str, lock: bool) -> KResult<()> {
    let mut lines = read_lines(SHADOW);
    let l = lines.iter_mut().find(|l| l.split(':').next() == Some(name)).ok_or(Errno::ENOENT)?;
    let mut f: Vec<String> = l.split(':').map(|s| s.to_string()).collect();
    if f.len() < 2 {
        return Err(Errno::EINVAL);
    }
    if lock && !f[1].starts_with('!') {
        f[1] = format!("!{}", f[1]);
    } else if !lock {
        f[1] = f[1].trim_start_matches('!').to_string();
    }
    *l = f.join(":");
    write_lines(SHADOW, &lines, 0o600)
}

pub fn password_status(name: &str) -> Option<&'static str> {
    let f = shadow_entry(name)?;
    let h = f.get(1)?;
    Some(if h.starts_with('!') {
        "L"
    } else if h.is_empty() || h == "*" {
        "NP"
    } else {
        "P"
    })
}

// ── account management ─────────────────────────────────────────────────────

pub struct NewUser<'a> {
    pub name: &'a str,
    pub uid: Option<u32>,
    pub group: Option<u32>,
    pub gecos: &'a str,
    pub home: Option<&'a str>,
    pub shell: &'a str,
    pub create_home: bool,
    pub extra_groups: Vec<String>,
}

fn next_free(used: impl Iterator<Item = u32>, from: u32) -> u32 {
    let mut v: Vec<u32> = used.filter(|&x| x >= from).collect();
    v.sort_unstable();
    let mut cand = from;
    for x in v {
        if x == cand {
            cand += 1;
        } else if x > cand {
            break;
        }
    }
    cand
}

fn add_group_unlocked(name: &str, gid: Option<u32>) -> KResult<u32> {
    if !valid_name(name) {
        return Err(Errno::EINVAL);
    }
    let gs = groups();
    if gs.iter().any(|g| g.name == name) {
        return Err(Errno::EEXIST);
    }
    let gid = match gid {
        Some(g) if gs.iter().any(|x| x.gid == g) => return Err(Errno::EEXIST),
        Some(g) => g,
        None => next_free(gs.iter().map(|g| g.gid), 1000),
    };
    let mut lines = read_lines(GROUP);
    lines.push(format!("{name}:x:{gid}:"));
    write_lines(GROUP, &lines, 0o644)?;
    Ok(gid)
}

fn del_group_unlocked(name: &str) -> KResult<()> {
    let g = group_by_name(name).ok_or(Errno::ENOENT)?;
    if users().iter().any(|u| u.gid == g.gid) {
        return Err(Errno::EBUSY); // primary group of a user
    }
    let lines: Vec<String> = read_lines(GROUP).into_iter().filter(|l| l.split(':').next() != Some(name)).collect();
    write_lines(GROUP, &lines, 0o644)
}

fn add_to_group_unlocked(user: &str, group: &str) -> KResult<()> {
    let mut lines = read_lines(GROUP);
    let l = lines.iter_mut().find(|l| l.split(':').next() == Some(group)).ok_or(Errno::ENOENT)?;
    let mut g = parse_group(l).ok_or(Errno::EINVAL)?;
    if !g.members.iter().any(|m| m == user) {
        g.members.push(user.to_string());
    }
    *l = format!("{}:x:{}:{}", g.name, g.gid, g.members.join(","));
    write_lines(GROUP, &lines, 0o644)
}

fn remove_from_groups_unlocked(user: &str) -> KResult<()> {
    let lines: Vec<String> = read_lines(GROUP)
        .into_iter()
        .map(|l| match parse_group(&l) {
            Some(mut g) if g.members.iter().any(|m| m == user) => {
                g.members.retain(|m| m != user);
                format!("{}:x:{}:{}", g.name, g.gid, g.members.join(","))
            }
            _ => l,
        })
        .collect();
    write_lines(GROUP, &lines, 0o644)
}

fn add_user_unlocked(n: &NewUser) -> KResult<User> {
    if !valid_name(n.name) {
        return Err(Errno::EINVAL);
    }
    let all = users();
    if all.iter().any(|u| u.name == n.name) {
        return Err(Errno::EEXIST);
    }
    let uid = match n.uid {
        Some(u) if all.iter().any(|x| x.uid == u) => return Err(Errno::EEXIST),
        Some(u) => u,
        None => next_free(all.iter().map(|u| u.uid), 1000),
    };
    let gid = match n.group {
        Some(g) => g,
        None => match group_by_name(n.name) {
            Some(g) => g.gid,
            None => add_group_unlocked(n.name, Some(uid)).or_else(|_| add_group_unlocked(n.name, None))?,
        },
    };
    let home = n.home.map(|h| h.to_string()).unwrap_or_else(|| format!("/home/{}", n.name));
    let u = User { name: n.name.to_string(), uid, gid, gecos: n.gecos.to_string(), home, shell: n.shell.to_string() };
    let mut lines = read_lines(PASSWD);
    lines.push(format!("{}:x:{}:{}:{}:{}:{}", u.name, u.uid, u.gid, u.gecos, u.home, u.shell));
    write_lines(PASSWD, &lines, 0o644)?;
    let mut sh = read_lines(SHADOW);
    sh.push(format!("{}:!:{}:0:99999:7:::", u.name, days_since_epoch()));
    write_lines(SHADOW, &sh, 0o600)?;
    for g in &n.extra_groups {
        add_to_group_unlocked(&u.name, g)?;
    }
    if n.create_home {
        let ctx = root_ctx();
        match ops::mkdir(&ctx, &u.home, 0o750) {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(e) => return Err(e),
        }
        ops::chown(&ctx, &u.home, Some(u.uid), Some(u.gid), true)?;
        ops::chmod(&ctx, &u.home, 0o750, true)?;
        let profile = format!("{}/.profile", u.home);
        ops::write_file(&ctx, &profile, b"# ~/.profile\n", 0o644)?;
        ops::chown(&ctx, &profile, Some(u.uid), Some(u.gid), true)?;
    }
    Ok(u)
}

fn del_user_unlocked(name: &str, remove_home: bool) -> KResult<()> {
    let u = by_name(name).ok_or(Errno::ENOENT)?;
    if u.uid == 0 {
        return Err(Errno::EPERM);
    }
    let p: Vec<String> = read_lines(PASSWD).into_iter().filter(|l| l.split(':').next() != Some(name)).collect();
    write_lines(PASSWD, &p, 0o644)?;
    let s: Vec<String> = read_lines(SHADOW).into_iter().filter(|l| l.split(':').next() != Some(name)).collect();
    write_lines(SHADOW, &s, 0o600)?;
    remove_from_groups_unlocked(name)?;
    // The user's private group goes too when nobody else uses it.
    if let Some(g) = group_by_name(name) {
        if g.gid == u.gid && g.members.is_empty() {
            let _ = del_group_unlocked(name);
        }
    }
    if remove_home {
        crate::fs::ops::remove_tree(&root_ctx(), &u.home)?;
    }
    Ok(())
}

// ── serialized entry points ────────────────────────────────────────────────
//
// Every change to passwd/group/shadow is a read-modify-write of whole files;
// one lock orders them so concurrent `useradd`s cannot lose each other's
// lines. (Readers need no lock: files are replaced atomically by rename.)

static DB_LOCK: crate::sync::Mutex<()> = crate::sync::Mutex::new(());

pub fn set_password(name: &str, password: &str) -> KResult<()> {
    let _g = DB_LOCK.lock();
    set_password_unlocked(name, password)
}

pub fn lock_password(name: &str, lock: bool) -> KResult<()> {
    let _g = DB_LOCK.lock();
    lock_password_unlocked(name, lock)
}

pub fn add_group(name: &str, gid: Option<u32>) -> KResult<u32> {
    let _g = DB_LOCK.lock();
    add_group_unlocked(name, gid)
}

pub fn del_group(name: &str) -> KResult<()> {
    let _g = DB_LOCK.lock();
    del_group_unlocked(name)
}

pub fn add_to_group(user: &str, group: &str) -> KResult<()> {
    let _g = DB_LOCK.lock();
    add_to_group_unlocked(user, group)
}

pub fn remove_from_group(user: &str, group: &str) -> KResult<()> {
    let _g = DB_LOCK.lock();
    let mut lines = read_lines(GROUP);
    let l = lines.iter_mut().find(|l| l.split(':').next() == Some(group)).ok_or(Errno::ENOENT)?;
    let mut g = parse_group(l).ok_or(Errno::EINVAL)?;
    if !g.members.iter().any(|m| m == user) {
        return Err(Errno::ESRCH);
    }
    g.members.retain(|m| m != user);
    *l = format!("{}:x:{}:{}", g.name, g.gid, g.members.join(","));
    write_lines(GROUP, &lines, 0o644)
}

pub fn remove_from_groups(user: &str) -> KResult<()> {
    let _g = DB_LOCK.lock();
    remove_from_groups_unlocked(user)
}

pub fn add_user(n: &NewUser) -> KResult<User> {
    let _g = DB_LOCK.lock();
    add_user_unlocked(n)
}

pub fn del_user(name: &str, remove_home: bool) -> KResult<()> {
    let _g = DB_LOCK.lock();
    del_user_unlocked(name, remove_home)
}

/// Rewrite `name`'s passwd entry through `f` (usermod, chsh, chfn).
pub fn modify_user(name: &str, f: impl FnOnce(&mut User) -> KResult<()>) -> KResult<User> {
    let _g = DB_LOCK.lock();
    let mut lines = read_lines(PASSWD);
    let idx = lines.iter().position(|l| l.split(':').next() == Some(name)).ok_or(Errno::ENOENT)?;
    let mut u = parse_user(&lines[idx]).ok_or(Errno::EINVAL)?;
    f(&mut u)?;
    if u.name != name && lines.iter().any(|l| l.split(':').next() == Some(u.name.as_str())) {
        return Err(Errno::EEXIST);
    }
    if [&u.gecos, &u.home, &u.shell].iter().any(|v| v.contains(':') || v.contains('\n')) {
        return Err(Errno::EINVAL);
    }
    lines[idx] = format!("{}:x:{}:{}:{}:{}:{}", u.name, u.uid, u.gid, u.gecos, u.home, u.shell);
    write_lines(PASSWD, &lines, 0o644)?;
    Ok(u)
}

/// Replace `user`'s supplementary groups with exactly `groups`.
pub fn set_groups(user: &str, groups: &[String]) -> KResult<()> {
    let _g = DB_LOCK.lock();
    for g in groups {
        if group_by_name(g).is_none() {
            return Err(Errno::ENOENT);
        }
    }
    remove_from_groups_unlocked(user)?;
    for g in groups {
        add_to_group_unlocked(user, g)?;
    }
    Ok(())
}

/// Create the databases on a fresh system: root (password `root`, as the
/// deployment expects — `passwd` changes it) plus the standard groups.
pub fn seed_databases(ctx: &Ctx) {
    if !ops::exists(ctx, PASSWD) {
        let _ = ops::write_file(ctx, PASSWD, b"root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/bin/false\n", 0o644);
    }
    if !ops::exists(ctx, GROUP) {
        let _ = ops::write_file(
            ctx,
            GROUP,
            b"root:x:0:\nwheel:x:10:root\ntty:x:5:\ndisk:x:6:\nsudo:x:27:\nusers:x:100:\nnogroup:x:65534:\n",
            0o644,
        );
    }
    if !ops::exists(ctx, SHADOW) {
        let line = format!("root:{}:{}:0:99999:7:::\nnobody:!:{}:0:99999:7:::\n", hash_password("root"), days_since_epoch(), days_since_epoch());
        let _ = ops::write_file(ctx, SHADOW, line.as_bytes(), 0o600);
        let _ = ops::chmod(ctx, SHADOW, 0o600, true);
        crate::knotice!("users", "created /etc/shadow; root password is the default — change it with `passwd`");
    }
}
