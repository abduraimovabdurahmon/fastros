//! Unix permission model
//!
//! Based on Linux kernel fs/namei.c :: generic_permission() logic.
//! Reference: https://elixir.bootlin.com/linux/latest/source/fs/namei.c
//!
//! Mode bits (lower 9 of u16), same layout as Linux:
//!   bit 8 (0o400) — owner  read
//!   bit 7 (0o200) — owner  write
//!   bit 6 (0o100) — owner  execute
//!   bit 5 (0o040) — group  read
//!   bit 4 (0o020) — group  write
//!   bit 3 (0o010) — group  execute
//!   bit 2 (0o004) — others read
//!   bit 1 (0o002) — others write
//!   bit 0 (0o001) — others execute

/// Permission request bits — same as Linux MAY_READ / MAY_WRITE / MAY_EXEC.
pub const MAY_READ:  u8 = 0o4;
pub const MAY_WRITE: u8 = 0o2;
pub const MAY_EXEC:  u8 = 0o1;

/// Default modes matching Linux coreutils defaults.
pub const MODE_DIR:       u16 = 0o755; // drwxr-xr-x
pub const MODE_FILE:      u16 = 0o644; // -rw-r--r--
pub const MODE_HOME:      u16 = 0o700; // drwx------  (user home dirs)
pub const MODE_TMP:       u16 = 0o1777; // drwxrwxrwt (sticky bit)
pub const MODE_ROOT_FILE: u16 = 0o600; // -rw-------  (root-only files)
pub const MODE_SHADOW:    u16 = 0o640; // -rw-r-----  (/etc/shadow)
pub const MODE_SUID:      u16 = 0o4755; // -rwsr-xr-x  (setuid)

/// Check whether a process with (euid, egid) may perform `want` on a file
/// owned by (file_uid, file_gid) with permission bits `mode`.
///
/// Mirrors Linux generic_permission():
///   1. root (euid==0) always passes  ← CAP_DAC_OVERRIDE
///   2. If uid matches → use owner bits
///   3. If gid matches → use group bits
///   4. Otherwise      → use other bits
pub fn check(
    file_uid: u32,
    file_gid: u32,
    file_mode: u16,
    euid: u32,
    egid: u32,
    want: u8,
) -> bool {
    // root bypass (CAP_DAC_OVERRIDE in Linux)
    if euid == 0 { return true; }

    let bits: u8 = if euid == file_uid {
        ((file_mode >> 6) & 0o7) as u8
    } else if egid == file_gid {
        ((file_mode >> 3) & 0o7) as u8
    } else {
        (file_mode & 0o7) as u8
    };

    bits & want != 0
}

/// Format `mode` as the classic 9-char rwx string into `out`.
/// E.g. 0o755 → b"rwxr-xr-x"
pub fn fmt_rwx(mode: u16, out: &mut [u8; 9]) {
    const CHARS: [u8; 2] = [b'-', 0]; // placeholder
    let bits = [
        (mode >> 8) & 1, (mode >> 7) & 1, (mode >> 6) & 1,
        (mode >> 5) & 1, (mode >> 4) & 1, (mode >> 3) & 1,
        (mode >> 2) & 1, (mode >> 1) & 1,  mode        & 1,
    ];
    let labels = [b'r', b'w', b'x', b'r', b'w', b'x', b'r', b'w', b'x'];
    let _ = CHARS;
    for i in 0..9 {
        out[i] = if bits[i] != 0 { labels[i] } else { b'-' };
    }
}

/// Format a full ls-style mode string (10 chars) into `out`.
/// `is_dir` = true → starts with 'd', else '-'.
/// E.g. dir 0o755 → "drwxr-xr-x"
pub fn fmt_mode_str(is_dir: bool, mode: u16, out: &mut [u8; 10]) {
    out[0] = if is_dir { b'd' } else { b'-' };
    let mut rwx = [0u8; 9];
    fmt_rwx(mode, &mut rwx);
    out[1..].copy_from_slice(&rwx);
}
