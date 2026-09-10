//! User account table — in-memory /etc/passwd + /etc/shadow
//!
//! Linux format reference:
//!   /etc/passwd: username:x:uid:gid:gecos:home:shell
//!   /etc/shadow: username:hash:lastchg:min:max:warn:inactive:expire
//!
//! We store the hash inline with the user record (no separate shadow table).

use super::auth::hash_password;

pub const MAX_USERS: usize = 16;
pub const NAME_CAP:  usize = 32;
pub const HOME_CAP:  usize = 64;
pub const SHELL_CAP: usize = 32;

#[derive(Clone, Copy)]
pub struct User {
    pub uid:          u32,
    pub gid:          u32,           // primary group ID
    pub name:         [u8; NAME_CAP],
    pub name_len:     usize,
    pub passwd_hash:  u64,           // FNV-1a of password (0 = no password / locked)
    pub home:         [u8; HOME_CAP],
    pub home_len:     usize,
    pub shell:        [u8; SHELL_CAP],
    pub shell_len:    usize,
    pub locked:       bool,          // account disabled (like /etc/shadow '!')
    pub used:         bool,
}

impl User {
    pub const fn empty() -> Self {
        Self {
            uid: 0, gid: 0,
            name: [0u8; NAME_CAP], name_len: 0,
            passwd_hash: 0,
            home: [0u8; HOME_CAP], home_len: 0,
            shell: [0u8; SHELL_CAP], shell_len: 0,
            locked: false, used: false,
        }
    }

    pub fn name_bytes(&self)  -> &[u8] { &self.name[..self.name_len]  }
    pub fn home_bytes(&self)  -> &[u8] { &self.home[..self.home_len]  }
    pub fn shell_bytes(&self) -> &[u8] { &self.shell[..self.shell_len] }
}

pub struct UserTable {
    pub entries: [User; MAX_USERS],
    pub count:   usize,
}

impl UserTable {
    pub const fn new() -> Self {
        Self {
            entries: [User::empty(); MAX_USERS],
            count: 0,
        }
    }

    pub fn find_by_name(&self, name: &[u8]) -> Option<&User> {
        for i in 0..self.count {
            let u = &self.entries[i];
            if u.used && u.name_bytes() == name { return Some(u); }
        }
        None
    }

    pub fn find_by_uid(&self, uid: u32) -> Option<&User> {
        for i in 0..self.count {
            let u = &self.entries[i];
            if u.used && u.uid == uid { return Some(u); }
        }
        None
    }

    pub fn find_by_name_mut(&mut self, name: &[u8]) -> Option<&mut User> {
        for i in 0..self.count {
            if self.entries[i].used {
                let nlen = self.entries[i].name_len;
                if &self.entries[i].name[..nlen] == name {
                    return Some(&mut self.entries[i]);
                }
            }
        }
        None
    }

    /// Add a new user. Returns false if table full or name already exists.
    pub fn add(
        &mut self,
        uid: u32, gid: u32,
        name: &[u8], password: &[u8],
        home: &[u8], shell: &[u8],
    ) -> bool {
        if self.count >= MAX_USERS { return false; }
        if self.find_by_name(name).is_some() { return false; }

        let i = self.count;
        let u = &mut self.entries[i];
        u.uid = uid;
        u.gid = gid;

        let nn = name.len().min(NAME_CAP);
        u.name[..nn].copy_from_slice(&name[..nn]);
        u.name_len = nn;

        u.passwd_hash = hash_password(password);
        u.locked = password.is_empty(); // empty password = locked (like '!' in shadow)

        let hn = home.len().min(HOME_CAP);
        u.home[..hn].copy_from_slice(&home[..hn]);
        u.home_len = hn;

        let sn = shell.len().min(SHELL_CAP);
        u.shell[..sn].copy_from_slice(&shell[..sn]);
        u.shell_len = sn;

        u.used = true;
        self.count += 1;
        true
    }

    /// Remove user by name. Returns true if found.
    pub fn remove(&mut self, name: &[u8]) -> bool {
        for i in 0..self.count {
            if self.entries[i].used && self.entries[i].name_bytes() == name {
                // Compact by shifting down
                for j in i..self.count - 1 {
                    self.entries[j] = self.entries[j + 1];
                }
                self.entries[self.count - 1] = User::empty();
                self.count -= 1;
                return true;
            }
        }
        false
    }

    /// Change password for a user.
    pub fn set_password(&mut self, name: &[u8], new_pass: &[u8]) -> bool {
        if let Some(u) = self.find_by_name_mut(name) {
            u.passwd_hash = hash_password(new_pass);
            u.locked = new_pass.is_empty();
            return true;
        }
        false
    }

    /// Allocate the next available UID ≥ 1000 (Linux convention).
    pub fn next_uid(&self) -> u32 {
        let mut max = 999u32;
        for i in 0..self.count {
            let u = &self.entries[i];
            if u.used && u.uid >= 1000 && u.uid > max {
                max = u.uid;
            }
        }
        max + 1
    }
}
