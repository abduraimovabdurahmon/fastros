//! Group table — in-memory /etc/group
//!
//! Linux format: groupname:x:gid:member1,member2,...

pub const MAX_GROUPS:      usize = 16;
pub const MAX_GRP_MEMBERS: usize = 16;
pub const NAME_CAP:        usize = 32;

#[derive(Clone, Copy)]
pub struct Group {
    pub gid:          u32,
    pub name:         [u8; NAME_CAP],
    pub name_len:     usize,
    pub members:      [u32; MAX_GRP_MEMBERS], // UIDs
    pub member_count: usize,
    pub used:         bool,
}

impl Group {
    pub const fn empty() -> Self {
        Self {
            gid: 0,
            name: [0u8; NAME_CAP], name_len: 0,
            members: [0u32; MAX_GRP_MEMBERS], member_count: 0,
            used: false,
        }
    }

    pub fn name_bytes(&self) -> &[u8] { &self.name[..self.name_len] }

    pub fn has_member(&self, uid: u32) -> bool {
        self.members[..self.member_count].contains(&uid)
    }
}

pub struct GroupTable {
    pub entries: [Group; MAX_GROUPS],
    pub count:   usize,
}

impl GroupTable {
    pub const fn new() -> Self {
        Self { entries: [Group::empty(); MAX_GROUPS], count: 0 }
    }

    pub fn find_by_name(&self, name: &[u8]) -> Option<&Group> {
        for i in 0..self.count {
            let g = &self.entries[i];
            if g.used && g.name_bytes() == name { return Some(g); }
        }
        None
    }

    pub fn find_by_gid(&self, gid: u32) -> Option<&Group> {
        for i in 0..self.count {
            let g = &self.entries[i];
            if g.used && g.gid == gid { return Some(g); }
        }
        None
    }

    pub fn add(&mut self, gid: u32, name: &[u8]) -> bool {
        if self.count >= MAX_GROUPS { return false; }
        if self.find_by_name(name).is_some() { return false; }
        let i = self.count;
        let g = &mut self.entries[i];
        g.gid = gid;
        let nn = name.len().min(NAME_CAP);
        g.name[..nn].copy_from_slice(&name[..nn]);
        g.name_len = nn;
        g.used = true;
        self.count += 1;
        true
    }

    pub fn add_member(&mut self, gid: u32, uid: u32) {
        for i in 0..self.count {
            if self.entries[i].used && self.entries[i].gid == gid {
                let mc = self.entries[i].member_count;
                if mc < MAX_GRP_MEMBERS && !self.entries[i].has_member(uid) {
                    self.entries[i].members[mc] = uid;
                    self.entries[i].member_count += 1;
                }
                return;
            }
        }
    }

    pub fn remove_member(&mut self, uid: u32) {
        for i in 0..self.count {
            if !self.entries[i].used { continue; }
            let mc = self.entries[i].member_count;
            let mut j = 0;
            while j < mc {
                if self.entries[i].members[j] == uid {
                    for k in j..mc - 1 {
                        self.entries[i].members[k] = self.entries[i].members[k + 1];
                    }
                    self.entries[i].member_count -= 1;
                    break;
                }
                j += 1;
            }
        }
    }

    /// Allocate the next available GID ≥ 1000.
    pub fn next_gid(&self) -> u32 {
        let mut max = 999u32;
        for i in 0..self.count {
            let g = &self.entries[i];
            if g.used && g.gid >= 1000 && g.gid > max { max = g.gid; }
        }
        max + 1
    }

    /// Collect all GIDs that uid belongs to (for `id` and `groups` commands).
    pub fn groups_for_uid(&self, uid: u32, out: &mut [u32; MAX_GROUPS]) -> usize {
        let mut n = 0;
        for i in 0..self.count {
            let g = &self.entries[i];
            if g.used && g.has_member(uid) && n < MAX_GROUPS {
                out[n] = g.gid;
                n += 1;
            }
        }
        n
    }
}
