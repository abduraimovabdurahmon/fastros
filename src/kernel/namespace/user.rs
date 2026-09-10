//! User Namespace
//!
//! Maps UIDs/GIDs inside a container to different IDs on the host.
//! Allows containers to run as "root" inside without being root on the host.
//!
//! Example mapping: container UID 0 → host UID 1000

use super::{Namespace, NsId};

pub struct UserNamespace {
    id: NsId,
    /// uid_map: (container_start, host_start, count)
    uid_map: [(u32, u32, u32); 4],
    gid_map: [(u32, u32, u32); 4],
}

impl UserNamespace {
    pub const fn root() -> Self {
        // Root namespace: identity mapping (uid 0..u32::MAX → 0..u32::MAX)
        Self {
            id: 0,
            uid_map: [(0, 0, u32::MAX), (0, 0, 0), (0, 0, 0), (0, 0, 0)],
            gid_map: [(0, 0, u32::MAX), (0, 0, 0), (0, 0, 0), (0, 0, 0)],
        }
    }

    pub fn new(id: NsId) -> Self {
        Self {
            id,
            uid_map: [(0, 0, 0); 4],
            gid_map: [(0, 0, 0); 4],
        }
    }

    /// Map a container UID to host UID.
    pub fn to_host_uid(&self, container_uid: u32) -> Option<u32> {
        for &(c_start, h_start, count) in &self.uid_map {
            if count == 0 { continue; }
            if container_uid >= c_start && container_uid < c_start + count {
                return Some(h_start + (container_uid - c_start));
            }
        }
        None
    }
}

impl Namespace for UserNamespace {
    fn id(&self) -> NsId { self.id }
}
