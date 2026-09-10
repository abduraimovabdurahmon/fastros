//! Mount Namespace
//!
//! Each mount namespace has an independent filesystem tree.
//! Containers use this to have their own root filesystem (overlay mount).

use super::{Namespace, NsId};

pub struct MountNamespace {
    id: NsId,
    // TODO: root dentry pointer into fs::vfs
}

impl MountNamespace {
    pub const fn root() -> Self {
        Self { id: 0 }
    }

    pub fn new(id: NsId) -> Self {
        Self { id }
    }
}

impl Namespace for MountNamespace {
    fn id(&self) -> NsId { self.id }
}
