//! Namespace subsystem — container isolation primitives
//!
//! Namespaces virtualize kernel resources so each container sees its own view.
//! This is the core building block of container isolation in FastROS.
//!
//! Namespace types:
//!   PID   — each container has its own PID 1
//!   Mount — each container has its own filesystem tree
//!   Net   — each container has its own network stack
//!   User  — each container has its own UID/GID space
//!
//! CAN IMPORT:   hal/, libs/
//! CANNOT IMPORT: arch/, drivers/, fs/, userspace/

pub mod mnt;
pub mod net;
pub mod pid;
pub mod user;

/// Unique identifier for a namespace instance.
pub type NsId = u64;

/// Common interface all namespace types implement.
pub trait Namespace {
    fn id(&self) -> NsId;
}

/// The set of namespaces a process (or container) belongs to.
pub struct NsSet {
    pub pid:  pid::PidNamespace,
    pub mnt:  mnt::MountNamespace,
    pub net:  net::NetNamespace,
    pub user: user::UserNamespace,
}

impl NsSet {
    /// Create the root namespace set (kernel init).
    pub const fn root() -> Self {
        Self {
            pid:  pid::PidNamespace::root(),
            mnt:  mnt::MountNamespace::root(),
            net:  net::NetNamespace::root(),
            user: user::UserNamespace::root(),
        }
    }
}
