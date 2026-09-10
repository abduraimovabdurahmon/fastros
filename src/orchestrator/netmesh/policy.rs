//! Network Policies
//!
//! Rules that control which containers can talk to which.
//! Enforced at the kernel level — packets are dropped before leaving the host.
//!
//! Example policy:
//!   Allow: namespace=frontend → namespace=backend, port=8080
//!   Deny:  all → namespace=db (except namespace=backend)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    Allow,
    Deny,
}

pub struct NetworkPolicy {
    pub src_ns_id: u64,     // source namespace (0 = any)
    pub dst_ns_id: u64,     // destination namespace
    pub dst_port:  u16,     // 0 = any
    pub action:    PolicyAction,
}

/// Check if a packet should be allowed.
/// Returns Allow or Deny.
pub fn evaluate(
    _src_ns: u64,
    _dst_ns: u64,
    _dst_port: u16,
    _policies: &[NetworkPolicy],
) -> PolicyAction {
    // TODO: iterate policies, first match wins
    // Default: allow all (permissive mode until policies are configured)
    PolicyAction::Allow
}
