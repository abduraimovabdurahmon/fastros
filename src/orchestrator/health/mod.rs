//! Health Checks and Self-Healing
//!
//! FastROS monitors containers and automatically restarts failed ones.
//!
//! Check types:
//!   Liveness  — is the container still alive? If not, restart it.
//!   Readiness — is the container ready to serve traffic? If not, pull it from discovery.
//!
//! Restart policies:
//!   Always    — restart on any exit
//!   OnFailure — restart only on non-zero exit code
//!   Never     — do not restart

use crate::container::runtime::ContainerId;

#[derive(Debug, Clone, Copy)]
pub enum RestartPolicy {
    Always,
    OnFailure,
    Never,
}

#[derive(Debug, Clone, Copy)]
pub enum HealthStatus {
    Healthy,
    Unhealthy,
    Unknown,
}

pub struct HealthCheck {
    pub container_id:   ContainerId,
    pub liveness:       HealthStatus,
    pub readiness:      HealthStatus,
    pub restart_policy: RestartPolicy,
    pub restart_count:  u32,
}

impl HealthCheck {
    pub fn new(container_id: ContainerId, policy: RestartPolicy) -> Self {
        Self {
            container_id,
            liveness:       HealthStatus::Unknown,
            readiness:      HealthStatus::Unknown,
            restart_policy: policy,
            restart_count:  0,
        }
    }

    /// Called by the health checker timer to evaluate and heal.
    pub fn evaluate(&mut self) {
        // TODO: send probe to container (exec or TCP check)
        // TODO: if unhealthy, apply restart policy
    }
}
