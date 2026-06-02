//! Error types for policy evaluation failures.
//!
//! [`PolicyDenied`] is the primary error returned when Cedar denies an authorization
//! request. It converts to a `MontyException` with `ExcType::PermissionError` so that
//! sandboxed code sees a standard Python exception.

use std::{error::Error, fmt};

use monty::{ExcType, MontyException};

/// Error returned when a Cedar policy denies an authorization request.
///
/// Contains the action and resource identifier for diagnostics, but intentionally
/// does NOT include the policy text or policy ID to prevent policy probing.
#[derive(Debug, Clone)]
pub struct PolicyDenied {
    /// The Cedar action that was attempted (e.g. "fs:read").
    pub action: &'static str,
    /// The resource identifier (e.g. a path or function name).
    pub resource: String,
}

impl fmt::Display for PolicyDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "policy denied action '{}' on '{}'", self.action, self.resource)
    }
}

impl Error for PolicyDenied {}

impl From<PolicyDenied> for MontyException {
    fn from(denied: PolicyDenied) -> Self {
        Self::new(ExcType::PermissionError, Some(denied.to_string()))
    }
}

/// Error returned when a policy cannot be parsed or validated against the schema.
#[derive(Debug, Clone)]
pub struct PolicyParseError {
    /// Human-readable description of what went wrong.
    pub message: String,
}

impl fmt::Display for PolicyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid Cedar policy: {}", self.message)
    }
}

impl Error for PolicyParseError {}
