//! JavaScript/TypeScript bindings for the Cedar policy engine.
//!
//! Exposes [`Policy`] which wraps [`monty_policy::PolicyEngine`] and can be
//! passed in `RunOptions` / `StartOptions` to enforce fine-grained access
//! control on sandbox operations.

use monty_policy::{DefaultDecision, PolicyConfig, PolicyEngine};
use napi::bindgen_prelude::*;
use napi_derive::napi;

/// Options for creating a new Policy.
#[napi(object)]
#[derive(Default)]
pub struct PolicyOptions {
    /// Name of the principal entity (default: `"anonymous"`).
    pub principal: Option<String>,
    /// Default decision: `"deny"` (default) or `"allow"`.
    pub default: Option<String>,
}

/// A Cedar policy controlling what sandboxed code can do.
///
/// Policies are written in the Cedar language and evaluated against each
/// sandbox operation (filesystem access, environment variables, external
/// function calls). By default, operations not explicitly permitted are denied.
#[napi]
pub struct Policy {
    pub(crate) engine: PolicyEngine,
}

#[napi]
impl Policy {
    /// Creates a new policy from Cedar policy text.
    ///
    /// @param policyText - Cedar policy rules
    /// @param options - Optional configuration (principal name, default decision)
    #[napi(constructor)]
    pub fn new(policy_text: String, options: Option<PolicyOptions>) -> Result<Self> {
        let options = options.unwrap_or_default();

        let default_decision = match options.default.as_deref() {
            None | Some("deny") => DefaultDecision::Deny,
            Some("allow") => DefaultDecision::Allow,
            Some(other) => {
                return Err(Error::from_reason(format!(
                    "invalid default decision '{other}': must be 'deny' or 'allow'"
                )));
            }
        };

        let config = PolicyConfig {
            principal: options.principal.unwrap_or_else(|| "anonymous".to_owned()),
            default_decision,
        };

        let engine = PolicyEngine::new(&policy_text, config).map_err(|e| Error::from_reason(e.message))?;

        Ok(Self { engine })
    }
}
