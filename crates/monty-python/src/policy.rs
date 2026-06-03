//! Python bindings for the Cedar policy engine.
//!
//! Exposes [`PyPolicy`] which wraps [`monty_policy::PolicyEngine`] and can be
//! passed to `Monty.run()` / `Monty.start()` to enforce fine-grained access
//! control on sandbox operations.

use std::sync::Arc;

use monty_policy::{DefaultDecision, PolicyConfig, PolicyEngine};
use pyo3::{exceptions::PyValueError, prelude::*};

/// A Cedar policy that controls what sandboxed code is allowed to do.
///
/// Policies are written in the Cedar language and evaluated against each
/// sandbox operation (filesystem access, environment variables, external
/// function calls). Operations not explicitly permitted are denied by default.
///
/// # Example
///
/// ```python
/// from pydantic_monty import Policy
///
/// policy = Policy('''
///     permit(principal, action == Monty::Action::"fs:read", resource)
///     when { resource.path like "/data/*" };
/// ''')
/// ```
#[pyclass(name = "Policy", module = "pydantic_monty", frozen)]
pub struct PyPolicy {
    pub(crate) engine: Arc<PolicyEngine>,
}

#[pymethods]
impl PyPolicy {
    /// Creates a new policy from Cedar policy text.
    ///
    /// # Arguments
    /// * `policy_text` — Cedar policy rules
    /// * `principal` — name of the principal entity (default: `"anonymous"`)
    /// * `default` — default decision: `"deny"` (default) or `"allow"`
    ///
    /// # Raises
    /// `ValueError` if the policy text is invalid or `default` is not recognized.
    #[new]
    #[pyo3(signature = (policy_text, *, principal = "anonymous", default = "deny"))]
    fn new(policy_text: &str, principal: &str, default: &str) -> PyResult<Self> {
        let default_decision = match default {
            "deny" => DefaultDecision::Deny,
            "allow" => DefaultDecision::Allow,
            other => {
                return Err(PyValueError::new_err(format!(
                    "invalid default decision '{other}': must be 'deny' or 'allow'"
                )));
            }
        };

        let config = PolicyConfig {
            principal: principal.to_owned(),
            default_decision,
        };

        let engine = PolicyEngine::new(policy_text, config).map_err(|e| PyValueError::new_err(e.message))?;

        Ok(Self {
            engine: Arc::new(engine),
        })
    }
}
