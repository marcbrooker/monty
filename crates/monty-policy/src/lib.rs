//! Cedar policy engine for the Monty Python sandbox.
//!
//! Provides [`PolicyEngine`] which evaluates Cedar policies against Monty sandbox
//! operations (filesystem access, environment variables, external function calls).
//! Cedar adds fine-grained, declarative access control on top of the existing
//! `MountTable` path security — both must allow an operation for it to proceed.
//!
//! # Example
//!
//! ```
//! use monty_policy::{PolicyConfig, PolicyEngine};
//!
//! let policy_text = r#"
//!     permit(
//!         principal,
//!         action == Monty::Action::"fs:read",
//!         resource
//!     ) when {
//!         resource.path like "/data/*"
//!     };
//! "#;
//!
//! let engine = PolicyEngine::new(policy_text, PolicyConfig::default()).unwrap();
//! ```

mod entities;
mod error;
mod request;
mod schema;

use std::{
    collections::HashMap,
    fmt,
    str::FromStr,
    sync::{Mutex, PoisonError},
};

use cedar_policy::{Authorizer, Decision, Entities, PolicySet, Schema};
use monty::OsFunctionCall;

pub use crate::error::{PolicyDenied, PolicyParseError};
use crate::{
    entities::{script_entity, script_uid},
    request::{build_entities, build_external_call_request, build_os_call_request, os_call_to_authz_request},
    schema::SCHEMA_SRC,
};

/// Configuration for constructing a [`PolicyEngine`].
#[derive(Debug, Clone)]
pub struct PolicyConfig {
    /// Name of the principal entity (the sandboxed script). Defaults to `"anonymous"`.
    pub principal: String,
    /// Default decision when no policy explicitly permits or forbids an action.
    /// Defaults to `Deny` (secure by default).
    pub default_decision: DefaultDecision,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            principal: "anonymous".to_owned(),
            default_decision: DefaultDecision::Deny,
        }
    }
}

/// The default authorization decision when no Cedar policy matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultDecision {
    /// Deny access unless explicitly permitted. This is the secure default.
    Deny,
    /// Allow access unless explicitly forbidden. Use when Cedar policies are
    /// intended only as a blocklist on top of existing mount-level controls.
    Allow,
}

/// Cedar policy engine that authorizes Monty sandbox operations.
///
/// Constructed once with a Cedar policy set, then consulted on each OS call or
/// external function call. The policy set is immutable after construction, so
/// authorization decisions are deterministic and cacheable.
///
/// # Security model
///
/// The engine sits between the VM's `FrameExit` and the `MountTable` dispatcher.
/// A denial here short-circuits before the mount table is consulted, preventing
/// information leakage about mount structure. A Cedar `permit` cannot override
/// `MountTable` denials — both layers must allow the operation.
pub struct PolicyEngine {
    authorizer: Authorizer,
    policy_set: PolicySet,
    #[expect(dead_code)]
    schema: Schema,
    principal_name: String,
    default_decision: DefaultDecision,
    /// Cache of authorization decisions keyed by (action, resource_id).
    ///
    /// The policy set is immutable after construction, so decisions are
    /// deterministic and safe to cache. Uses `Mutex` for thread-safe interior
    /// mutability since the engine may be shared across thread boundaries.
    cache: Mutex<HashMap<(&'static str, String), bool>>,
}

impl PolicyEngine {
    /// Creates a new policy engine by parsing Cedar policy text against the Monty schema.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyParseError`] if the policy text is syntactically invalid or
    /// references entity types/actions not defined in the Monty schema.
    pub fn new(policy_text: &str, config: PolicyConfig) -> Result<Self, PolicyParseError> {
        let schema = Schema::from_cedarschema_str(SCHEMA_SRC)
            .map_err(|e| PolicyParseError {
                message: format!("schema error: {e}"),
            })?
            .0;

        let policy_set = PolicySet::from_str(policy_text).map_err(|e| PolicyParseError {
            message: format!("policy parse error: {e}"),
        })?;

        Ok(Self {
            authorizer: Authorizer::new(),
            policy_set,
            schema,
            principal_name: config.principal,
            default_decision: config.default_decision,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Checks whether a Cedar policy permits the given OS call.
    ///
    /// Returns `Ok(())` if the operation is allowed, or `Err(PolicyDenied)` if
    /// the policy forbids it. Operations not covered by Cedar (e.g. `DateToday`)
    /// are always allowed since they have no security implications.
    pub fn authorize_os_call(&self, call: &OsFunctionCall) -> Result<(), PolicyDenied> {
        let Some(authz) = os_call_to_authz_request(call) else {
            // Not policy-gated (informational call).
            return Ok(());
        };

        let principal_uid = script_uid(&self.principal_name);
        let principal_entity = script_entity(&self.principal_name);
        let entities = build_entities(&principal_entity, &authz.resource);
        let request = build_os_call_request(&principal_uid, &authz);

        self.evaluate(&request, &entities, authz.action, authz.resource.uid().id().as_ref())
    }

    /// Checks whether a Cedar policy permits calling the named external function.
    ///
    /// Returns `Ok(())` if the call is allowed, or `Err(PolicyDenied)` if denied.
    pub fn authorize_external_call(&self, function_name: &str) -> Result<(), PolicyDenied> {
        let principal_uid = script_uid(&self.principal_name);
        let principal_entity = script_entity(&self.principal_name);
        let (request, resource) = build_external_call_request(&principal_uid, function_name);
        let entities = build_entities(&principal_entity, &resource);

        self.evaluate(&request, &entities, "ext:call", function_name)
    }

    /// Core evaluation: checks the cache first, then runs the Cedar authorizer.
    ///
    /// For `DefaultDecision::Deny`: uses Cedar's native semantics directly.
    /// For `DefaultDecision::Allow`: allows unless an explicit `forbid` policy matched
    /// (Cedar returns Deny with empty reasons when no policies matched at all;
    /// in allow-by-default mode, that should be treated as allowed).
    fn evaluate(
        &self,
        request: &cedar_policy::Request,
        entities: &Entities,
        action: &'static str,
        resource_id: &str,
    ) -> Result<(), PolicyDenied> {
        // Check cache first — policy set is immutable, so decisions are stable.
        let cache_key = (action, resource_id.to_owned());
        if let Some(&denied) = self
            .cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&cache_key)
        {
            return if denied {
                Err(PolicyDenied {
                    action,
                    resource: cache_key.1,
                })
            } else {
                Ok(())
            };
        }

        let response = self.authorizer.is_authorized(request, &self.policy_set, entities);

        let denied = match self.default_decision {
            DefaultDecision::Deny => response.decision() == Decision::Deny,
            DefaultDecision::Allow => {
                response.decision() == Decision::Deny && response.diagnostics().reason().next().is_some()
            }
        };

        // Populate cache.
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(cache_key, denied);

        if denied {
            Err(PolicyDenied {
                action,
                resource: resource_id.to_owned(),
            })
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for PolicyEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyEngine")
            .field("principal_name", &self.principal_name)
            .field("default_decision", &self.default_decision)
            .finish_non_exhaustive()
    }
}
