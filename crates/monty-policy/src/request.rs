//! Translation from Monty runtime operations to Cedar authorization requests.
//!
//! Maps each [`OsFunctionCall`] variant to a Cedar action name and resource entity,
//! and provides a helper for external function call authorization.

use cedar_policy::{Context, Entities, Entity, EntityUid, Request};
use monty::{FileMode, OsFunctionCall};

use crate::entities::{env_var_entity, external_function_entity, path_entity};

/// The Cedar action and resource derived from a Monty operation.
///
/// Used internally to build a [`Request`] for the Cedar authorizer.
pub struct AuthzRequest {
    /// Cedar action name (e.g. "fs:read").
    pub action: &'static str,
    /// Resource entity for the request.
    pub resource: Entity,
}

/// Translates an [`OsFunctionCall`] into the Cedar action name and resource entity.
///
/// Returns `None` for operations that are not policy-gated (e.g. `DateToday`,
/// `DateTimeNow`) — these are considered safe informational calls.
pub fn os_call_to_authz_request(call: &OsFunctionCall) -> Option<AuthzRequest> {
    match call {
        // --- fs:read ---
        OsFunctionCall::ReadText(p)
        | OsFunctionCall::ReadBytes(p)
        | OsFunctionCall::Stat(p)
        | OsFunctionCall::Resolve(p)
        | OsFunctionCall::Absolute(p) => Some(AuthzRequest {
            action: "fs:read",
            resource: path_entity(p.as_str()),
        }),

        // --- fs:exists ---
        OsFunctionCall::Exists(p)
        | OsFunctionCall::IsFile(p)
        | OsFunctionCall::IsDir(p)
        | OsFunctionCall::IsSymlink(p) => Some(AuthzRequest {
            action: "fs:exists",
            resource: path_entity(p.as_str()),
        }),

        // --- fs:write ---
        OsFunctionCall::WriteText(a) | OsFunctionCall::AppendText(a) => Some(AuthzRequest {
            action: "fs:write",
            resource: path_entity(a.path.as_str()),
        }),
        OsFunctionCall::WriteBytes(a) | OsFunctionCall::AppendBytes(a) => Some(AuthzRequest {
            action: "fs:write",
            resource: path_entity(a.path.as_str()),
        }),

        // --- fs:create ---
        OsFunctionCall::Mkdir(a) => Some(AuthzRequest {
            action: "fs:create",
            resource: path_entity(a.path.as_str()),
        }),

        // --- fs:delete ---
        OsFunctionCall::Unlink(p) | OsFunctionCall::Rmdir(p) => Some(AuthzRequest {
            action: "fs:delete",
            resource: path_entity(p.as_str()),
        }),

        // --- fs:list ---
        OsFunctionCall::Iterdir(p) => Some(AuthzRequest {
            action: "fs:list",
            resource: path_entity(p.as_str()),
        }),

        // --- fs:rename ---
        OsFunctionCall::Rename(a) => Some(AuthzRequest {
            action: "fs:rename",
            resource: path_entity(a.src.as_str()),
        }),

        // --- Open: action depends on file mode ---
        OsFunctionCall::Open(a) => {
            let action = if open_mode_is_write(a.mode) {
                "fs:write"
            } else {
                "fs:read"
            };
            Some(AuthzRequest {
                action,
                resource: path_entity(a.path.as_str()),
            })
        }

        // --- env:read ---
        OsFunctionCall::Getenv(a) => Some(AuthzRequest {
            action: "env:read",
            resource: env_var_entity(&a.key),
        }),
        // GetEnviron reads the entire environment dict. We use "__all__" as
        // a synthetic resource name (not a valid env var name on any OS) so
        // policies can distinguish "read all env vars" from "read a specific var".
        OsFunctionCall::GetEnviron => Some(AuthzRequest {
            action: "env:read",
            resource: env_var_entity("__all__"),
        }),

        // --- Not policy-gated (informational, no security implications) ---
        OsFunctionCall::DateToday | OsFunctionCall::DateTimeNow(_) => None,

        // Placeholder variant — never dispatched.
        OsFunctionCall::Used => None,
    }
}

/// Builds a Cedar [`Request`] for an OS call authorization check.
pub fn build_os_call_request(principal: &EntityUid, authz: &AuthzRequest) -> Request {
    let action: EntityUid = format!("Monty::Action::\"{}\"", authz.action)
        .parse()
        .expect("known action names are valid EntityUids");

    Request::new(
        principal.clone(),
        action,
        authz.resource.uid(),
        Context::empty(),
        None, // schema validation done at policy parse time
    )
    .expect("request construction with known types is infallible")
}

/// Builds a Cedar [`Request`] for an external function call authorization check.
pub fn build_external_call_request(principal: &EntityUid, function_name: &str) -> (Request, Entity) {
    let resource = external_function_entity(function_name);

    let action: EntityUid = "Monty::Action::\"ext:call\""
        .parse()
        .expect("known action name is valid");

    let request = Request::new(principal.clone(), action, resource.uid(), Context::empty(), None)
        .expect("request construction with known types is infallible");

    (request, resource)
}

/// Builds a Cedar [`Entities`] set containing the principal and resource entities.
pub fn build_entities(principal_entity: &Entity, resource: &Entity) -> Entities {
    Entities::from_entities([principal_entity.clone(), resource.clone()], None)
        .expect("entity set construction with disjoint UIDs is infallible")
}

/// Returns `true` if the file open mode implies a write operation.
///
/// `ReadUpdate` (`r+`) is included because it allows writing to the file
/// even though it also reads.
fn open_mode_is_write(mode: FileMode) -> bool {
    matches!(
        mode,
        FileMode::ReadUpdate(_)
            | FileMode::Write(_)
            | FileMode::WriteUpdate(_)
            | FileMode::Append(_)
            | FileMode::AppendUpdate(_)
    )
}
