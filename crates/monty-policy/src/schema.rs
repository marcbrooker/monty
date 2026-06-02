//! Embedded Cedar schema for the Monty sandbox policy model.
//!
//! The schema defines entity types (Script, Path, EnvVar, ExternalFunction, Network)
//! and actions (fs:read, fs:write, etc.) that Cedar policies can reference. It is
//! compiled in as a constant so users write policies against a known, fixed vocabulary
//! — this prevents confused-deputy attacks via custom entity types.

/// Cedar schema in the human-readable format.
///
/// Entity types:
/// - `Script`: the sandboxed code (always the principal)
/// - `Path`: a filesystem path (virtual, within the sandbox namespace)
/// - `EnvVar`: an environment variable name
/// - `ExternalFunction`: a host-registered external function
/// - `Network`: a network endpoint (host:port or DNS name, reserved for future use)
pub const SCHEMA_SRC: &str = r#"
namespace Monty {
    entity Script = {};

    entity Path = {
        "path": String,
    };

    entity EnvVar = {
        "name": String,
    };

    entity ExternalFunction = {
        "name": String,
    };

    entity Network = {
        "host": String,
        "port": __cedar::Long,
    };

    action "fs:read" appliesTo {
        principal: [Script],
        resource: [Path],
    };

    action "fs:write" appliesTo {
        principal: [Script],
        resource: [Path],
    };

    action "fs:exists" appliesTo {
        principal: [Script],
        resource: [Path],
    };

    action "fs:list" appliesTo {
        principal: [Script],
        resource: [Path],
    };

    action "fs:create" appliesTo {
        principal: [Script],
        resource: [Path],
    };

    action "fs:delete" appliesTo {
        principal: [Script],
        resource: [Path],
    };

    action "fs:rename" appliesTo {
        principal: [Script],
        resource: [Path],
    };

    action "env:read" appliesTo {
        principal: [Script],
        resource: [EnvVar],
    };

    action "ext:call" appliesTo {
        principal: [Script],
        resource: [ExternalFunction],
    };

    action "net:connect" appliesTo {
        principal: [Script],
        resource: [Network],
    };
}
"#;
