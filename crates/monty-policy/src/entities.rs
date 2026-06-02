//! Entity and context construction for Cedar authorization requests.
//!
//! Builds Cedar `Entity` values for the principal (Script) and resources
//! (Path, EnvVar, ExternalFunction) from Monty runtime data.

use std::collections::{HashMap, HashSet};

use cedar_policy::{Entity, EntityId, EntityTypeName, EntityUid, RestrictedExpression};

/// Creates an `EntityUid` for a `Monty::Script` principal.
pub fn script_uid(name: &str) -> EntityUid {
    EntityUid::from_type_name_and_id(entity_type("Script"), EntityId::new(name))
}

/// Creates an `Entity` for a filesystem path resource.
pub fn path_entity(path: &str) -> Entity {
    let uid = EntityUid::from_type_name_and_id(entity_type("Path"), EntityId::new(path));
    let attrs = HashMap::from([("path".to_owned(), RestrictedExpression::new_string(path.to_owned()))]);
    Entity::new(uid, attrs, HashSet::new()).expect("path entity construction is infallible with known schema")
}

/// Creates an `Entity` for an environment variable resource.
pub fn env_var_entity(name: &str) -> Entity {
    let uid = EntityUid::from_type_name_and_id(entity_type("EnvVar"), EntityId::new(name));
    let attrs = HashMap::from([("name".to_owned(), RestrictedExpression::new_string(name.to_owned()))]);
    Entity::new(uid, attrs, HashSet::new()).expect("env var entity construction is infallible with known schema")
}

/// Creates an `Entity` for an external function resource.
pub fn external_function_entity(name: &str) -> Entity {
    let uid = EntityUid::from_type_name_and_id(entity_type("ExternalFunction"), EntityId::new(name));
    let attrs = HashMap::from([("name".to_owned(), RestrictedExpression::new_string(name.to_owned()))]);
    Entity::new(uid, attrs, HashSet::new())
        .expect("external function entity construction is infallible with known schema")
}

/// Creates a `Monty::Script` entity (the principal) with no attributes.
pub fn script_entity(name: &str) -> Entity {
    Entity::new_no_attrs(script_uid(name), HashSet::new())
}

/// Helper to build a `Monty::<TypeName>` entity type name.
fn entity_type(type_name: &str) -> EntityTypeName {
    format!("Monty::{type_name}")
        .parse()
        .expect("known entity type names are valid")
}
