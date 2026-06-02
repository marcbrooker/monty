//! Integration tests for the Cedar policy engine.

use monty::{FileMode, GetenvArgs, MkdirCallArgs, MontyObject, MontyPath, OpenCallArgs, OsFunctionCall};
use monty_policy::{DefaultDecision, PolicyConfig, PolicyDenied, PolicyEngine};

/// Helper to create a policy engine with deny-by-default and the given policy text.
fn engine(policy_text: &str) -> PolicyEngine {
    PolicyEngine::new(policy_text, PolicyConfig::default()).unwrap()
}

/// Helper to create a policy engine with allow-by-default (blocklist mode).
fn engine_allow_default(policy_text: &str) -> PolicyEngine {
    PolicyEngine::new(
        policy_text,
        PolicyConfig {
            default_decision: DefaultDecision::Allow,
            ..Default::default()
        },
    )
    .unwrap()
}

// =============================================================================
// Schema and construction tests
// =============================================================================

#[test]
fn empty_policy_parses() {
    let engine = PolicyEngine::new("", PolicyConfig::default()).unwrap();
    // With deny-by-default and no policies, everything should be denied.
    let call = OsFunctionCall::ReadText(MontyPath::new("/foo.txt".to_owned()));
    assert!(engine.authorize_os_call(&call).is_err());
}

#[test]
fn invalid_policy_returns_parse_error() {
    let result = PolicyEngine::new("this is not valid cedar", PolicyConfig::default());
    assert!(result.is_err());
}

#[test]
fn custom_principal_name() {
    let config = PolicyConfig {
        principal: "my-script".to_owned(),
        ..Default::default()
    };
    // Should parse without error.
    let _engine = PolicyEngine::new(
        r#"permit(principal == Monty::Script::"my-script", action, resource);"#,
        config,
    )
    .unwrap();
}

// =============================================================================
// Filesystem read policy tests
// =============================================================================

#[test]
fn permit_fs_read_all_paths() {
    let e = engine(r#"permit(principal, action == Monty::Action::"fs:read", resource);"#);

    let read = OsFunctionCall::ReadText(MontyPath::new("/data/file.txt".to_owned()));
    assert!(e.authorize_os_call(&read).is_ok());

    let read_bytes = OsFunctionCall::ReadBytes(MontyPath::new("/other.bin".to_owned()));
    assert!(e.authorize_os_call(&read_bytes).is_ok());
}

#[test]
fn permit_fs_read_specific_path_pattern() {
    let e = engine(
        r#"permit(principal, action == Monty::Action::"fs:read", resource) when { resource.path like "/data/*" };"#,
    );

    let allowed = OsFunctionCall::ReadText(MontyPath::new("/data/file.txt".to_owned()));
    assert!(e.authorize_os_call(&allowed).is_ok());

    let denied = OsFunctionCall::ReadText(MontyPath::new("/secret/file.txt".to_owned()));
    assert!(e.authorize_os_call(&denied).is_err());
}

#[test]
fn deny_fs_read_denies_stat_and_resolve() {
    // No permit policies = deny all (deny-by-default)
    let e = engine("");

    let stat = OsFunctionCall::Stat(MontyPath::new("/foo".to_owned()));
    assert!(e.authorize_os_call(&stat).is_err());

    let resolve = OsFunctionCall::Resolve(MontyPath::new("/foo".to_owned()));
    assert!(e.authorize_os_call(&resolve).is_err());

    let absolute = OsFunctionCall::Absolute(MontyPath::new("/foo".to_owned()));
    assert!(e.authorize_os_call(&absolute).is_err());
}

// =============================================================================
// Filesystem write policy tests
// =============================================================================

#[test]
fn permit_fs_write_specific_path() {
    let e = engine(
        r#"permit(principal, action == Monty::Action::"fs:write", resource) when { resource.path like "/output/*" };"#,
    );

    let allowed = OsFunctionCall::WriteText(monty::PathStringDataArgs {
        path: MontyPath::new("/output/result.txt".to_owned()),
        data: "hello".to_owned(),
    });
    assert!(e.authorize_os_call(&allowed).is_ok());

    let denied = OsFunctionCall::WriteText(monty::PathStringDataArgs {
        path: MontyPath::new("/input/data.txt".to_owned()),
        data: "hack".to_owned(),
    });
    assert!(e.authorize_os_call(&denied).is_err());
}

#[test]
fn open_write_mode_uses_fs_write_action() {
    let e = engine(r#"permit(principal, action == Monty::Action::"fs:write", resource);"#);

    let open_write = OsFunctionCall::Open(OpenCallArgs {
        path: MontyPath::new("/file.txt".to_owned()),
        mode: FileMode::Write(false),
    });
    assert!(e.authorize_os_call(&open_write).is_ok());

    // Read mode should NOT match fs:write permit
    let open_read = OsFunctionCall::Open(OpenCallArgs {
        path: MontyPath::new("/file.txt".to_owned()),
        mode: FileMode::Read(false),
    });
    assert!(e.authorize_os_call(&open_read).is_err());
}

#[test]
fn open_read_mode_uses_fs_read_action() {
    let e = engine(r#"permit(principal, action == Monty::Action::"fs:read", resource);"#);

    let open_read = OsFunctionCall::Open(OpenCallArgs {
        path: MontyPath::new("/file.txt".to_owned()),
        mode: FileMode::Read(false),
    });
    assert!(e.authorize_os_call(&open_read).is_ok());
}

// =============================================================================
// Filesystem exists/list/create/delete/rename tests
// =============================================================================

#[test]
fn permit_fs_exists() {
    let e = engine(r#"permit(principal, action == Monty::Action::"fs:exists", resource);"#);

    let exists = OsFunctionCall::Exists(MontyPath::new("/foo".to_owned()));
    assert!(e.authorize_os_call(&exists).is_ok());

    let is_file = OsFunctionCall::IsFile(MontyPath::new("/foo".to_owned()));
    assert!(e.authorize_os_call(&is_file).is_ok());

    let is_dir = OsFunctionCall::IsDir(MontyPath::new("/foo".to_owned()));
    assert!(e.authorize_os_call(&is_dir).is_ok());

    let is_symlink = OsFunctionCall::IsSymlink(MontyPath::new("/foo".to_owned()));
    assert!(e.authorize_os_call(&is_symlink).is_ok());
}

#[test]
fn permit_fs_list() {
    let e = engine(r#"permit(principal, action == Monty::Action::"fs:list", resource);"#);

    let iterdir = OsFunctionCall::Iterdir(MontyPath::new("/data".to_owned()));
    assert!(e.authorize_os_call(&iterdir).is_ok());
}

#[test]
fn permit_fs_create() {
    let e = engine(r#"permit(principal, action == Monty::Action::"fs:create", resource);"#);

    let mkdir = OsFunctionCall::Mkdir(MkdirCallArgs {
        path: MontyPath::new("/new_dir".to_owned()),
        parents: false,
        exist_ok: false,
    });
    assert!(e.authorize_os_call(&mkdir).is_ok());
}

#[test]
fn permit_fs_delete() {
    let e = engine(r#"permit(principal, action == Monty::Action::"fs:delete", resource);"#);

    let unlink = OsFunctionCall::Unlink(MontyPath::new("/file.txt".to_owned()));
    assert!(e.authorize_os_call(&unlink).is_ok());

    let rmdir = OsFunctionCall::Rmdir(MontyPath::new("/dir".to_owned()));
    assert!(e.authorize_os_call(&rmdir).is_ok());
}

#[test]
fn permit_fs_rename() {
    let e = engine(r#"permit(principal, action == Monty::Action::"fs:rename", resource);"#);

    let rename = OsFunctionCall::Rename(monty::RenameCallArgs {
        src: MontyPath::new("/old.txt".to_owned()),
        dst: MontyPath::new("/new.txt".to_owned()),
    });
    assert!(e.authorize_os_call(&rename).is_ok());
}

// =============================================================================
// Environment variable policy tests
// =============================================================================

#[test]
fn permit_env_read_specific_var() {
    let e =
        engine(r#"permit(principal, action == Monty::Action::"env:read", resource) when { resource.name == "HOME" };"#);

    let allowed = OsFunctionCall::Getenv(GetenvArgs {
        key: "HOME".to_owned(),
        default: MontyObject::None,
    });
    assert!(e.authorize_os_call(&allowed).is_ok());

    let denied = OsFunctionCall::Getenv(GetenvArgs {
        key: "SECRET_KEY".to_owned(),
        default: MontyObject::None,
    });
    assert!(e.authorize_os_call(&denied).is_err());
}

#[test]
fn permit_env_read_all() {
    let e = engine(r#"permit(principal, action == Monty::Action::"env:read", resource);"#);

    let get_environ = OsFunctionCall::GetEnviron;
    assert!(e.authorize_os_call(&get_environ).is_ok());
}

// =============================================================================
// External function call policy tests
// =============================================================================

#[test]
fn permit_ext_call_specific_function() {
    let e = engine(
        r#"permit(principal, action == Monty::Action::"ext:call", resource) when { resource.name == "fetch" };"#,
    );

    assert!(e.authorize_external_call("fetch").is_ok());
    assert!(e.authorize_external_call("exec_dangerous").is_err());
}

#[test]
fn permit_ext_call_all() {
    let e = engine(r#"permit(principal, action == Monty::Action::"ext:call", resource);"#);

    assert!(e.authorize_external_call("anything").is_ok());
}

// =============================================================================
// Default decision behavior tests
// =============================================================================

#[test]
fn deny_default_blocks_everything_without_explicit_permit() {
    let e = engine("");

    let read = OsFunctionCall::ReadText(MontyPath::new("/foo".to_owned()));
    assert!(e.authorize_os_call(&read).is_err());
    assert!(e.authorize_external_call("func").is_err());
}

#[test]
fn allow_default_permits_everything_without_explicit_forbid() {
    let e = engine_allow_default("");

    let read = OsFunctionCall::ReadText(MontyPath::new("/foo".to_owned()));
    assert!(e.authorize_os_call(&read).is_ok());
    assert!(e.authorize_external_call("func").is_ok());
}

#[test]
fn allow_default_with_forbid_blocks_specific() {
    let e = engine_allow_default(r#"forbid(principal, action == Monty::Action::"fs:write", resource);"#);

    // Reads still allowed (no forbid for read)
    let read = OsFunctionCall::ReadText(MontyPath::new("/foo".to_owned()));
    assert!(e.authorize_os_call(&read).is_ok());

    // Writes blocked by explicit forbid
    let write = OsFunctionCall::WriteText(monty::PathStringDataArgs {
        path: MontyPath::new("/foo".to_owned()),
        data: "x".to_owned(),
    });
    assert!(e.authorize_os_call(&write).is_err());
}

// =============================================================================
// Non-gated operations (should always succeed)
// =============================================================================

#[test]
fn date_operations_not_policy_gated() {
    // Even with deny-all, date operations should pass since they're informational.
    let e = engine("");

    let today = OsFunctionCall::DateToday;
    assert!(e.authorize_os_call(&today).is_ok());

    let now = OsFunctionCall::DateTimeNow(MontyObject::None);
    assert!(e.authorize_os_call(&now).is_ok());
}

// =============================================================================
// Error message tests
// =============================================================================

#[test]
fn policy_denied_error_contains_action_and_resource() {
    let e = engine("");
    let read = OsFunctionCall::ReadText(MontyPath::new("/secret/file.txt".to_owned()));
    let err = e.authorize_os_call(&read).unwrap_err();

    assert_eq!(err.action, "fs:read");
    assert_eq!(err.resource, "/secret/file.txt");
    assert!(err.to_string().contains("fs:read"));
    assert!(err.to_string().contains("/secret/file.txt"));
}

#[test]
fn policy_denied_converts_to_monty_exception() {
    let denied = PolicyDenied {
        action: "fs:write",
        resource: "/path".to_owned(),
    };
    let exc: monty::MontyException = denied.into();
    // Should be a PermissionError
    assert!(format!("{exc}").contains("policy denied"));
}

// =============================================================================
// Combined policy tests (multiple rules)
// =============================================================================

#[test]
fn combined_read_write_policy() {
    let e = engine(
        r#"
        permit(principal, action == Monty::Action::"fs:read", resource);
        permit(principal, action == Monty::Action::"fs:write", resource)
            when { resource.path like "/output/*" };
        permit(principal, action == Monty::Action::"fs:exists", resource);
    "#,
    );

    // Read anywhere: allowed
    let read = OsFunctionCall::ReadText(MontyPath::new("/anywhere/file.txt".to_owned()));
    assert!(e.authorize_os_call(&read).is_ok());

    // Write to /output: allowed
    let write_ok = OsFunctionCall::WriteText(monty::PathStringDataArgs {
        path: MontyPath::new("/output/result.txt".to_owned()),
        data: "ok".to_owned(),
    });
    assert!(e.authorize_os_call(&write_ok).is_ok());

    // Write elsewhere: denied
    let write_bad = OsFunctionCall::WriteText(monty::PathStringDataArgs {
        path: MontyPath::new("/input/file.txt".to_owned()),
        data: "bad".to_owned(),
    });
    assert!(e.authorize_os_call(&write_bad).is_err());

    // Exists check: allowed
    let exists = OsFunctionCall::Exists(MontyPath::new("/foo".to_owned()));
    assert!(e.authorize_os_call(&exists).is_ok());

    // Delete: denied (no permit for fs:delete)
    let delete = OsFunctionCall::Unlink(MontyPath::new("/file".to_owned()));
    assert!(e.authorize_os_call(&delete).is_err());
}
