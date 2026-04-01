use std::fs;
use std::path::Path;

pub fn run() -> i32 {
    let authz_dir = Path::new(".authz");
    if authz_dir.exists() {
        eprintln!(r#"{{"error":".authz/ directory already exists"}}"#);
        return 1;
    }
    if let Err(e) = fs::create_dir_all(authz_dir) {
        eprintln!(r#"{{"error":"failed to create .authz/: {}"}}"#, e);
        return 3;
    }
    let defaults = [
        ("schema.cedarschema", duramen_policy_defaults::SCHEMA),
        (
            "allow-default.cedar",
            duramen_policy_defaults::ALLOW_DEFAULT,
        ),
        (
            "audit-file-writes.cedar",
            duramen_policy_defaults::AUDIT_FILE_WRITES,
        ),
        (
            "deny-destructive.cedar",
            duramen_policy_defaults::DENY_DESTRUCTIVE,
        ),
        (
            "require-approval-sensitive.cedar",
            duramen_policy_defaults::REQUIRE_APPROVAL_SENSITIVE,
        ),
    ];
    for (name, content) in &defaults {
        if let Err(e) = fs::write(authz_dir.join(name), content) {
            eprintln!(r#"{{"error":"failed to write {}: {}"}}"#, name, e);
            return 3;
        }
    }
    println!(
        r#"{{"status":"initialized","files_created":{}}}"#,
        defaults.len()
    );
    0
}
