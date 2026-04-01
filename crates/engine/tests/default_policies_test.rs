/// Integration tests for the default Cedar policies shipped with Duramen.
///
/// Tests each policy individually and as a combined set to verify:
///   - allow-read-only.cedar: permits read/list/status/log/diff and git::read
///   - audit-file-writes.cedar: permits file edits with @advice("audit") on non-protected
///   - deny-destructive.cedar: forbids force-push, git::destructive, is_destructive resources, protected deletes
///   - require-approval-sensitive.cedar: requires approval for push/commit/network/write on protected refs, non-protected file:delete
use duramen_engine::adapter::PolicyEngine;
use duramen_engine::decision::DecisionTier;
use duramen_engine::entities::*;
use duramen_engine::evaluator::CedarEngine;

fn all_defaults() -> String {
    duramen_policy_defaults::all_default_policies().join("\n")
}

fn make_request(action: &str, resource: AuthzResource) -> AuthzRequest {
    AuthzRequest {
        principal: AgentPrincipal::new("CopilotCLI"),
        action: AuthzAction::new(action),
        resource,
        context: AuthzContext {
            tool_name: "test".into(),
            working_directory: None,
            file_patterns_affected: Vec::new(),
            extra: serde_json::Value::Null,
        },
    }
}

fn file_resource(path: &str, is_protected: bool) -> AuthzResource {
    let mut r = AuthzResource::file(path);
    r.attributes = serde_json::json!({"is_protected": is_protected});
    r
}

fn git_resource(ref_name: &str, is_protected: bool) -> AuthzResource {
    let mut r = AuthzResource::git_ref(ref_name);
    r.attributes = serde_json::json!({"is_protected": is_protected});
    r
}

fn destructive_resource() -> AuthzResource {
    let mut r = AuthzResource::command("rm -rf /");
    r.attributes = serde_json::json!({"is_destructive": true});
    r
}

// ──────────────────────────────────────────────────────────────────
// Combined default policies tests
// ──────────────────────────────────────────────────────────────────

#[test]
fn combined_allows_read_operations() {
    let engine = CedarEngine::from_policy_str(&all_defaults()).unwrap();

    let read_cases = vec![
        ("file:read", AuthzResource::file("/src/main.rs")),
        ("directory:list", AuthzResource::file("/src")),
        ("git:status", AuthzResource::git_ref("HEAD")),
        ("git:log", AuthzResource::git_ref("HEAD")),
        ("git:diff", AuthzResource::git_ref("HEAD")),
        ("git::read", AuthzResource::git_ref("HEAD")),
    ];

    for (action, resource) in read_cases {
        let req = make_request(action, resource);
        let decision = engine.evaluate(&req).unwrap();
        assert_eq!(
            decision.decision,
            DecisionTier::Allow,
            "action '{action}' should be allowed"
        );
    }
}

#[test]
fn combined_audits_file_writes_on_non_protected() {
    let engine = CedarEngine::from_policy_str(&all_defaults()).unwrap();

    for action in ["file:create", "file:edit"] {
        let req = make_request(action, file_resource("/src/lib.rs", false));
        let decision = engine.evaluate(&req).unwrap();
        assert_eq!(
            decision.decision,
            DecisionTier::Audit,
            "action '{action}' on non-protected file should be audited"
        );
    }
}

#[test]
fn combined_denies_force_push() {
    let engine = CedarEngine::from_policy_str(&all_defaults()).unwrap();

    let req = make_request("git:force-push", AuthzResource::git_ref("main"));
    let decision = engine.evaluate(&req).unwrap();
    assert_eq!(decision.decision, DecisionTier::Deny);
}

#[test]
fn combined_denies_destructive_operations() {
    let engine = CedarEngine::from_policy_str(&all_defaults()).unwrap();

    let req = make_request("git::destructive", AuthzResource::git_ref("main"));
    let decision = engine.evaluate(&req).unwrap();
    assert_eq!(decision.decision, DecisionTier::Deny);
}

#[test]
fn combined_denies_destructive_resource() {
    let engine = CedarEngine::from_policy_str(&all_defaults()).unwrap();

    let req = make_request("shell:rm", destructive_resource());
    let decision = engine.evaluate(&req).unwrap();
    assert_eq!(decision.decision, DecisionTier::Deny);
}

#[test]
fn combined_requires_approval_for_push_on_protected() {
    let engine = CedarEngine::from_policy_str(&all_defaults()).unwrap();

    for action in ["git:push", "git:commit", "git::network", "git::write"] {
        let req = make_request(action, git_resource("main", true));
        let decision = engine.evaluate(&req).unwrap();
        assert_eq!(
            decision.decision,
            DecisionTier::RequireApproval,
            "action '{action}' on protected ref should require approval"
        );
    }
}

#[test]
fn combined_requires_approval_for_file_delete_non_protected() {
    let engine = CedarEngine::from_policy_str(&all_defaults()).unwrap();

    let req = make_request("file:delete", file_resource("/tmp/test.txt", false));
    let decision = engine.evaluate(&req).unwrap();
    assert_eq!(decision.decision, DecisionTier::RequireApproval);
}

#[test]
fn combined_denies_file_delete_on_protected() {
    let engine = CedarEngine::from_policy_str(&all_defaults()).unwrap();

    let req = make_request("file:delete", file_resource("/.env", true));
    let decision = engine.evaluate(&req).unwrap();
    assert_eq!(decision.decision, DecisionTier::Deny);
}

#[test]
fn combined_allows_unknown_action() {
    let engine = CedarEngine::from_policy_str(&all_defaults()).unwrap();

    let req = make_request("shell:unknown", AuthzResource::command("mystery"));
    let decision = engine.evaluate(&req).unwrap();
    assert_eq!(
        decision.decision,
        DecisionTier::Allow,
        "unknown actions should be allowed (default permit)"
    );
}

// ──────────────────────────────────────────────────────────────────
// Individual policy tests
// ──────────────────────────────────────────────────────────────────

#[test]
fn allow_default_permits_everything() {
    let engine =
        CedarEngine::from_policy_str(duramen_policy_defaults::ALLOW_DEFAULT).unwrap();

    let req = make_request("file:read", AuthzResource::file("/src/main.rs"));
    let decision = engine.evaluate(&req).unwrap();
    assert_eq!(decision.decision, DecisionTier::Allow);

    // Also allows writes and unknown actions
    let req = make_request("file:edit", AuthzResource::file("/src/main.rs"));
    let decision = engine.evaluate(&req).unwrap();
    assert_eq!(decision.decision, DecisionTier::Allow);

    let req = make_request("shell:unknown", AuthzResource::command("anything"));
    let decision = engine.evaluate(&req).unwrap();
    assert_eq!(decision.decision, DecisionTier::Allow);
}

#[test]
#[allow(deprecated)]
fn allow_read_only_alias_still_works() {
    // ALLOW_READ_ONLY is a deprecated alias for ALLOW_DEFAULT
    assert_eq!(
        duramen_policy_defaults::ALLOW_READ_ONLY,
        duramen_policy_defaults::ALLOW_DEFAULT,
    );
}

#[test]
fn audit_file_writes_produces_audit_tier() {
    let engine =
        CedarEngine::from_policy_str(duramen_policy_defaults::AUDIT_FILE_WRITES).unwrap();

    let req = make_request("file:edit", file_resource("/src/lib.rs", false));
    let decision = engine.evaluate(&req).unwrap();
    assert_eq!(decision.decision, DecisionTier::Audit);
}

#[test]
fn audit_file_writes_skips_protected() {
    let engine =
        CedarEngine::from_policy_str(duramen_policy_defaults::AUDIT_FILE_WRITES).unwrap();

    let req = make_request("file:edit", file_resource("/.env", true));
    let decision = engine.evaluate(&req).unwrap();
    assert_eq!(
        decision.decision,
        DecisionTier::Deny,
        "protected files should not be permitted by audit-file-writes"
    );
}

#[test]
fn deny_destructive_blocks_force_push() {
    let policy = format!(
        "{}\n{}",
        duramen_policy_defaults::ALLOW_DEFAULT,
        duramen_policy_defaults::DENY_DESTRUCTIVE,
    );
    let engine = CedarEngine::from_policy_str(&policy).unwrap();

    let req = make_request("git:force-push", AuthzResource::git_ref("main"));
    let decision = engine.evaluate(&req).unwrap();
    assert_eq!(decision.decision, DecisionTier::Deny);
}

#[test]
fn deny_destructive_blocks_destructive_attribute() {
    let policy = format!(
        "permit(principal, action, resource);\n{}",
        duramen_policy_defaults::DENY_DESTRUCTIVE,
    );
    let engine = CedarEngine::from_policy_str(&policy).unwrap();

    let req = make_request("shell:rm", destructive_resource());
    let decision = engine.evaluate(&req).unwrap();
    assert_eq!(decision.decision, DecisionTier::Deny);
}

#[test]
fn require_approval_sensitive_on_protected_push() {
    let engine = CedarEngine::from_policy_str(
        duramen_policy_defaults::REQUIRE_APPROVAL_SENSITIVE,
    )
    .unwrap();

    let req = make_request("git:push", git_resource("main", true));
    let decision = engine.evaluate(&req).unwrap();
    assert_eq!(decision.decision, DecisionTier::RequireApproval);
}

#[test]
fn require_approval_sensitive_skips_unprotected() {
    let engine = CedarEngine::from_policy_str(
        duramen_policy_defaults::REQUIRE_APPROVAL_SENSITIVE,
    )
    .unwrap();

    let req = make_request("git:push", git_resource("feature-branch", false));
    let decision = engine.evaluate(&req).unwrap();
    assert_eq!(
        decision.decision,
        DecisionTier::Deny,
        "unprotected refs are not covered by require-approval-sensitive"
    );
}

// ──────────────────────────────────────────────────────────────────
// Validate policies test
// ──────────────────────────────────────────────────────────────────

#[test]
fn annotated_policies_return_metadata() {
    let engine = CedarEngine::from_policy_str(&all_defaults()).unwrap();

    // Read-only action should have policy metadata from allow-read-only
    let req = make_request("file:read", AuthzResource::file("/src/main.rs"));
    let decision = engine.evaluate(&req).unwrap();
    assert_eq!(decision.decision, DecisionTier::Allow);
    // Allow decisions from the read-only policy should carry the name
    assert!(
        decision.policy_name.is_some(),
        "annotated permit policy should return policy_name"
    );

    // Audit decision should carry metadata
    let req = make_request("file:edit", file_resource("/src/lib.rs", false));
    let decision = engine.evaluate(&req).unwrap();
    assert_eq!(decision.decision, DecisionTier::Audit);
    assert_eq!(decision.policy_name.as_deref(), Some("Audit file writes"));

    // Require-approval should carry metadata
    let req = make_request("git:push", git_resource("main", true));
    let decision = engine.evaluate(&req).unwrap();
    assert_eq!(decision.decision, DecisionTier::RequireApproval);
    assert!(decision.policy_name.is_some());
}

#[test]
fn default_policies_validate_against_schema() {
    let policies = duramen_policy_defaults::all_default_policies()
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();

    let engine = CedarEngine::from_policy_sources_with_schema(
        &policies,
        duramen_policy_defaults::SCHEMA,
    )
    .unwrap();

    engine.validate_policies().unwrap();
}

#[test]
fn schema_validation_rejects_invalid_policy() {
    let bad_policy = vec![
        r#"permit(principal, action == Action::"nonexistent:action", resource);"#.to_string(),
    ];
    let engine = CedarEngine::from_policy_sources_with_schema(
        &bad_policy,
        duramen_policy_defaults::SCHEMA,
    )
    .unwrap();
    assert!(engine.validate_policies().is_err());
}
