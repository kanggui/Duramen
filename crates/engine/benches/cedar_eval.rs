//! Benchmarks for Cedar policy evaluation performance.
//!
//! Measures the core authorization hot path: building Cedar entities from an
//! AuthzRequest and evaluating against the default policy set.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use duramen_engine::adapter::PolicyEngine;
use duramen_engine::decision::DecisionTier;
use duramen_engine::entities::*;
use duramen_engine::evaluator::CedarEngine;

fn default_engine() -> CedarEngine {
    let policies = duramen_policy_defaults::all_default_policies().join("\n");
    CedarEngine::from_policy_str(&policies).unwrap()
}

fn file_read_request() -> AuthzRequest {
    AuthzRequest {
        principal: AgentPrincipal::new("CopilotCLI"),
        action: AuthzAction::new("file:read"),
        resource: AuthzResource::file("/src/main.rs"),
        context: AuthzContext {
            tool_name: "view".into(),
            working_directory: Some("/project".into()),
            file_patterns_affected: Vec::new(),
            extra: serde_json::Value::Null,
        },
    }
}

fn file_edit_request() -> AuthzRequest {
    let mut r = AuthzResource::file("/src/lib.rs");
    r.attributes = serde_json::json!({"is_protected": false});
    AuthzRequest {
        principal: AgentPrincipal::new("CopilotCLI"),
        action: AuthzAction::new("file:edit"),
        resource: r,
        context: AuthzContext {
            tool_name: "edit".into(),
            working_directory: Some("/project".into()),
            file_patterns_affected: vec!["/src/lib.rs".into()],
            extra: serde_json::Value::Null,
        },
    }
}

fn git_force_push_request() -> AuthzRequest {
    let mut r = AuthzResource::git_ref("main");
    r.attributes = serde_json::json!({"is_destructive": true, "remote": "origin"});
    AuthzRequest {
        principal: AgentPrincipal::new("CopilotCLI"),
        action: AuthzAction::new("git:force-push"),
        resource: r,
        context: AuthzContext {
            tool_name: "bash".into(),
            working_directory: Some("/project".into()),
            file_patterns_affected: Vec::new(),
            extra: serde_json::Value::Null,
        },
    }
}

fn git_push_protected_request() -> AuthzRequest {
    let mut r = AuthzResource::git_ref("main");
    r.attributes = serde_json::json!({"is_protected": true});
    AuthzRequest {
        principal: AgentPrincipal::new("CopilotCLI"),
        action: AuthzAction::new("git:push"),
        resource: r,
        context: AuthzContext {
            tool_name: "bash".into(),
            working_directory: Some("/project".into()),
            file_patterns_affected: Vec::new(),
            extra: serde_json::Value::Null,
        },
    }
}

fn bench_cedar_eval(c: &mut Criterion) {
    let engine = default_engine();

    c.bench_function("cedar_eval/allow_file_read", |b| {
        let req = file_read_request();
        b.iter(|| {
            let decision = engine.evaluate(black_box(&req)).unwrap();
            assert_eq!(decision.decision, DecisionTier::Allow);
        });
    });

    c.bench_function("cedar_eval/audit_file_edit", |b| {
        let req = file_edit_request();
        b.iter(|| {
            let decision = engine.evaluate(black_box(&req)).unwrap();
            assert_eq!(decision.decision, DecisionTier::Audit);
        });
    });

    c.bench_function("cedar_eval/deny_force_push", |b| {
        let req = git_force_push_request();
        b.iter(|| {
            let decision = engine.evaluate(black_box(&req)).unwrap();
            assert_eq!(decision.decision, DecisionTier::Deny);
        });
    });

    c.bench_function("cedar_eval/require_approval_protected_push", |b| {
        let req = git_push_protected_request();
        b.iter(|| {
            let decision = engine.evaluate(black_box(&req)).unwrap();
            assert_eq!(decision.decision, DecisionTier::RequireApproval);
        });
    });
}

fn bench_engine_init(c: &mut Criterion) {
    let policies = duramen_policy_defaults::all_default_policies().join("\n");

    c.bench_function("engine_init/parse_default_policies", |b| {
        b.iter(|| {
            let engine = CedarEngine::from_policy_str(black_box(&policies)).unwrap();
            black_box(engine);
        });
    });

    c.bench_function("engine_init/parse_and_validate", |b| {
        let policy_sources: Vec<String> = duramen_policy_defaults::all_default_policies()
            .iter()
            .map(|s| s.to_string())
            .collect();
        let schema = duramen_policy_defaults::SCHEMA;
        b.iter(|| {
            let engine = CedarEngine::from_policy_sources_with_schema(
                black_box(&policy_sources),
                black_box(schema),
            )
            .unwrap();
            engine.validate_policies().unwrap();
        });
    });
}

criterion_group!(benches, bench_cedar_eval, bench_engine_init);
criterion_main!(benches);
