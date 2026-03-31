//! End-to-end pipeline benchmarks.
//!
//! Measures the full authorization path: payload normalization → Cedar policy
//! evaluation → response formatting. This is the hot path for every tool call
//! intercepted by the preToolUse hook.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use duramen_engine::adapter::PolicyEngine;
use duramen_engine::entities::RawHookPayload;
use duramen_engine::evaluator::CedarEngine;
use duramen_policy_defaults;
use duramen_request_adaptor::get_normalizer;
use duramen_response_formatter::get_formatter;

fn default_engine() -> CedarEngine {
    let policies = duramen_policy_defaults::all_default_policies().join("\n");
    CedarEngine::from_policy_str(&policies).unwrap()
}

fn bench_e2e_pipeline(c: &mut Criterion) {
    let engine = default_engine();
    let normalizer = get_normalizer("copilot-cli").unwrap();
    let formatter = get_formatter("copilot-cli").unwrap();

    // File read — allowed
    c.bench_function("e2e/file_read_allow", |b| {
        let payload: RawHookPayload = serde_json::from_str(
            r#"{"tool":"view","args":{"path":"/src/main.rs"},"cwd":"/project"}"#,
        )
        .unwrap();
        b.iter(|| {
            let reqs = normalizer.normalize(black_box(&payload)).unwrap();
            let decision = engine.evaluate(&reqs[0]).unwrap();
            let resp = formatter.format(&decision, &reqs[0]);
            assert_eq!(resp.exit_code, 0);
        });
    });

    // File edit — audited (allow + log)
    c.bench_function("e2e/file_edit_audit", |b| {
        let payload: RawHookPayload = serde_json::from_str(
            r#"{"tool":"edit","args":{"path":"/src/lib.rs"},"cwd":"/project"}"#,
        )
        .unwrap();
        b.iter(|| {
            let reqs = normalizer.normalize(black_box(&payload)).unwrap();
            let decision = engine.evaluate(&reqs[0]).unwrap();
            let resp = formatter.format(&decision, &reqs[0]);
            assert_eq!(resp.exit_code, 0);
        });
    });

    // Destructive command — denied
    c.bench_function("e2e/destructive_deny", |b| {
        let payload: RawHookPayload = serde_json::from_str(
            r#"{"tool":"bash","args":{"command":"rm -rf /"},"cwd":"/project"}"#,
        )
        .unwrap();
        b.iter(|| {
            let reqs = normalizer.normalize(black_box(&payload)).unwrap();
            let decision = engine.evaluate(&reqs[0]).unwrap();
            let resp = formatter.format(&decision, &reqs[0]);
            assert_eq!(resp.exit_code, 1);
        });
    });

    // Git force push — denied
    c.bench_function("e2e/git_force_push_deny", |b| {
        let payload: RawHookPayload = serde_json::from_str(
            r#"{"tool":"bash","args":{"command":"git push --force origin main"},"cwd":"/project"}"#,
        )
        .unwrap();
        b.iter(|| {
            let reqs = normalizer.normalize(black_box(&payload)).unwrap();
            let decision = engine.evaluate(&reqs[0]).unwrap();
            let resp = formatter.format(&decision, &reqs[0]);
            assert_eq!(resp.exit_code, 1);
        });
    });

    // Git status — allowed (read)
    c.bench_function("e2e/git_status_allow", |b| {
        let payload: RawHookPayload = serde_json::from_str(
            r#"{"tool":"bash","args":{"command":"git status"},"cwd":"/project"}"#,
        )
        .unwrap();
        b.iter(|| {
            let reqs = normalizer.normalize(black_box(&payload)).unwrap();
            let decision = engine.evaluate(&reqs[0]).unwrap();
            let resp = formatter.format(&decision, &reqs[0]);
            assert_eq!(resp.exit_code, 0);
        });
    });

    // Real Copilot CLI payload format (toolName/toolArgs as string)
    c.bench_function("e2e/real_copilot_payload", |b| {
        let payload: RawHookPayload = serde_json::from_str(
            r#"{"timestamp":1704614600000,"cwd":"/project","toolName":"bash","toolArgs":"{\"command\":\"cargo test\"}"}"#,
        )
        .unwrap();
        b.iter(|| {
            let reqs = normalizer.normalize(black_box(&payload)).unwrap();
            let decision = engine.evaluate(&reqs[0]).unwrap();
            let resp = formatter.format(&decision, &reqs[0]);
            black_box(resp);
        });
    });
}

fn bench_normalizer_only(c: &mut Criterion) {
    let normalizer = get_normalizer("copilot-cli").unwrap();

    c.bench_function("normalizer/simple_tool", |b| {
        let payload: RawHookPayload = serde_json::from_str(
            r#"{"tool":"edit","args":{"path":"/src/main.rs"},"cwd":"/project"}"#,
        )
        .unwrap();
        b.iter(|| {
            normalizer.normalize(black_box(&payload)).unwrap();
        });
    });

    c.bench_function("normalizer/shell_command", |b| {
        let payload: RawHookPayload = serde_json::from_str(
            r#"{"tool":"bash","args":{"command":"cargo build --release"},"cwd":"/project"}"#,
        )
        .unwrap();
        b.iter(|| {
            normalizer.normalize(black_box(&payload)).unwrap();
        });
    });

    c.bench_function("normalizer/git_command", |b| {
        let payload: RawHookPayload = serde_json::from_str(
            r#"{"tool":"bash","args":{"command":"git push --force origin main"},"cwd":"/project"}"#,
        )
        .unwrap();
        b.iter(|| {
            normalizer.normalize(black_box(&payload)).unwrap();
        });
    });

    c.bench_function("normalizer/real_copilot_format", |b| {
        let payload: RawHookPayload = serde_json::from_str(
            r#"{"timestamp":1704614600000,"cwd":"/project","toolName":"edit","toolArgs":"{\"path\":\"/src/main.rs\",\"old_str\":\"foo\",\"new_str\":\"bar\"}"}"#,
        )
        .unwrap();
        b.iter(|| {
            normalizer.normalize(black_box(&payload)).unwrap();
        });
    });
}

fn bench_formatter_only(c: &mut Criterion) {
    let engine = default_engine();
    let normalizer = get_normalizer("copilot-cli").unwrap();
    let copilot_fmt = get_formatter("copilot-cli").unwrap();
    let generic_fmt = get_formatter("generic").unwrap();

    let payload: RawHookPayload = serde_json::from_str(
        r#"{"tool":"view","args":{"path":"/src/main.rs"},"cwd":"/project"}"#,
    )
    .unwrap();
    let reqs = normalizer.normalize(&payload).unwrap();
    let decision = engine.evaluate(&reqs[0]).unwrap();

    c.bench_function("formatter/copilot_cli", |b| {
        b.iter(|| {
            copilot_fmt.format(black_box(&decision), black_box(&reqs[0]));
        });
    });

    c.bench_function("formatter/generic", |b| {
        b.iter(|| {
            generic_fmt.format(black_box(&decision), black_box(&reqs[0]));
        });
    });
}

criterion_group!(benches, bench_e2e_pipeline, bench_normalizer_only, bench_formatter_only);
criterion_main!(benches);
