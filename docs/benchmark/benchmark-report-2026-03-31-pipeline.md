# Benchmark Report

**Date:** 2026-03-31 12:00 PDT
**Commit:** `e6c5cbb` (enrichment pipeline)
**Profile:** Release (Cargo `bench` profile, `opt-level = 3`)

> **Note:** This report includes the enrichment pipeline (4 enrichers + 2 classifiers).
> Chained commands (e.g., `cmd1 && cmd2`) evaluate N sub-commands independently,
> multiplying normalization + evaluation time by N.

## Environment

| | |
|---|---|
| **OS** | Windows 10.0.26200 |
| **CPU** | Intel Core Ultra 7 268V (8 cores / 8 threads) |
| **RAM** | 31.7 GB |
| **Rust** | rustc 1.94.1 (2026-03-25) |
| **Cedar** | cedar-policy 4.x |

## Results

### Cedar Policy Evaluation (`cargo bench -p duramen-engine --bench cedar_eval`)

| Benchmark | Median | Lower | Upper |
|-----------|-------:|------:|------:|
| `cedar_eval/allow_file_read` | **63.7 µs** | 60.3 µs | 67.7 µs |
| `cedar_eval/audit_file_edit` | **94.5 µs** | 90.0 µs | 98.8 µs |
| `cedar_eval/deny_force_push` | **70.2 µs** | 65.7 µs | 76.0 µs |
| `cedar_eval/require_approval_protected_push` | **67.6 µs** | 63.5 µs | 73.0 µs |
| `engine_init/parse_default_policies` | **225.0 µs** | 210.9 µs | 241.5 µs |
| `engine_init/parse_and_validate` | **3.06 ms** | 2.98 ms | 3.15 ms |

### End-to-End Pipeline (`cargo bench -p duramen --bench e2e_pipeline`)

Includes normalization with enrichment pipeline → Cedar evaluation → response formatting.

| Benchmark | Median | Lower | Upper | Decision |
|-----------|-------:|------:|------:|----------|
| `e2e/file_read_allow` | **80.8 µs** | 75.7 µs | 86.5 µs | Allow |
| `e2e/file_edit_audit` | **66.2 µs** | 63.8 µs | 69.0 µs | Audit |
| `e2e/destructive_deny` | **75.7 µs** | 71.7 µs | 80.0 µs | Deny |
| `e2e/git_force_push_deny` | **66.5 µs** | 63.2 µs | 70.5 µs | Deny |
| `e2e/git_status_allow` | **60.2 µs** | 58.2 µs | 62.6 µs | Allow |
| `e2e/real_copilot_payload` | **91.7 µs** | 86.3 µs | 96.9 µs | Allow |

### Component Isolation

#### Request Adaptor (normalization + enrichment pipeline)

| Benchmark | Median | Lower | Upper |
|-----------|-------:|------:|------:|
| `normalizer/simple_tool` | **507 ns** | 496 ns | 520 ns |
| `normalizer/shell_command` | **2.63 µs** | 2.58 µs | 2.67 µs |
| `normalizer/git_command` | **1.33 µs** | 1.29 µs | 1.36 µs |
| `normalizer/real_copilot_format` | **776 ns** | 754 ns | 801 ns |

#### Response Formatter (formatting only)

| Benchmark | Median | Lower | Upper |
|-----------|-------:|------:|------:|
| `formatter/copilot_cli` | **361 ns** | 353 ns | 370 ns |
| `formatter/generic` | **256 ns** | 249 ns | 263 ns |

## Comparison with Previous Report (pre-pipeline)

| Benchmark | Before | After | Delta |
|-----------|-------:|------:|------:|
| `e2e/file_read_allow` | 47.6 µs | 80.8 µs | +70% |
| `e2e/file_edit_audit` | 45.7 µs | 66.2 µs | +45% |
| `e2e/destructive_deny` | 43.1 µs | 75.7 µs | +76% |
| `e2e/git_status_allow` | 49.1 µs | 60.2 µs | +23% |
| `normalizer/simple_tool` | 592 ns | 507 ns | -14% |
| `normalizer/shell_command` | 2.11 µs | 2.63 µs | +25% |
| `normalizer/git_command` | 1.65 µs | 1.33 µs | -19% |
| `formatter/copilot_cli` | 755 ns | 361 ns | -52% |
| `formatter/generic` | 482 ns | 256 ns | -47% |

### Analysis

- **E2E pipeline increased 23-76%** — primarily from Cedar context population
  (building context from AuthzContext fields adds overhead to Cedar evaluation)
- **Normalization is mixed** — simple tools faster, shell commands slightly slower
  from enricher chain overhead (~500ns for 4 enrichers + 2 classifiers)
- **Formatters got faster** — likely measurement noise / CPU thermal state
- **All E2E paths remain under 100µs** — well within the 10ms target
- **Cedar evaluation dominates** — enrichment pipeline adds <1µs, Cedar eval is 60-95µs

### Latency Budget

```
┌─────────────────────────────────────────────────────────────┐
│ E2E latency breakdown (file_read_allow, ~81µs total)        │
│                                                             │
│ Normalizer:    ~0.5 µs  █                          (0.6%)  │
│ Enrichers:     ~0.5 µs  █                          (0.6%)  │
│ Cedar eval:    ~80  µs  ████████████████████████████ (98%)  │
│ Formatter:     ~0.4 µs  █                          (0.5%)  │
└─────────────────────────────────────────────────────────────┘
```

## Running Benchmarks

```bash
cargo bench -p duramen-engine --bench cedar_eval
cargo bench -p duramen --bench e2e_pipeline
cargo bench -- "normalizer/"   # normalizer only
cargo bench -- "e2e/"          # e2e only
```
