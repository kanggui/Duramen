# Benchmark Report

**Date:** 2026-03-31 00:20 PDT  
**Commit:** `7b7198b` (post-namespace removal)  
**Profile:** Release (Cargo `bench` profile, `opt-level = 3`)

> **Note:** These benchmarks were captured before the multi-evaluation change for chained commands. Individual evaluation times are accurate, but chained commands (e.g., `cmd1 && cmd2`) evaluate N sub-commands independently, multiplying total latency.

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

Core authorization hot path — builds Cedar entities from `AuthzRequest` and evaluates against the default policy set (4 policies, 8 rules).

| Benchmark | Median | Lower | Upper | Decision |
|-----------|-------:|------:|------:|----------|
| `cedar_eval/allow_file_read` | **57.6 µs** | 55.1 µs | 59.8 µs | Allow |
| `cedar_eval/audit_file_edit` | **48.7 µs** | 47.4 µs | 50.0 µs | Audit |
| `cedar_eval/deny_force_push` | **109.2 µs** | 106.7 µs | 111.8 µs | Deny |
| `cedar_eval/require_approval_protected_push` | **114.6 µs** | 111.5 µs | 118.1 µs | RequireApproval |

#### Engine Initialization

| Benchmark | Median | Lower | Upper |
|-----------|-------:|------:|------:|
| `engine_init/parse_default_policies` | **458.0 µs** | 446.5 µs | 469.3 µs |
| `engine_init/parse_and_validate` | **4.29 ms** | 4.19 ms | 4.40 ms |

### End-to-End Pipeline (`cargo bench -p duramen --bench e2e_pipeline`)

Full authorization path: payload normalization → Cedar evaluation → response formatting.

| Benchmark | Median | Lower | Upper | Decision |
|-----------|-------:|------:|------:|----------|
| `e2e/file_read_allow` | **47.6 µs** | 46.3 µs | 49.1 µs | Allow |
| `e2e/file_edit_audit` | **45.7 µs** | 44.9 µs | 46.5 µs | Audit |
| `e2e/destructive_deny` | **43.1 µs** | 41.8 µs | 44.4 µs | Deny |
| `e2e/git_force_push_deny` | **48.2 µs** | 46.8 µs | 50.0 µs | Deny |
| `e2e/git_status_allow` | **49.1 µs** | 47.9 µs | 50.7 µs | Allow |
| `e2e/real_copilot_payload` | **36.0 µs** | 34.9 µs | 37.2 µs | Deny |

### Component Isolation

#### Request Adaptor (normalization only)

| Benchmark | Median | Lower | Upper |
|-----------|-------:|------:|------:|
| `normalizer/simple_tool` | **592 ns** | 546 ns | 643 ns |
| `normalizer/shell_command` | **2.11 µs** | 2.06 µs | 2.16 µs |
| `normalizer/git_command` | **1.65 µs** | 1.61 µs | 1.69 µs |
| `normalizer/real_copilot_format` | **1.70 µs** | 1.66 µs | 1.74 µs |

#### Response Formatter (formatting only)

| Benchmark | Median | Lower | Upper |
|-----------|-------:|------:|------:|
| `formatter/copilot_cli` | **755 ns** | 736 ns | 773 ns |
| `formatter/generic` | **482 ns** | 465 ns | 499 ns |

## Analysis

### Latency Budget

The preToolUse hook adds latency to every agent tool call. Target: < 10ms for negligible UX impact.

```
┌─────────────────────────────────────────────────────────────┐
│ E2E latency breakdown (file_read_allow, ~48µs total)        │
│                                                             │
│ Normalizer:  ~0.6 µs  ██                          (1.3%)   │
│ Cedar eval:  ~47  µs  ████████████████████████████ (97.5%)  │
│ Formatter:   ~0.5 µs  █                           (1.2%)   │
└─────────────────────────────────────────────────────────────┘
```

- **Normalization** and **formatting** are sub-microsecond — negligible
- **Cedar evaluation** dominates at ~48-115µs depending on decision path
- **Deny paths** are slower (~109µs) because Cedar evaluates all policies before concluding no permit matches
- **Total E2E** is **well under 1ms** — ~200x headroom vs the 10ms target
- **Engine init** (~458µs parse, ~4.3ms with validation) is one-time cost per invocation

### Key Takeaways

1. **Sub-millisecond authorization** — every tool call adds < 120µs overhead
2. **Permit decisions are faster than deny** — Cedar short-circuits on first matching permit
3. **Normalization is ~1000x cheaper** than Cedar evaluation
4. **Schema validation is expensive** (~4.3ms) — only run during `duramen validate`, not on every `check`

## Running Benchmarks

```bash
# All benchmarks
cargo bench

# Engine only
cargo bench -p duramen-engine --bench cedar_eval

# E2E pipeline only  
cargo bench -p duramen --bench e2e_pipeline

# Specific benchmark
cargo bench -p duramen --bench e2e_pipeline -- "e2e/file_read"
```

HTML reports are generated in `target/criterion/` with graphs and statistical analysis.
