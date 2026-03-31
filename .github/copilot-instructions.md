# Copilot Instructions for Duramen

## Build & Test

```bash
cargo build                              # Build all crates
cargo test                               # Run all tests
cargo test -p duramen-engine             # Test engine crate only
cargo test -p duramen -- check           # Run only check-related tests
cargo test -p duramen-engine --test default_policies_test  # Run policy eval tests only
cargo run -p duramen -- check --help     # Test CLI locally
```

## Architecture

Rust Cargo workspace with 6 crates. `engine` is the core — all other crates depend on it.

```
              ┌──────────────────┐
stdin ──────► │ request-adaptor  │──► AuthzRequest ──► engine ──► AuthzDecision
              │ (per-agent input)│                   (Cedar eval)       │
              └──────────────────┘                                     ▼
              ┌──────────────────┐                              ┌─────────────┐
stdout ◄───── │response-formatter│◄─────────────────────────────│ audit logger │
              │(per-agent output)│                              └─────────────┘
              └──────────────────┘
```

- **engine** — Core: `PolicyEngine` trait, `CedarEngine` (Cedar evaluation + schema validation), entity types (`AuthzRequest`, `AuthzDecision`), policy loading/merging.
- **request-adaptor** — Input: converts agent-specific hook payloads → `AuthzRequest`. Includes command handler registry, enrichment pipeline (path sensitivity, file metadata, network domain, elevation), and action classifiers (destructive, package install).
- **response-formatter** — Output: converts `AuthzDecision` → agent response JSON. Trait: `ResponseFormatter`.
- **audit** — JSON-line structured audit logging (`AuditLogger`, `AuditEntry`).
- **policy-defaults** — Embeds default Cedar policies and schema at compile time via `include_str!`.
- **cli** — Binary entry point. Subcommands: `check`, `validate`, `init`, `audit`.

## Key Conventions

- **Adapter pair pattern:** The `--agent` flag selects both a normalizer (input) and formatter (output) as a matched pair. Register in `get_normalizer()` in `request-adaptor/src/lib.rs` and `get_formatter()` in `response-formatter/src/lib.rs`.
- **Command handler registry:** Shell commands (bash/powershell) are parsed by `CommandHandler` implementations in `request-adaptor/src/commands/`. Register new handlers in `get_command_handler()` in `commands/mod.rs`. Unregistered commands fall through to `DefaultCommandHandler`.
- **Enrichment pipeline:** After command parsing, resources pass through `ResourceEnricher` chain (path sensitivity, file metadata, network domain, elevation) then `ActionClassifier` chain (destructive detection, package install). Add new security concerns by implementing traits in `request-adaptor/src/enrichers/` or `classifiers/`. See `pipeline.rs` for the `EnrichmentPipeline` runner.
- **Fail-closed:**Any engine error results in a `deny` decision. Hook scripts deny on unexpected exit codes. Security systems never fail-open.
- **Decision tiers:** `allow` (exit 0), `audit` (exit 0 + log), `require-approval` (exit 2), `deny` (exit 1), `error` (exit 3).
- **Cedar advice annotations:** `@advice("audit")` and `@advice("require-approval")` on Cedar `permit` policies promote Allow → Audit/RequireApproval. See `evaluator.rs::check_advice()`.
- **Policy resolution order:** repo `.authz/` > user `~/.config/duramen/` > compiled-in defaults.
- **Entity model:** Principals are `Agent::`, resources are `File::`, `Command::`, `Url::`, `GitRef::`. No Cedar namespace prefix needed.
- **Schema validation:** Policies use `has` guards for optional attributes (e.g., `resource has is_protected && resource.is_protected == true`) to pass Cedar's strict validator.
- **Example policies:** `policies/examples/` contains reference policies (allow-all, deny-network, team-workflow) that users can copy into `.authz/`.

## Testing Patterns

- **Unit tests:** Inline `#[cfg(test)] mod tests` in each crate's source files.
- **Policy evaluation tests:** `crates/engine/tests/default_policies_test.rs` — tests each default policy individually and combined. Uses helper builders (`make_request()`, `file_resource()`, `git_resource()`), asserts exact `DecisionTier`.
- **CLI integration tests:** `crates/cli/tests/` — uses `assert_cmd::Command::cargo_bin("duramen")` to run the binary, `write_stdin()` for hook payloads, predicates for output assertions.

## Agent Hook Integration

### Hook protocol

Copilot CLI sends tool calls as JSON on stdin via `preToolUse` hook. The hook scripts (`hooks/copilot-cli/duramen-hook.sh` and `hooks/copilot-cli/duramen-hook.ps1`) pipe through `duramen check --agent copilot-cli` and return:
```json
{"permissionDecision": "allow"}
{"permissionDecision": "deny", "permissionDecisionReason": "Blocked by policy"}
{"permissionDecision": "ask", "permissionDecisionReason": "Requires approval"}
```

Hook config is at `hooks/copilot-cli/duramen.json`. The JSON has both `bash` and `powershell` properties for cross-platform support — Copilot CLI picks the right one per OS.

### Testing the hook locally

```bash
echo '{"tool":"edit","args":{"path":"/src/main.rs"}}' | duramen check --agent copilot-cli
echo '{"tool":"powershell","args":{"command":"rm -rf /"}}' | duramen check --agent copilot-cli
```

### Adding a new agent

1. Create `crates/request-adaptor/src/<agent>.rs` implementing `AgentNormalizer`
2. Create `crates/response-formatter/src/<agent>.rs` implementing `ResponseFormatter`
3. Add match arm in `get_normalizer()` (`request-adaptor/src/lib.rs`) and `get_formatter()` (`response-formatter/src/lib.rs`)
4. Use with `--agent <name>`
