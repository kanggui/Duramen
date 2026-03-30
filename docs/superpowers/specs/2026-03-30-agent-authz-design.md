# AgentAuthZ Design Specification

## Problem

AI coding agents (Copilot CLI, Cursor, Codex, etc.) execute tool calls — file edits, shell commands, git operations, network requests — without fine-grained authorization checks. There is no standard mechanism to enforce policies like "deny destructive commands" or "require approval before pushing to main" across agents.

## Approach

Build a Rust CLI tool (`agent-authz`) that embeds the Cedar authorization engine. Agents invoke it as a pre-tool-use hook before each operation. The CLI evaluates the request against Cedar policies and returns a tiered decision: allow, audit, require-approval, or deny.

Design for multi-agent support from the start via a normalization layer that converts each agent's hook payload into a unified Cedar entity model.

---

## Entity Model (Cedar Schema)

Authorization is expressed as: **Principal** performs **Action** on **Resource** in **Context**.

### Principals

Each coding agent is a distinct Cedar principal:

- `Agent::"CopilotCLI"`, `Agent::"Cursor"`, `Agent::"Codex"`
- Attributes: `trust_level`, `session_id`, `user`

### Actions

Hierarchically organized:

- **File:** `file:create`, `file:read`, `file:edit`, `file:delete`
- **Shell:** `shell:execute`
- **Git:** `git:commit`, `git:push`, `git:force-push`, `git:branch`
- **Network:** `network:fetch`
- **Custom:** `tool:<name>` for extensibility
- **Groups:** `file:*` (all file actions), `destructive` (dangerous operations)

### Resources

- `File::"/path"` — attributes: `extension`, `directory`, `is_protected`
- `Command::"<cmd>"` — attributes: `binary`, `args`, `is_destructive`
- `Url::"https://..."` — network targets
- `GitRef::"main"` — branches, attributes: `is_protected`

### Context

- `tool_name`: which agent tool is being invoked
- `working_directory`: repo root
- `file_patterns_affected`: glob patterns of files being touched

### Decision Tiers

| Decision | Exit Code | Behavior |
|---|---|---|
| `allow` | 0 | Proceed silently |
| `audit` | 0 | Proceed, write to audit log |
| `require-approval` | 2 | Block, prompt human for approval |
| `deny` | 1 | Block with reason |
| `error` | 3 | System failure (malformed input, bad policy) |

---

## Project Structure

```
agent-authz/
├── Cargo.toml                  # Workspace root
├── crates/
│   ├── cli/                    # CLI binary (agent-authz)
│   │   └── src/
│   │       ├── main.rs         # Entry point, arg parsing (clap)
│   │       ├── commands/       # check, validate, init, audit subcommands
│   │       └── output.rs       # JSON/human-readable output formatting
│   ├── engine/                 # Core authorization engine
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── evaluator.rs    # Cedar policy evaluation wrapper
│   │       ├── entities.rs     # Entity construction (Agent, File, Command, etc.)
│   │       ├── policy.rs       # Policy loading, compilation, validation
│   │       ├── decision.rs     # Decision types (Allow/Audit/RequireApproval/Deny)
│   │       └── adapter.rs      # PolicyEngine trait for swappable backends
│   ├── normalizer/             # Agent-specific payload normalization
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── traits.rs       # AgentNormalizer trait
│   │       ├── copilot_cli.rs  # Copilot CLI hook payload normalizer
│   │       └── generic.rs      # Generic/fallback normalizer
│   ├── audit/                  # Audit logging
│   │   └── src/
│   │       ├── lib.rs
│   │       └── logger.rs       # Structured JSON audit log writer
│   └── policy-defaults/        # Default policy set
│       └── src/
│           └── lib.rs          # Embeds default .cedar policies via include_str!()
├── policies/
│   ├── default/                # Shipped default policies
│   │   ├── schema.cedarschema  # Cedar schema definition
│   │   ├── deny-destructive.cedar
│   │   ├── audit-file-writes.cedar
│   │   ├── allow-read-only.cedar
│   │   └── require-approval-sensitive.cedar
│   └── examples/               # Example custom policies
├── tests/
│   ├── integration/            # End-to-end CLI tests
│   └── policy/                 # Policy evaluation tests
└── docs/
```

### Component Responsibilities

**`cli` crate** — The `agent-authz` binary. Subcommands:
- `check`: Evaluate an authorization request
- `validate`: Lint/compile-check policies
- `init`: Scaffold `.authz/` directory in a repo
- `audit`: Query the audit log

**`engine` crate** — Core authorization library. Houses the `PolicyEngine` trait (adapter layer for swappable backends) and the `CedarEngine` implementation. Constructs Cedar entities from normalized input, loads and compiles policies, runs evaluation.

**`normalizer` crate** — Converts agent-specific hook payloads into the unified `AuthzRequest` model. Each agent gets a normalizer implementation behind the `AgentNormalizer` trait.

**`audit` crate** — Writes structured JSON decision logs. Kept separate for reuse if the project evolves to daemon mode.

**`policy-defaults` crate** — Embeds default Cedar policies at compile time so the binary ships with safe defaults even without repo-local policies.

---

## Agent Normalization Layer

Each agent provides tool-call data in a different format. The normalization layer converts agent-specific hook payloads into the unified Cedar entity model.

### Flow

```
Agent Hook Payload → Normalizer (per-agent) → Unified AuthzRequest → Cedar Evaluator
```

### Unified AuthzRequest

```rust
struct AuthzRequest {
    principal: AgentPrincipal,    // Agent type + instance ID
    action: AuthzAction,          // Canonical action (e.g., "file:write")
    resource: AuthzResource,      // Typed resource with attributes
    context: AuthzContext,        // Tool name, working dir, session metadata
}
```

### AgentNormalizer Trait

```rust
trait AgentNormalizer {
    fn normalize(&self, raw_input: &RawHookPayload) -> Result<AuthzRequest>;
    fn agent_type(&self) -> &str;  // "copilot-cli", "cursor", "codex", etc.
}
```

### Implementations

- `CopilotCliNormalizer` — Maps Copilot CLI hook payloads to `AuthzRequest`
- `GenericNormalizer` — Fallback for agents that pass pre-formatted JSON matching the schema
- Future: `CursorNormalizer`, `CodexNormalizer`, etc.

### CLI Input Modes

The `check` command accepts either:
1. **Explicit args** (`--principal`, `--action`, `--resource`, `--context`) — used with the generic normalizer
2. **Agent-specific stdin** (`--agent copilot-cli < hook_payload.json`) — piped through the agent's normalizer

---

## CLI Interface

```bash
# Evaluate an authorization request
agent-authz check \
  --principal "CopilotCLI" \
  --action "file:delete" \
  --resource "/src/main.rs" \
  --context '{"tool":"powershell","command":"rm src/main.rs"}' \
  --policy-dir .authz/

# Agent-specific input via stdin
echo '{"tool":"powershell","args":{"command":"rm -rf /"}}' | \
  agent-authz check --agent copilot-cli --policy-dir .authz/

# Scaffold policies in a repo
agent-authz init

# Validate policies
agent-authz validate --policy-dir .authz/

# Query audit log
agent-authz audit --since "1h" --decision deny --principal CopilotCLI
```

### Policy Resolution Order

1. Repo-local `.authz/` directory (highest priority)
2. User-level `~/.config/agent-authz/` policies
3. Built-in defaults (lowest priority, compiled into binary)

---

## Default Policy Set

Shipped policies providing safety out of the box:

### `deny-destructive.cedar`
Denies operations classified as destructive:
- `rm -rf`, `git push --force`, deleting protected files (`.env`, `Cargo.lock`, etc.)
- Modifications to CI/CD configs (`.github/workflows/`, `.gitlab-ci.yml`)
- Any shell command with `sudo`

### `audit-file-writes.cedar`
Allows file writes but logs them to the audit trail. Covers `file:create`, `file:edit` for all non-protected paths.

### `allow-read-only.cedar`
Unconditionally allows read-only operations: `file:read`, `directory:list`, `git:status`, `git:log`, `git:diff`.

### `require-approval-sensitive.cedar`
Requires human approval for:
- Modifying secrets/credentials files
- Network requests to non-allowlisted domains
- Git operations on protected branches (`main`, `master`, `release/*`)

---

## Audit Logging

Each authorization decision is written as a JSON line to `~/.agent-authz/audit.log`:

```json
{
  "timestamp": "2026-03-30T19:30:00Z",
  "request_id": "uuid",
  "principal": {"type": "Agent", "id": "CopilotCLI"},
  "action": "file:delete",
  "resource": {"type": "File", "path": "/src/main.rs"},
  "context": {"tool": "powershell", "working_dir": "/repo"},
  "raw_command": {
    "tool": "powershell",
    "args": {"command": "rm src/main.rs", "description": "Delete main file"}
  },
  "decision": "deny",
  "reason": "Deleting source files is denied by deny-destructive policy",
  "policy_id": "deny-destructive",
  "evaluation_time_ms": 2
}
```

The `raw_command` field preserves the complete original tool invocation — tool name, all arguments, and metadata — exactly as the agent received it before normalization.

---

## Testing Strategy

1. **Unit tests** (per crate) — Entity construction, policy compilation, normalizer logic, decision mapping
2. **Policy tests** (`tests/policy/`) — Cedar policy evaluation tests using Cedar's built-in test framework. Each default policy gets a test file with allow/deny scenarios.
3. **Integration tests** (`tests/integration/`) — End-to-end CLI tests: invoke `agent-authz check` with various inputs, assert exit codes and JSON output. Uses `assert_cmd` crate.
4. **Example hook tests** — Simulate an agent hook flow: payload → normalize → evaluate → assert decision

## Error Handling

- Invalid/missing policies → exit 3 with descriptive error JSON
- Malformed input → exit 3 with validation error
- Policy compilation failure → `validate` subcommand catches this before runtime
- Cedar evaluation errors → logged + treated as `deny` (fail-closed)

**Fail-closed principle:** If the authorization system itself fails (corrupt policies, unexpected input), the default is `deny`. Security systems must never fail-open.
