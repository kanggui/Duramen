# Duramen 🌲

**Status:** Alpha — functional and tested (219 tests), used with GitHub Copilot CLI. API may change.

> **Duramen** is the botanical term for heartwood — the dense, decay-resistant inner core of a cedar tree. It's a perfect metaphor for a security layer that keeps the "trunk" of the agent's logic from rotting or being compromised.

Fine-grained authorization for AI coding agents, powered by [Cedar](https://www.cedarpolicy.com/).

## Quick Start

```bash
# Build
cargo build --release

# Initialize policies in your repo
./target/release/duramen init

# Install hooks for Copilot CLI
./hooks/copilot-cli/install.sh /path/to/your/repo

# That's it! Duramen now evaluates every tool call before execution.
```

## What It Looks Like

When Copilot CLI tries a safe operation:
```
✓ Edit src/main.rs (edit)
```

When it tries something destructive:
```
✗ Hard reset last 3 commits (shell)
  │ git reset --hard HEAD~3
  └ Denied by preToolUse hook: request denied by policy
    [Deny destructive git: Blocks destructive git operations like reset --hard and branch -D]
```

When a file write is audited:
```
✓ Create src/utils.rs (create)
  └ Allowed (audit logged to ~/.duramen/audit.log)
```

## Problem

AI coding agents (GitHub Copilot CLI, Cursor, Codex, etc.) execute powerful tool calls — file edits, shell commands, git operations, network requests — with minimal guardrails. A single misguided `rm -rf /`, an accidental `git push --force` to main, or a write to a secrets file can cause serious damage. Today there is no standard mechanism to enforce policies like "deny destructive commands" or "require human approval before pushing to protected branches" across agents.

## Goals

- **Prevent high-risk operations** before they execute — not after the damage is done
- **Support multiple agents** with a single policy engine (Copilot CLI today, Cursor/Codex/others tomorrow)
- **Four-tier enforcement** — allow, audit (allow + log), require-approval (block + prompt), deny
- **Policy-as-code** — Cedar policies checked into the repo, customizable per project
- **Fail-closed** — if the authorization system itself fails, default to deny

## Approach

Duramen is a Rust CLI tool that hooks into an agent's **pre-tool-use** lifecycle. Before the agent executes any tool call, the hook pipes the request through `duramen check`, which evaluates it against Cedar authorization policies and returns a decision.

```
Agent plans tool call → preToolUse hook fires → duramen evaluates → allow/deny/audit/approve
```

Duramen uses [Cedar](https://www.cedarpolicy.com/), an open-source policy language designed for authorization. Cedar provides deny-overrides semantics (a single `forbid` blocks regardless of `permit` rules), schema validation for type-checking policies at authoring time (`duramen validate`), sub-millisecond evaluation fast enough for inline hook execution, and Rust-native integration with no FFI or network overhead.

### Why a CLI?

A CLI tool is the simplest integration path — any agent that supports pre-tool hooks can shell out to `duramen check`. No SDK embedding, no daemon management, no language-specific bindings needed.

### Policy Resolution

Policies are loaded in additive merge order (all policies are combined, Cedar deny-overrides semantics apply):

1. **Repo-local** `.authz/` — project-specific overrides
2. **User-level** `~/.config/duramen/policies` — personal defaults
3. **Built-in defaults** — compiled into the binary, always available

### Decision Tiers

| Decision | Exit Code | Behavior | Cedar Mechanism |
|---|---|---|---|
| `allow` | 0 | Proceed silently | `permit` policy matches |
| `audit` | 0 | Proceed + write audit log | `permit` with `@advice("audit")` |
| `require-approval` | 2 | Prompt user for confirmation | `permit` with `@advice("require-approval")` |
| `deny` | 1 | Block with reason | `forbid` policy matches or no `permit` |

Exit code 3 indicates a system error (malformed input, policy parse failure). This is not a decision tier — it always results in denial (fail-closed).

## Setup

### Prerequisites

- Rust toolchain (`rustup install stable`)

### Build

```bash
cargo build --release
# Binary at target/release/duramen
```

### Initialize policies in your repo

```bash
duramen init
# Creates .authz/ with default Cedar policies:
#   schema.cedarschema       — entity type definitions
#   allow-default.cedar       — permits all actions not explicitly forbidden
#   deny-destructive.cedar   — forbids rm -rf, force-push, sudo
#   audit-file-writes.cedar  — permits file edits with audit logging
#   require-approval-sensitive.cedar — requires approval for protected branches
```

### Installing Policies

Duramen loads policies from three locations. All are combined — Cedar's deny-overrides semantics mean a `forbid` at any level blocks the action.

**Repo-level** (`.authz/` in your project — shared with the team):

```bash
# Generate defaults
duramen init

# Add a custom policy
cat > .authz/no-network.cedar << 'EOF'
forbid(principal, action == Action::"network:fetch", resource);
EOF

# Copy an example policy
cp policies/examples/team-workflow.cedar .authz/

# Commit policies with your code
git add .authz/ && git commit -m "Add authorization policies"
```

**User-level** (`~/.config/duramen/policies` — applies to ALL your repos):

```bash
# Create user policy directory
mkdir -p ~/.config/duramen/policies

# Add personal policies that apply everywhere
cat > ~/.config/duramen/policies/my-rules.cedar << 'EOF'
@advice("require-approval")
permit(principal, action == Action::"git:push", resource);
EOF
```

**Built-in defaults** (compiled into the binary — always available, lowest priority):

The 4 default policies ship with the binary. They apply even without `duramen init`. Run `duramen init` to copy them to `.authz/` for customization.

### Validate policies

```bash
# Check policies parse correctly and match the Cedar schema
duramen validate --policy-dir .authz/
```

### Copilot CLI hook integration

Use the install script to set up hooks in any repo:

```bash
# Install hooks (copies config + scripts + optionally the binary)
./hooks/copilot-cli/install.sh /path/to/your/repo

# Or on Windows
.\hooks\copilot-cli\install.ps1 -RepoPath C:\path\to\your\repo
```

Copilot CLI auto-discovers hooks in `.github/hooks/` and fires `preToolUse` before every tool call. See [hooks/copilot-cli/README.md](hooks/copilot-cli/README.md) for details.

### Manual usage

```bash
# Check with explicit arguments
duramen check \
  --principal CopilotCLI \
  --action file:delete \
  --resource /src/main.rs

# Check with agent-specific normalization (stdin)
echo '{"tool":"powershell","args":{"command":"rm -rf /"}}' | \
  duramen check --agent copilot-cli

# Validate your policies against the Cedar schema
duramen validate --policy-dir .authz/

# Query the audit log
duramen audit --since 24h --decision deny
```

## Default Policies

| Policy | What it does |
|---|---|
| `allow-default.cedar` | Permits all actions not explicitly forbidden by other policies (catch-all) |
| `deny-destructive.cedar` | Forbids `git:force-push`, `git::destructive`, any action on resources with `is_destructive`, protected file deletes |
| `audit-file-writes.cedar` | Permits `file:create` and `file:edit` on non-protected files, logs to audit trail |
| `require-approval-sensitive.cedar` | Requires human approval for `git:push`/`git:commit`/`git::network`/`git::write` on protected refs, non-protected `file:delete` |

### Writing custom policies

Cedar policies live in `.authz/`. See `policies/examples/` for ready-to-use templates:

| Example | Description |
|---|---|
| `allow-all.cedar` | Permits everything — for development/testing |
| `deny-network.cedar` | Blocks all network access and git push |
| `team-workflow.cedar` | Realistic team policy with audit + approval tiers |

Custom policy example — deny network access entirely:

```cedar
forbid(
    principal,
    action == Action::"network:fetch",
    resource
);
```

Example — only allow a specific agent to edit CI files:

```cedar
forbid(
    principal,
    action == Action::"file:edit",
    resource
) when {
    resource has directory && resource.directory == ".github/workflows"
} unless {
    principal == Agent::"CopilotCLI"
};
```

## Audit Log

Non-allow authorization decisions (audit, require-approval, deny) are logged as JSON lines to `~/.duramen/audit.log`:

```json
{
  "timestamp": "2026-03-30T19:30:00Z",
  "request_id": "uuid",
  "principal": {"type": "Agent", "id": "CopilotCLI"},
  "action": "file:delete",
  "resource": {"type": "File", "path": "/src/main.rs"},
  "context": {
    "tool": "powershell",
    "working_dir": "/project",
    "file_patterns_affected": ["/src/main.rs"]
  },
  "raw_command": {"tool": "powershell", "args": {"command": "rm src/main.rs"}},
  "decision": "deny",
  "reason": "request denied by policy",
  "policy_id": "deny-destructive-resource"
}
```

### Querying the audit log

```bash
# Show all entries
duramen audit

# Show denials from the last hour
duramen audit --since 1h --decision deny

# Show last 10 entries from a specific log file
duramen audit --limit 10 --log-path ./audit.log
```

Supported `--since` units: `m` (minutes), `h` (hours), `d` (days), `s` (seconds).

## Solution Architecture

```
┌─────────────────────────────────────────────────────┐
│                    AGENT                            │
│  Tool call planned → preToolUse hook fires          │
└──────────────────────┬──────────────────────────────┘
                       │ stdin (tool payload JSON)
                       ▼
┌──────────────────────────────────────────────────────┐
│              duramen check --agent <name>        │
│                                                      │
│  Request Adaptor ─→ AuthzRequest ─→ Cedar Engine    │
│  (per-agent)        (unified)      (policy eval)    │
│                                       │              │
│                                       ▼              │
│                               Decision Router        │
│                               + Audit Logger         │
│                                       │              │
│                                       ▼              │
│                              Response Formatter      │
│                              (per-agent)             │
└──────────────────────┬───────────────────────────────┘
                       │ stdout (decision JSON) + exit code
                       ▼
┌──────────────────────────────────────────────────────┐
│                    AGENT                             │
│  exit 0 → execute    exit 1 → block                  │
│  exit 2 → prompt     exit 3 → error                  │
└──────────────────────────────────────────────────────┘
```

### Adapter Pair Pattern

Each agent speaks a different language. The `--agent` flag selects a **matched pair** of request adaptor (input) and response formatter (output):

| Agent | Normalizer | Formatter |
|---|---|---|
| `copilot-cli` | Maps tool names (`edit`, `powershell`, `web_fetch`) to Cedar actions | Returns `{"allowed": bool, "message": "...", "should_prompt_user": bool}` |
| `generic` | Expects explicit `--principal`/`--action`/`--resource` args | Returns raw `AuthzDecision` JSON |

### Cedar Entity Model

| Entity Type | Examples | Key Attributes |
|---|---|---|
| `Agent` | `CopilotCLI`, `Cursor`, `Codex` | `trust_level`, `session_id`, `user` |
| `File` | `/src/main.rs`, `.env` | `extension`, `directory`, `is_protected`, `is_destructive` |
| `Command` | `cargo build`, `rm -rf /` | `binary`, `args`, `is_destructive` |
| `Url` | `https://api.example.com` | `domain`, `is_destructive` |
| `GitRef` | `main`, `release/v1` | `is_protected`, `is_destructive`, `is_elevated`, `remote` |

### Project Structure

A Cargo workspace with 6 crates:

| Crate | Role |
|---|---|
| `crates/engine/` | Core: `PolicyEngine` trait, `CedarEngine`, entity types, policy loading |
| `crates/request-adaptor/` | Input: converts agent-specific payloads → unified `AuthzRequest` |
| `crates/response-formatter/` | Output: converts `AuthzDecision` → agent-specific response |
| `crates/audit/` | Structured JSON-line audit logging |
| `crates/policy-defaults/` | Embeds default Cedar policies at compile time |
| `crates/cli/` | Binary with `check`, `validate`, `init`, `audit` subcommands |

### Adding a New Agent

1. **Request Adaptor:** Create `crates/request-adaptor/src/<agent>.rs` implementing `AgentNormalizer` — maps the agent's tool call format to `AuthzRequest`
2. **Response Formatter:** Create `crates/response-formatter/src/<agent>.rs` implementing `ResponseFormatter` — maps `AuthzDecision` to the agent's expected response format
3. **Register:** Add match arms in `get_normalizer()` and `get_formatter()` in each crate's `lib.rs`
4. **Use:** `duramen check --agent <name>` selects the matched pair

### Extending Authorization Logic

To add new security concerns without modifying existing code:

1. **Resource Enricher** — implement `ResourceEnricher` in `crates/request-adaptor/src/enrichers/` to add attributes (e.g., `is_protected`, `domain`)
2. **Action Classifier** — implement `ActionClassifier` in `crates/request-adaptor/src/classifiers/` to reclassify actions (e.g., `shell:pip` → `package:install`)
3. Register in `default_pipeline()` in `copilot_cli.rs`

## Design Documentation

- [Design Specification](docs/specs/2026-03-30-duramen-design.md) — full architecture, entity model, request flow diagrams
- [Implementation Plan](docs/plans/2026-03-30-duramen.md) — task-by-task build plan
- [Benchmark Reports](docs/benchmark/) — sub-millisecond authorization performance analysis
- [Test Coverage](docs/test-coverage.md) — 219 tests across all crates
- [Adding Command Handlers](docs/adding-command-handlers.md) — guide for adding per-binary parsing logic
- [Scenarios & Use Cases](docs/scenarios.md) — protecting against unintended agent behavior for individuals, teams, and organizations
- [Agent Permission Integration](docs/agent-permission-integration.md) — how Duramen works alongside agent built-in controls like --yolo
- [Adding a New Agent](docs/adding-a-new-agent.md) — step-by-step guide for supporting a new AI coding agent
- [Copilot CLI Cedar Mapping](docs/copilot-cli-cedar-mapping.md) — how tool calls map to Cedar entities

## Contributing

Contributions are welcome! Here's how to get started:

1. **Build:** `cargo build`
2. **Test:** `cargo test` (219 tests)
3. **Bench:** `cargo bench`

### Extension points

- **New agent support** — implement `AgentNormalizer` + `ResponseFormatter` ([guide](docs/adding-a-new-agent.md))
- **New command handler** — implement `CommandHandler` for a specific binary ([guide](docs/adding-command-handlers.md))
- **New security enricher** — implement `ResourceEnricher` or `ActionClassifier` in the enrichment pipeline
- **New Cedar policies** — add `.cedar` files to `policies/examples/`

See [.github/copilot-instructions.md](.github/copilot-instructions.md) for architecture and conventions.

## License

MIT
