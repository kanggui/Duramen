# Adding a New Agent

This guide walks through adding support for a new AI coding agent to Duramen, using a hypothetical "Cursor" agent as the example.

## Architecture Overview

Duramen uses a **matched pair** pattern — each agent needs:

1. **Request Adaptor** — converts the agent's hook payload into `Vec<AuthzRequest>`
2. **Response Formatter** — converts `AuthzDecision` into the agent's expected response format
3. **Hook scripts** — bridge between the agent's hook system and `duramen check`

```
Agent sends hook payload
    → Hook script reads stdin, pipes to duramen check --agent <name>
    → Request Adaptor normalizes to AuthzRequest(s)
    → Cedar Engine evaluates against policies
    → Response Formatter outputs agent-specific JSON
    → Hook script translates to agent's protocol
```

Everything else (engine, policies, audit, enrichment pipeline) is shared across all agents.

## Step 1: Implement the Request Adaptor

Create `crates/request-adaptor/src/cursor.rs`:

```rust
use crate::traits::{AgentNormalizer, NormalizerError};
use duramen_engine::entities::{
    AgentPrincipal, AuthzAction, AuthzContext, AuthzRequest, AuthzResource, RawHookPayload,
};

pub struct CursorNormalizer;

impl AgentNormalizer for CursorNormalizer {
    fn normalize(&self, raw_input: &RawHookPayload) -> Result<Vec<AuthzRequest>, NormalizerError> {
        // Map the agent's tool names to Cedar actions and resources.
        // raw_input.tool contains the tool name (e.g., "terminal", "file_edit")
        // raw_input.args contains the tool arguments as JSON
        // raw_input.cwd contains the working directory

        let (action, resource) = match raw_input.tool.as_str() {
            "file_edit" => {
                let path = raw_input.args.get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                ("file:edit", AuthzResource::file(path))
            }
            "terminal" => {
                let command = raw_input.args.get("command")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                // Reuse the shell command parsing infrastructure
                // (command handlers, enrichment pipeline, chained command splitting)
                // by calling the shared utilities
                ("shell:execute", AuthzResource::command(command))
            }
            "web_search" => {
                let query = raw_input.args.get("query")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                ("network:fetch", AuthzResource::url(query))
            }
            _ => ("tool:unknown", AuthzResource::command("unknown")),
        };

        Ok(vec![AuthzRequest {
            principal: AgentPrincipal::new("Cursor"),
            action: AuthzAction::new(action),
            resource,
            context: AuthzContext {
                tool_name: raw_input.tool.clone(),
                working_directory: raw_input.cwd.clone(),
                file_patterns_affected: Vec::new(),
                extra: serde_json::Value::Null,
            },
        }])
    }

    fn agent_type(&self) -> &str {
        "cursor"
    }
}
```

### Key decisions

- **Principal name**: Use the agent's identity (e.g., `"Cursor"`) — policies can target specific agents with `principal == Agent::"Cursor"`
- **Tool mapping**: Map the agent's tool names to Cedar actions from the schema (`file:read`, `file:edit`, `shell:execute`, etc.)
- **Shell commands**: For agents with terminal/shell tools, you can reuse the `commands/` handler registry and `split_chained_commands()` from `copilot_cli.rs`
- **Return `Vec`**: Return multiple `AuthzRequest`s if the agent sends chained commands

## Step 2: Implement the Response Formatter

Create `crates/response-formatter/src/cursor.rs`:

```rust
use crate::traits::{FormattedResponse, ResponseFormatter};
use duramen_engine::decision::{AuthzDecision, DecisionTier};
use duramen_engine::entities::AuthzRequest;
use serde::Serialize;

#[derive(Serialize)]
struct CursorResponse {
    // Match whatever JSON format Cursor's hook system expects
    status: String,       // "approved" | "rejected" | "needs_confirmation"
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<String>,
}

pub struct CursorFormatter;

impl ResponseFormatter for CursorFormatter {
    fn format(&self, decision: &AuthzDecision, _request: &AuthzRequest) -> FormattedResponse {
        let (status, exit_code) = match decision.decision {
            DecisionTier::Allow | DecisionTier::Audit => ("approved", 0),
            DecisionTier::RequireApproval => ("needs_confirmation", 2),
            DecisionTier::Deny => ("rejected", 1),
        };

        let response = CursorResponse {
            status: status.to_string(),
            message: decision.reason.clone(),
            policy: decision.policy_name.clone(),
        };

        FormattedResponse {
            stdout: serde_json::to_string(&response)
                .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}")),
            exit_code,
        }
    }

    fn agent_type(&self) -> &str {
        "cursor"
    }
}
```

### Key decisions

- **Response format**: Match the agent's expected JSON structure — check the agent's hook documentation
- **Exit codes**: The CLI uses the exit code from `FormattedResponse`. Most agents use 0=allow, 1=deny, but check your agent's convention.
- **Policy metadata**: Include `policy_name`/`policy_description` if the agent can display them

## Step 3: Register Both

### `crates/request-adaptor/src/lib.rs`

```rust
pub mod cursor;  // ← add

pub fn get_normalizer(agent: &str) -> Result<Box<dyn AgentNormalizer>, NormalizerError> {
    match agent {
        "copilot-cli" => Ok(Box::new(copilot_cli::CopilotCliNormalizer)),
        "cursor" => Ok(Box::new(cursor::CursorNormalizer)),  // ← add
        "generic" | "" => Ok(Box::new(generic::GenericNormalizer)),
        unknown => Err(NormalizerError::InvalidPayload(format!("unknown agent: {unknown}"))),
    }
}
```

### `crates/response-formatter/src/lib.rs`

```rust
pub mod cursor;  // ← add

pub fn get_formatter(agent: &str) -> Result<Box<dyn ResponseFormatter>, String> {
    match agent {
        "copilot-cli" => Ok(Box::new(copilot_cli::CopilotCliFormatter)),
        "cursor" => Ok(Box::new(cursor::CursorFormatter)),  // ← add
        "generic" | "" => Ok(Box::new(generic::GenericFormatter)),
        unknown => Err(format!("unknown agent: {unknown}")),
    }
}
```

## Step 4: Create Hook Scripts

Create `hooks/cursor/` with the agent's hook integration:

```
hooks/cursor/
├── README.md           # Setup instructions for Cursor users
├── duramen.json        # Hook config in Cursor's format
├── duramen-hook.sh     # Bash hook script
├── duramen-hook.ps1    # PowerShell hook script
├── install.sh          # Install script
└── install.ps1         # Install script (Windows)
```

The hook scripts translate between the agent's hook protocol and `duramen check --agent cursor`. The pattern is always:

```bash
#!/bin/bash
INPUT=$(cat)
RESULT=$(echo "$INPUT" | duramen check --agent cursor 2>/dev/null)
EXIT_CODE=$?

case $EXIT_CODE in
  0) echo '{"status":"approved"}' ;;
  1) # Extract reason from duramen output, format for agent
     REASON=$(echo "$RESULT" | jq -r '.message // "Blocked"')
     jq -n --arg r "$REASON" '{"status":"rejected","message":$r}'
     ;;
  *) echo '{"status":"rejected","message":"System error"}' ;;
esac
```

### Key considerations

- **Read the agent's hook docs** to understand the exact JSON format for both input and output
- **Field names matter** — Copilot CLI uses `permissionDecision`/`permissionDecisionReason`, other agents will have different field names
- **stdin handling** — some agents pipe JSON, others pass it as arguments
- **Test with the actual agent** — simulate payloads before deploying

## Step 5: Add Tests

### Normalizer unit tests

```rust
// crates/request-adaptor/src/cursor.rs

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalizes_file_edit() {
        let payload = RawHookPayload {
            tool: "file_edit".to_string(),
            args: json!({ "path": "/src/main.rs" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CursorNormalizer.normalize(&payload).unwrap();
        assert_eq!(reqs[0].action.name, "file:edit");
        assert_eq!(reqs[0].principal.agent_type, "Cursor");
    }
}
```

### E2E CLI test

```rust
// crates/cli/tests/cursor_test.rs

#[test]
fn cursor_file_edit_allowed() {
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args(["check", "--agent", "cursor"])
        .write_stdin(r#"{"tool":"file_edit","args":{"path":"/src/main.rs"}}"#);
    cmd.assert().success();
}
```

### Hook script test (if applicable)

Follow the pattern in `crates/cli/tests/hook_script_test.rs` — pipe payloads through the actual hook script and verify the response format.

## Checklist

- [ ] `crates/request-adaptor/src/<agent>.rs` — normalizer implementation
- [ ] `crates/response-formatter/src/<agent>.rs` — formatter implementation
- [ ] Match arms in `get_normalizer()` and `get_formatter()`
- [ ] `hooks/<agent>/` — hook config, scripts, install script, README
- [ ] Unit tests for normalizer (all tool types)
- [ ] Unit tests for formatter (all decision tiers)
- [ ] E2E CLI tests with `--agent <name>`
- [ ] Hook script tests (if applicable)
- [ ] Update `docs/test-coverage.md` with new test counts
- [ ] Update `README.md` agent table if adding to built-in agents

## Reference: Copilot CLI Implementation

For a complete working example, study these files:
- `crates/request-adaptor/src/copilot_cli.rs` — full normalizer with shell parsing, enrichment pipeline
- `crates/response-formatter/src/copilot_cli.rs` — formatter with all decision tiers
- `hooks/copilot-cli/` — hook scripts, install scripts, README
- `crates/cli/tests/hook_script_test.rs` — hook protocol tests
