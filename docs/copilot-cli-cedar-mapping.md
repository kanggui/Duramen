# Copilot CLI to Cedar Mapping Reference

This document describes how Copilot CLI tool calls are normalized into Cedar authorization requests by the `CopilotCliNormalizer`.

## Overview

When Copilot CLI fires a `preToolUse` hook, it sends a JSON payload describing the tool call. Duramen normalizes this into one or more Cedar authorization requests with four components:

```
Copilot CLI Payload          Cedar Authorization Request
─────────────────           ──────────────────────────────
tool name            ──→    Principal + Action + Resource Type
tool args            ──→    Resource ID + Attributes
working_directory    ──→    Context
```

The Cedar engine then evaluates each request as:

```
Agent::"CopilotCLI"  performs  Action::"<action>"  on  <Type>::"<id>"
```

**Default posture:** Duramen ships with `allow-default.cedar`, which **allows all operations by default**. Specific `forbid`, `@advice("audit")`, and `@advice("require-approval")` policies override the default to deny, audit, or gate particular actions.

---

## Principal Mapping

All Copilot CLI tool calls produce the same principal:

| Copilot CLI | Cedar Principal |
|---|---|
| Any tool call | `Agent::"CopilotCLI"` |

The principal is hardcoded because the normalizer knows the source agent. Other normalizers (e.g., for Cursor) would produce `Agent::"Cursor"`, etc.

---

## Tool → Action + Resource Type Mapping

Each Copilot CLI tool name maps to a Cedar action and resource type:

| Copilot CLI Tool | Cedar Action | Cedar Resource Type | Resource ID Source |
|---|---|---|---|
| `view` | `Action::"file:read"` | `File` | `args.path` |
| `edit` | `Action::"file:edit"` | `File` | `args.path` |
| `create` | `Action::"file:create"` | `File` | `args.path` |
| `grep` | `Action::"file:read"` | `File` | `args.path` |
| `glob` | `Action::"file:read"` | `File` | `args.path` |
| `powershell` | `Action::"shell:<binary>"` | `File` | Resolved from args/cwd |
| `bash` | `Action::"shell:<binary>"` | `File` | Resolved from args/cwd |
| `web_fetch` | `Action::"network:fetch"` | `Url` | `args.url` |
| *(any other)* | `Action::"tool:unknown"` | *(varies)* | `"unknown"` |

**Note:** `grep` and `glob` are treated as read operations because they search/list files without modifying them.

### Shell command resource resolution

For `powershell` and `bash` tool calls, the normalizer parses the command string to determine the binary and the target resource:

1. **Prefixes are stripped:** `sudo`, `env`, `nohup`, `nice`, `time` are removed. `sudo` sets `is_elevated: true`.
2. **The binary name determines the action:** `cargo build` → `Action::"shell:cargo"`, `rm -rf dist` → `Action::"shell:rm"`.
3. **The resource is a `File`, not a `Command`:** The `DefaultCommandHandler` resolves the last non-flag argument as a file path (joined with `cwd` if relative). If the target looks like a URL (`http://` or `https://`), the resource is a `Url` instead.
4. **If no non-flag arguments exist**, the resource defaults to the working directory.

### Git command special handling

When `powershell` or `bash` tool calls contain **git commands**, the normalizer detects the `git` binary and routes to the `GitCommandHandler`. Git commands produce `git::*` actions on `GitRef` resources:

| Shell Command | Cedar Action | Cedar Resource Type | Resource ID |
|---|---|---|---|
| `git status`, `git log`, `git diff`, `git show`, `git remote` | `Action::"git::read"` | `GitRef` | `"HEAD"` |
| `git branch` (no delete), `git tag` (no delete) | `Action::"git::read"` | `GitRef` | `"HEAD"` |
| `git add`, `git commit`, `git merge`, `git rebase`, `git checkout`, `git switch`, `git stash` | `Action::"git::write"` | `GitRef` | `"HEAD"` or ref arg |
| `git reset` (no `--hard`) | `Action::"git::write"` | `GitRef` | ref arg or `"HEAD"` |
| `git tag -d` | `Action::"git::write"` | `GitRef` | tag name |
| `git fetch`, `git pull`, `git clone` | `Action::"git::network"` | `GitRef` | ref arg or `"HEAD"` |
| `git push` (no `--force`) | `Action::"git::network"` | `GitRef` | ref arg or `"HEAD"` |
| `git push --force` / `-f` | `Action::"git::destructive"` | `GitRef` | ref arg |
| `git reset --hard` | `Action::"git::destructive"` | `GitRef` | ref arg or `"HEAD"` |
| `git branch -D` / `-d` | `Action::"git::destructive"` | `GitRef` | branch name |
| `git clean -fd` / `-f` | `Action::"git::destructive"` | `GitRef` | `"HEAD"` |

Git resources include attributes: `is_destructive` (true for destructive actions), `remote` (for push/pull/fetch), and `is_elevated` (true if prefixed with `sudo`).

Unknown git subcommands default to `git::write`.

---

## Chained Commands

Shell commands containing `&&`, `||`, or `;` operators are split into multiple sub-commands. Each sub-command produces its own `AuthzRequest`, and **each is evaluated independently** by the Cedar engine.

**Example:** `cargo build && cargo test` produces two requests:

1. `Action::"shell:cargo"` on `File::"/project/build"` (from `cargo build`)
2. `Action::"shell:cargo"` on `File::"/project/test"` (from `cargo test`)

If **any** sub-command is denied, the entire chained command is blocked. All sub-commands must be allowed for the tool call to proceed.

---

## Concrete Examples

### File Edit

**Copilot CLI payload:**
```json
{
  "tool": "edit",
  "args": {
    "path": "/src/main.rs",
    "old_str": "fn old()",
    "new_str": "fn new()"
  }
}
```

**Cedar request:**
```
principal:  Agent::"CopilotCLI"
action:     Action::"file:edit"
resource:   File::"/src/main.rs"
              attributes: { is_protected: false }
context:    { tool_name: "edit", file_patterns_affected: ["/src/main.rs"] }
```

**Matched policy:** `audit-file-writes.cedar` (permit with `@advice("audit")`) → Decision: **audit** (exit 0, logged)

---

### Shell Command (safe)

**Copilot CLI payload:**
```json
{
  "tool": "powershell",
  "args": {
    "command": "cargo test --workspace"
  },
  "cwd": "/project"
}
```

**Cedar request:**
```
principal:  Agent::"CopilotCLI"
action:     Action::"shell:cargo"
resource:   File::"/project/test"
              attributes: { is_destructive: false, is_elevated: false }
context:    { tool_name: "powershell", working_directory: "/project" }
```

**Matched policy:** `allow-default.cedar` (permit all) → Decision: **allow** (exit 0)

---

### Shell Command (destructive)

**Copilot CLI payload:**
```json
{
  "tool": "bash",
  "args": {
    "command": "sudo rm -rf /"
  }
}
```

**Cedar request:**
```
principal:  Agent::"CopilotCLI"
action:     Action::"shell:rm"
resource:   File::"/"
              attributes: { is_destructive: true, is_elevated: true }
context:    { tool_name: "bash" }
```

**Matched policy:** `deny-destructive.cedar` (`forbid ... when { resource has is_destructive && resource.is_destructive == true }`) → Decision: **deny** (exit 1)

The `is_destructive` flag is set by substring-matching the command against `DESTRUCTIVE_PATTERNS`. The `is_elevated` flag is set because `sudo` was stripped as a prefix.

---

### File Read

**Copilot CLI payload:**
```json
{
  "tool": "view",
  "args": {
    "path": "/src/lib.rs"
  }
}
```

**Cedar request:**
```
principal:  Agent::"CopilotCLI"
action:     Action::"file:read"
resource:   File::"/src/lib.rs"
              attributes: { is_protected: false }
context:    { tool_name: "view", file_patterns_affected: ["/src/lib.rs"] }
```

**Matched policy:** `allow-default.cedar` → Decision: **allow** (exit 0)

---

### Network Fetch

**Copilot CLI payload:**
```json
{
  "tool": "web_fetch",
  "args": {
    "url": "https://docs.rs/cedar-policy/latest/"
  }
}
```

**Cedar request:**
```
principal:  Agent::"CopilotCLI"
action:     Action::"network:fetch"
resource:   Url::"https://docs.rs/cedar-policy/latest/"
context:    { tool_name: "web_fetch" }
```

**Matched policy:** `allow-default.cedar` → Decision: **allow** (exit 0)

---

### File Creation

**Copilot CLI payload:**
```json
{
  "tool": "create",
  "args": {
    "path": "/src/new_module.rs",
    "file_text": "pub fn hello() {}"
  }
}
```

**Cedar request:**
```
principal:  Agent::"CopilotCLI"
action:     Action::"file:create"
resource:   File::"/src/new_module.rs"
              attributes: { is_protected: false }
context:    { tool_name: "create", file_patterns_affected: ["/src/new_module.rs"] }
```

**Matched policy:** `audit-file-writes.cedar` (permit with `@advice("audit")` when not protected) → Decision: **audit** (exit 0, logged)

---

### Search (grep)

**Copilot CLI payload:**
```json
{
  "tool": "grep",
  "args": {
    "pattern": "TODO",
    "path": "/src"
  }
}
```

**Cedar request:**
```
principal:  Agent::"CopilotCLI"
action:     Action::"file:read"
resource:   File::"/src"
              attributes: { is_protected: false }
context:    { tool_name: "grep", file_patterns_affected: ["/src"] }
```

**Matched policy:** `allow-default.cedar` → Decision: **allow** (exit 0)

---

### Git Push (safe)

**Copilot CLI payload:**
```json
{
  "tool": "bash",
  "args": {
    "command": "git push origin feature-branch"
  }
}
```

**Cedar request:**
```
principal:  Agent::"CopilotCLI"
action:     Action::"git::network"
resource:   GitRef::"feature-branch"
              attributes: { is_destructive: false, remote: "origin", is_elevated: false }
context:    { tool_name: "bash" }
```

**Matched policy:** `allow-default.cedar` → Decision: **allow** (exit 0)

---

### Git Force Push (destructive)

**Copilot CLI payload:**
```json
{
  "tool": "bash",
  "args": {
    "command": "git push --force origin main"
  }
}
```

**Cedar request:**
```
principal:  Agent::"CopilotCLI"
action:     Action::"git::destructive"
resource:   GitRef::"main"
              attributes: { is_destructive: true, remote: "origin", is_elevated: false }
context:    { tool_name: "bash" }
```

**Matched policy:** `deny-destructive.cedar` (`forbid ... action == Action::"git::destructive"`) → Decision: **deny** (exit 1)

---

## Destructive Command Detection

Shell commands (`powershell`, `bash`) are checked for destructive patterns by the normalizer. The `is_destructive` flag is set on `resource.attributes` and flows through to Cedar as an entity attribute.

**Data flow:**
```
Copilot CLI payload: {"tool":"bash","args":{"command":"sudo rm -rf /"}}
    ↓ CopilotCliNormalizer.parse_single_command()
    ↓ Strips "sudo" prefix → is_elevated = true
    ↓ binary = "rm", action = "shell:rm"
    ↓ DefaultCommandHandler resolves resource → File::"/"
    ↓ is_destructive("sudo rm -rf /") → true (matches "rm -rf" and "sudo ")
AuthzRequest {
    action: "shell:rm",
    resource: File::"/" { is_destructive: true, is_elevated: true },
    ...
}
    ↓ CedarEngine evaluation
deny-destructive.cedar: resource has is_destructive && resource.is_destructive == true  →  DENY
```

| Pattern | Example Command | Detected? |
|---|---|---|
| `rm -rf` | `rm -rf /tmp/build` | ✅ |
| `rm -r` | `rm -r old_dir/` | ✅ |
| `sudo ` | `sudo apt install nginx` | ✅ |
| `git push --force` | `git push --force origin main` | ✅ |
| `git push -f` | `git push -f` | ✅ |
| `mkfs` | `mkfs.ext4 /dev/sda1` | ✅ |
| `dd if=` | `dd if=/dev/zero of=/dev/sda` | ✅ |
| `format ` | `format C:` | ✅ |
| `> /dev/` | `echo x > /dev/sda` | ✅ |
| `chmod 777` | `chmod 777 /var/www` | ✅ |
| `:(){ :\|:& };:` | Fork bomb | ✅ |
| `cargo build` | `cargo build --release` | ❌ (safe) |
| `npm install` | `npm install express` | ❌ (safe) |
| `git push` | `git push origin feature` | ❌ (safe, no --force) |

Detection is case-insensitive substring matching. The list is defined in `crates/request-adaptor/src/copilot_cli.rs::DESTRUCTIVE_PATTERNS`.

**Note:** For git commands routed through the `GitCommandHandler`, destructiveness is determined by subcommand and flags (e.g., `--force`, `--hard`, `-D`), not by the `DESTRUCTIVE_PATTERNS` list. The pattern list is used for the `is_destructive` attribute on the resource; the `GitCommandHandler` separately classifies the action as `git::destructive`.

---

## Cedar Schema Reference

The full entity model is defined in `policies/default/schema.cedarschema`:

### Entity Types

```
Agent    → { trust_level?, session_id?, user? }
File     → { extension?, directory?, is_protected?, is_destructive? }
Command  → { binary?, args?, is_destructive? }
Url      → { domain?, is_destructive? }
GitRef   → { is_protected?, is_destructive?, is_elevated?, remote? }
```

### Actions

```
file:create, file:read, file:edit, file:delete   → Agent × File
directory:list                                    → Agent × File
shell:execute                                     → Agent × [Command, File]
git:commit, git:push, git:force-push, git:branch  → Agent × GitRef
git:status, git:log, git:diff                     → Agent × GitRef
git::read, git::write, git::network, git::destructive → Agent × GitRef
network:fetch, network:request                    → Agent × Url
tool:unknown                                      → Agent × [Command, File, Url]
```

**Note:** The schema declares `shell:execute` as a general action on `[Command, File]`, but the normalizer emits specific `shell:<binary>` actions (e.g., `shell:cargo`, `shell:rm`). The schema also includes both colon-separated (`git:push`) and double-colon (`git::network`) action styles; the normalizer uses the double-colon variants (`git::read`, `git::write`, `git::network`, `git::destructive`).

### Context Fields

The `AuthzContext` included with every request contains:

| Field | Type | Description |
|---|---|---|
| `tool_name` | `String` | Original Copilot CLI tool name (`"powershell"`, `"edit"`, etc.) |
| `working_directory` | `Option<String>` | Working directory from the hook payload or args |
| `file_patterns_affected` | `Vec<String>` | List of file paths affected (populated for `File` resources) |
| `extra` | `Value` | Reserved for future use |

---

## Default Policy Decision Matrix

Summary of what each default policy does for each tool. The base policy is `allow-default.cedar`, which permits everything not explicitly overridden:

| Copilot CLI Tool | Cedar Action | Default Decision | Policy |
|---|---|---|---|
| `view` | `file:read` | **allow** | `allow-default.cedar` |
| `grep` | `file:read` | **allow** | `allow-default.cedar` |
| `glob` | `file:read` | **allow** | `allow-default.cedar` |
| `edit` | `file:edit` | **audit** | `audit-file-writes.cedar` |
| `create` | `file:create` | **audit** | `audit-file-writes.cedar` |
| `edit` (protected file) | `file:edit` | **allow** | `allow-default.cedar` (audit policy excludes protected) |
| `powershell` / `bash` (safe) | `shell:<binary>` | **allow** | `allow-default.cedar` |
| `powershell` / `bash` (destructive) | `shell:<binary>` | **deny** | `deny-destructive.cedar` |
| `web_fetch` | `network:fetch` | **allow** | `allow-default.cedar` |
| `git status` / `git log` | `git::read` | **allow** | `allow-default.cedar` |
| `git commit` / `git add` | `git::write` | **allow** | `allow-default.cedar` |
| `git push` (safe) | `git::network` | **allow** | `allow-default.cedar` |
| `git push --force` | `git::destructive` | **deny** | `deny-destructive.cedar` |
| `git reset --hard` | `git::destructive` | **deny** | `deny-destructive.cedar` |
| `git push` (protected ref) | `git::network` | **require-approval** | `require-approval-sensitive.cedar` |
| `file:delete` (non-protected) | `file:delete` | **require-approval** | `require-approval-sensitive.cedar` |
| `file:delete` (protected) | `file:delete` | **deny** | `deny-destructive.cedar` |
| *(unknown tool)* | `tool:unknown` | **allow** | `allow-default.cedar` |

### Default Policies

| Policy File | Type | Effect |
|---|---|---|
| `allow-default.cedar` | `permit` | Allows all operations (base layer) |
| `audit-file-writes.cedar` | `permit` + `@advice("audit")` | Audits `file:create` and `file:edit` on non-protected files |
| `deny-destructive.cedar` | `forbid` | Blocks `git:force-push`, `git::destructive`, resources with `is_destructive == true`, and `file:delete` on protected files |
| `require-approval-sensitive.cedar` | `permit` + `@advice("require-approval")` | Requires human approval for git push/commit/network/write on protected refs, and `file:delete` on non-protected files |

**To restrict further**, add `forbid` policies. For example, to block all shell commands:

```cedar
// .authz/deny-all-shell.cedar
forbid(
    principal,
    action == Action::"shell:execute",
    resource
);
```

---

## Extending the Mapping

### Adding a new Copilot CLI tool

If Copilot CLI adds a new tool (e.g., `delete_file`), update the `map_tool()` function in `crates/request-adaptor/src/copilot_cli.rs`:

```rust
fn map_tool(tool: &str) -> (&str, &str) {
    match tool {
        // ... existing mappings ...
        "delete_file" => ("file:delete", "file"),   // ← add here
        _ => ("tool:unknown", "unknown"),
    }
}
```

### Adding a new command handler

To add specialized handling for a binary (e.g., `docker`):

1. Create `crates/request-adaptor/src/commands/docker.rs` implementing `CommandHandler`
2. Register it in `crates/request-adaptor/src/commands/mod.rs` (`get_command_handler()`)
3. The handler controls the action name and resource extraction for that binary

### Adding a new Cedar action

1. Add the action to `policies/default/schema.cedarschema`
2. Map the tool to the new action in `map_tool()` or a command handler
3. Write policy rules for the new action in `.authz/`

### Source code reference

- **Normalizer:** `crates/request-adaptor/src/copilot_cli.rs` — `map_tool()`, `parse_single_command()`, `split_chained_commands()`, `is_destructive()`
- **Command handlers:** `crates/request-adaptor/src/commands/` — `git.rs` (git), `default.rs` (fallback)
- **Entity types:** `crates/engine/src/entities.rs` — `AuthzRequest`, `AuthzResource`, `AuthzContext`
- **Schema:** `policies/default/schema.cedarschema`
- **Default policies:** `policies/default/*.cedar`
