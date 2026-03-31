# How Duramen Works With Agent Built-in Permissions

AI coding agents like GitHub Copilot CLI have their own permission systems — flags like `--allow-all-tools`, `--yolo`, `--allow-tool`, `--deny-tool`. Duramen doesn't replace these controls; it adds a **policy-as-code layer underneath** that agents can't bypass.

## Two Layers of Defense

```
┌──────────────────────────────────────────────────────────────────┐
│                     Layer 1: AGENT CONTROLS                      │
│                                                                  │
│  Copilot CLI flags: --allow-tool, --deny-tool, --yolo           │
│  Interactive prompts: "Allow this tool? [y/N]"                   │
│  Scope: per-session, per-user, controlled by the developer       │
│                                                                  │
│  ► Developer decides: "I trust this agent to run shell commands" │
└──────────────────────┬───────────────────────────────────────────┘
                       │ Agent approved → fires preToolUse hook
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│                     Layer 2: DURAMEN POLICIES                    │
│                                                                  │
│  Cedar policies: .authz/*.cedar + ~/.config/duramen/policies     │
│  Evaluation: per-tool-call, attribute-aware, fail-closed         │
│  Scope: per-repo or per-org, controlled by team/security         │
│                                                                  │
│  ► Policy decides: "This specific action on this resource is     │
│    allowed/denied/audited regardless of agent settings"          │
└──────────────────────────────────────────────────────────────────┘
```

The critical property: **Layer 2 always runs, even when Layer 1 is fully permissive.** A developer using `--yolo` skips the agent's own prompts, but Duramen's `preToolUse` hook still fires and evaluates every tool call against Cedar policies.

## How They Interact

### Agent allows + Duramen allows → **Executes**

The normal case. Both layers agree the action is safe.

```
Developer: "Run cargo build"
  → Agent: allowed (--allow-tool or prompted)
  → Duramen: allowed (catch-all permit)
  → Result: ✅ cargo build runs
```

### Agent allows + Duramen denies → **Blocked**

The agent thinks it's fine, but Duramen's policy says no. This is the key security value — even `--yolo` can't override a Duramen `forbid`.

```
Developer (using --yolo): "Force push to main"
  → Agent: allowed (--yolo skips all prompts)
  → Duramen: DENIED (deny-destructive forbids git:force-push)
  → Result: ❌ Blocked with policy explanation
```

### Agent denies + Duramen allows → **Blocked by agent**

The agent's own controls block it before Duramen is even consulted. Duramen's hook never fires.

```
Developer: "Run rm -rf /" (agent has --deny-tool='shell(rm:*)')
  → Agent: denied (--deny-tool matched)
  → Duramen: never consulted (hook doesn't fire)
  → Result: ❌ Blocked by agent
```

### Agent prompts + Duramen requires approval → **Double prompt**

Both layers independently ask for confirmation. This is redundant but safe.

```
Developer: "Push to main"
  → Agent: prompts "Allow shell tool? [y/N]"
  → Developer approves
  → Duramen: requires-approval (protected branch policy)
  → Agent shows: "Requires approval: [policy name]"
  → Result: ⏸️ Developer prompted again by Duramen
```

## Common Configurations

### "I trust the agent, protect me from mistakes"

```bash
# Agent side: permissive
copilot-cli --yolo

# Duramen side: block destructive operations
# (default policies already do this)
duramen init
```

The agent runs freely, but Duramen catches `rm -rf`, `git push --force`, `git reset --hard`, etc. Best of both worlds — speed with guardrails.

### "Audit everything the agent does"

```bash
# Agent side: your choice
copilot-cli --allow-all-tools

# Duramen side: audit all file writes
# (default audit-file-writes.cedar already does this)
```

Every file edit is logged to `~/.duramen/audit.log` with full context — what tool, what file, what the agent was trying to do. Query with:

```bash
duramen audit --since 24h --decision audit
```

### "Lock down for the team"

```bash
# Agent side: each developer's choice (can't enforce)
copilot-cli  # some use --yolo, some don't

# Duramen side: enforced via .authz/ in repo
# .authz/org-policy.cedar committed to repo
forbid(principal, action == Action::"git:force-push", resource);
forbid(principal, action == Action::"file:delete", resource)
  when { resource has is_protected && resource.is_protected == true };
```

Even developers using `--yolo` hit the Duramen guardrails. The policies are in the repo — every clone gets them. And Cedar's deny-overrides means no local policy can `permit` what the org `forbid`s.

## Copilot CLI Permission Flags Reference

| Flag | What it does | Duramen interaction |
|------|-------------|---------------------|
| `--allow-all-tools` | Skips agent tool approval prompts | Duramen hook still fires |
| `--yolo` / `--allow-all` | Skips ALL agent prompts (tools, paths, URLs) | Duramen hook still fires |
| `--allow-tool='shell(git:*)'` | Allows specific tool patterns | Duramen evaluates independently |
| `--deny-tool='shell(rm:*)'` | Blocks specific tool patterns | Tool blocked before Duramen sees it |
| `--available-tools` | Limits which tools the AI can see | Duramen only sees tools the AI attempts |
| `--excluded-tools` | Hides tools from the AI model | Tool never attempted, Duramen not involved |

### Key takeaway

Agent flags control **what the AI model can attempt**. Duramen controls **what actually executes**. They operate at different points in the pipeline:

```
AI decides to use tool
  → Agent flags: should I even try? (--deny-tool, --excluded-tools)
  → Agent prompts: does the user approve? (--allow-tool, interactive)
  → preToolUse hook: does Duramen policy allow it? (Cedar evaluation)
  → Tool executes (only if all three pass)
```

## When Duramen Adds Value Over Agent Controls

| Need | Agent controls | Duramen adds |
|------|---------------|-------------|
| "Don't force-push" | `--deny-tool='shell(git push --force:*)'` — fragile pattern matching | Cedar `forbid` on `git:force-push` action — semantic, not string-based |
| "Protect .env files" | No built-in mechanism | Auto-detects `.env`, marks `is_protected`, policies block edits |
| "Audit file changes" | No built-in audit log | Every non-trivial decision logged with full context |
| "Team-wide rules" | Each developer sets their own flags | `.authz/` policies committed to repo, enforced for everyone |
| "Chained command safety" | `git log && git reset --hard` — agent sees one command | Duramen splits and evaluates each sub-command independently |
| "Policy-as-code" | CLI flags are imperative, ephemeral | Cedar policies are declarative, versioned, reviewable |
| "Compliance evidence" | None | Structured audit log + schema validation + named policies |

## Summary

Duramen is not a replacement for agent-level controls. It's a **complementary layer** that provides:

1. **Persistence** — policies survive across sessions (agent flags don't)
2. **Centralization** — team/org policies that individuals can't override
3. **Semantics** — action + resource + attribute evaluation (not string pattern matching)
4. **Auditability** — structured log of every decision with policy traceability
5. **Fail-closed guarantee** — even if `--yolo` is on, destructive operations are blocked
