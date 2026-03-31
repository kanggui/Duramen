# Duramen Scenarios: Protecting Against Unintended Agent Behavior

## The Risk

AI coding agents are powerful — they edit files, run shell commands, push code, and make network requests. But they operate on probability, not certainty. A well-intentioned prompt can lead to:

- `git push --force origin main` — rewriting shared history
- `rm -rf src/` — deleting source files during cleanup
- Editing `.env` or `secrets.yaml` — exposing credentials
- `git reset --hard HEAD~5` — discarding uncommitted work
- `pip install malicious-package` — introducing supply chain risk
- `curl` exfiltrating data to external endpoints

Duramen sits between the agent and the action, evaluating every tool call against Cedar policies before it executes.

---

## Scenario 1: Individual Developer — "Don't Let the Agent Break My Repo"

### The situation
You use Copilot CLI for daily coding. It's great at writing code, but sometimes it runs destructive commands you didn't intend — force pushes, hard resets, or deleting files it thinks are unnecessary.

### Setup (2 minutes)

```bash
# Build and install
cargo build --release
export PATH="$PATH:$(pwd)/target/release"

# Install hooks in your repo
./hooks/copilot-cli/install.sh ~/my-project
```

### What happens now

You ask Copilot: *"Clean up the old feature branches and push the changes"*

**Without Duramen:**
```
✓ git branch -D feature-old
✓ git push --force origin main
  └ History rewritten. Your teammates' work is gone.
```

**With Duramen (default policies):**
```
✓ git branch -D feature-old
  └ Denied: Blocks destructive git operations like branch -D

✓ git push --force origin main
  └ Denied: Blocks git force-push operations
```

The agent is told the commands were blocked and explains the policy to you. You can then decide to run them manually if you truly intend to.

### Customizing for your workflow

Want to allow branch deletion but still block force-push? Add a policy to `.authz/`:

```cedar
// .authz/allow-branch-cleanup.cedar
@id("allow-branch-delete")
@name("Allow branch deletion")
@description("Permits deleting local git branches")
permit(
    principal,
    action == Action::"git::destructive",
    resource
) when {
    !(resource has remote)
};
```

---

## Scenario 2: Team Lead — "Protect the Main Branch"

### The situation
Your team of 5 developers all use AI coding agents. You want to ensure no agent can push directly to `main` or `release/*` branches without human review, regardless of which developer is running the agent.

### Setup

1. Add policies to the shared repo:

```cedar
// .authz/protect-main.cedar
@id("protect-main-branch")
@name("Protect main branch")
@description("Requires human approval before any git operations on main or release branches")
@advice("require-approval")
permit(
    principal,
    action in [
        Action::"git:push",
        Action::"git:commit",
        Action::"git::write",
        Action::"git::network"
    ],
    resource
) when {
    resource has is_protected && resource.is_protected == true
};
```

2. Commit `.authz/` to the repo — every developer who clones gets the policies automatically.

3. Each developer installs the hook once:
```bash
./hooks/copilot-cli/install.sh .
```

### What happens now

Developer asks Copilot: *"Push my changes to main"*

```
✗ Push to main (shell)
  │ git push origin main
  └ Requires approval: Requires human approval before any git operations
    on main or release branches
```

The agent pauses and asks the developer to confirm. If they approve, the push proceeds. If not, it's blocked.

### Audit trail

Every blocked or approved action is logged:

```bash
duramen audit --since 7d --decision require-approval
```

```json
[
  {
    "timestamp": "2026-03-31T14:30:00Z",
    "principal": {"type": "Agent", "id": "CopilotCLI"},
    "action": "git::network",
    "resource": {"type": "GitRef", "path": "main"},
    "decision": "require-approval",
    "policy_name": "Protect main branch",
    "raw_command": {"toolName": "bash", "toolArgs": "{\"command\":\"git push origin main\"}"}
  }
]
```

---

## Scenario 3: Security Team — "Enforce Organization-Wide Policies"

### The situation
Your organization has 50+ developers using various AI agents. The security team needs to enforce baseline policies that individual developers cannot override:

- No force-pushing anywhere
- No installing packages without review
- No editing secrets files
- No network requests to unapproved domains
- All file edits audited

### Setup: Centralized policy distribution

Duramen loads policies in order: **repo `.authz/`** + **user `~/.config/duramen/policies`** + **compiled-in defaults**. Cedar's deny-overrides semantics mean a `forbid` at any level blocks the action regardless of `permit` rules elsewhere.

**Option A: Repo-level enforcement**

Add `.authz/` policies to every repo via a template or CI check:

```bash
# In your repo template or CI setup script
duramen init  # Creates .authz/ with safe defaults
cp /org/security/policies/*.cedar .authz/
```

**Option B: User-level enforcement**

Distribute policies to every developer's machine:

```bash
# Run once per developer (or via MDM/provisioning)
mkdir -p ~/.config/duramen/policies
cp /org/security/policies/*.cedar ~/.config/duramen/policies/
```

User-level policies apply to ALL repos the developer works in.

### Organization policies

```cedar
// org-security/no-force-push.cedar
@id("org-no-force-push")
@name("Organization: No force push")
@description("Force pushing is prohibited across all repositories")
forbid(
    principal,
    action == Action::"git:force-push",
    resource
);

// org-security/no-unreviewed-packages.cedar
@id("org-review-packages")
@name("Organization: Review package installations")
@description("Package installations require human approval")
@advice("require-approval")
permit(
    principal,
    action == Action::"package:install",
    resource
);

// org-security/protect-secrets.cedar
@id("org-protect-secrets")
@name("Organization: Protect secrets files")
@description("Blocks agent edits to secrets, keys, and credential files")
forbid(
    principal,
    action in [Action::"file:edit", Action::"file:delete"],
    resource
) when {
    resource has is_protected && resource.is_protected == true
};

// org-security/audit-all-writes.cedar
@id("org-audit-writes")
@name("Organization: Audit all file writes")
@description("All file modifications are logged for compliance")
@advice("audit")
permit(
    principal,
    action in [Action::"file:create", Action::"file:edit"],
    resource
);
```

### Key property: developers can't override forbids

Even if a developer adds `permit(principal, action, resource)` to their repo's `.authz/`, Cedar's **deny-overrides** semantics ensure the organization's `forbid` rules always win. This makes centralized enforcement reliable.

### Compliance dashboard

Query the audit log across teams:

```bash
# All denials this week
duramen audit --since 7d --decision deny

# All package install attempts
duramen audit --since 30d | jq '.[] | select(.action == "package:install")'

# Actions by a specific agent
duramen audit --since 7d --principal CopilotCLI
```

---

## Scenario 4: Open Source Maintainer — "Safe AI-Assisted Contributions"

### The situation
You maintain a popular open source project. Contributors use AI agents to submit PRs. You want to ensure agents can read code and run tests, but can't modify CI configuration, delete files, or push directly.

### Policies

```cedar
// .authz/contributor-safe.cedar

// Allow read-only operations freely
@id("contributor-allow-reads")
@name("Allow read-only operations")
permit(
    principal,
    action in [
        Action::"file:read",
        Action::"directory:list",
        Action::"git::read"
    ],
    resource
);

// Allow file edits with audit trail
@id("contributor-audit-edits")
@name("Audit file edits")
@advice("audit")
permit(
    principal,
    action in [Action::"file:create", Action::"file:edit"],
    resource
) when {
    !(resource has is_protected && resource.is_protected == true)
};

// Block CI config changes
@id("contributor-protect-ci")
@name("Protect CI configuration")
@description("Prevents agent modification of CI/CD pipeline files")
forbid(
    principal,
    action in [Action::"file:edit", Action::"file:create", Action::"file:delete"],
    resource
) when {
    resource has directory && resource.directory == ".github/workflows"
};

// Block all deletes
@id("contributor-no-delete")
@name("Block file deletion")
@description("Agents cannot delete files in this repository")
forbid(
    principal,
    action == Action::"file:delete",
    resource
);

// Block all pushes
@id("contributor-no-push")
@name("Block direct push")
@description("Agents cannot push directly — use PRs instead")
forbid(
    principal,
    action in [Action::"git:push", Action::"git::network"],
    resource
);
```

### Result

Contributors' agents can freely read code, run tests, and edit source files. But they can't:
- Modify `.github/workflows/` (CI)
- Delete any files
- Push directly (must create PRs)
- Force-push or reset

All edits are audit-logged for review.

---

## Scenario 5: Compliance Officer — "Prove Our AI Agents Are Governed"

### The situation
Your organization must demonstrate to auditors that AI coding agents operate within defined guardrails — what actions are allowed, what's blocked, and a complete audit trail.

### Evidence

**1. Policy-as-code (auditable)**

All policies are Cedar files checked into version control:
```bash
ls .authz/
# schema.cedarschema
# allow-default.cedar
# deny-destructive.cedar
# audit-file-writes.cedar
# org-protect-secrets.cedar
```

Each policy has an `@id`, `@name`, and `@description` — human-readable documentation embedded in the policy itself.

**2. Audit log (tamper-evident)**

Every non-trivial decision is logged as structured JSON:
```bash
duramen audit --since 30d --limit 1000 > monthly-audit-export.json
```

Each entry includes: timestamp, agent identity, action, resource, decision, policy that determined the outcome, and the original tool invocation.

**3. Validation (testable)**

Policies are schema-validated before deployment:
```bash
duramen validate --policy-dir .authz/
# {"status":"valid","policy_count":5}
```

**4. Fail-closed (verifiable)**

If Duramen itself fails (malformed input, missing binary, policy error), the default is **deny**. The system never fails open.

---

## Summary: Policy Patterns

| Goal | Policy pattern | Cedar mechanism |
|------|---------------|----------------|
| Block a specific action | `forbid(principal, action == Action::"...", resource)` | Deny-overrides |
| Allow with audit trail | `@advice("audit") permit(...)` | Advice annotation |
| Require human approval | `@advice("require-approval") permit(...)` | Advice annotation |
| Protect specific files | `forbid(...) when { resource has is_protected && resource.is_protected == true }` | Attribute-based |
| Restrict by file path | `forbid(...) when { resource has directory && resource.directory == "..." }` | Attribute-based |
| Restrict by agent | `forbid(...) unless { principal == Agent::"CopilotCLI" }` | Principal-based |
| Allow everything (dev) | `permit(principal, action, resource)` | Catch-all permit |

## Getting Started

```bash
cargo build --release
./target/release/duramen init
./hooks/copilot-cli/install.sh .
```

See [README.md](../README.md) for full setup instructions.
