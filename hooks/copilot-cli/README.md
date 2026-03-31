# Copilot CLI Hook Integration

This folder contains everything needed to integrate Duramen with GitHub Copilot CLI's `preToolUse` hook system.

## Files

| File | Purpose |
|------|---------|
| `duramen.json` | Hook config — Copilot CLI auto-discovers this in `.github/hooks/` |
| `duramen-hook.sh` | Bash hook script (macOS/Linux) |
| `duramen-hook.ps1` | PowerShell hook script (Windows) |
| `install.sh` | Install script — copies hook files to a target repo |
| `install.ps1` | Install script (PowerShell) |

## Quick Install

### Prerequisites

1. Build Duramen: `cargo build --release`
2. Add `target/release/duramen` to your PATH

### Install to a repo

```bash
# From the Duramen repo root
./hooks/copilot-cli/install.sh /path/to/your/repo

# Or on Windows (PowerShell)
.\hooks\copilot-cli\install.ps1 -RepoPath C:\path\to\your\repo
```

This copies `duramen.json`, `duramen-hook.sh`, and `duramen-hook.ps1` into the target repo's `.github/hooks/` directory. Copilot CLI auto-discovers hooks in that location.

### Manual Install

```bash
mkdir -p /path/to/your/repo/.github/hooks
cp hooks/copilot-cli/duramen.json /path/to/your/repo/.github/hooks/
cp hooks/copilot-cli/duramen-hook.sh /path/to/your/repo/.github/hooks/
cp hooks/copilot-cli/duramen-hook.ps1 /path/to/your/repo/.github/hooks/
```

## How It Works

```
Agent plans tool call → Copilot CLI fires preToolUse hook
    → duramen-hook.{sh,ps1} reads tool payload from stdin
    → pipes through: duramen check --agent copilot-cli
    → returns {"permissionDecision": "allow|deny|ask"} to Copilot CLI
```

### Exit Codes

| Code | Meaning | Hook response |
|------|---------|---------------|
| 0 | Allow or Audit | `{"permissionDecision": "allow"}` |
| 1 | Deny | `{"permissionDecision": "deny", "permissionDecisionReason": "..."}` |
| 2 | Require approval | `{"permissionDecision": "ask", "permissionDecisionReason": "... (approval required)"}` |
| 3 | System error | `{"permissionDecision": "deny", "permissionDecisionReason": "Duramen system error (fail-closed)"}` |

## Uninstall

Remove the hook files from the target repo:

```bash
rm /path/to/your/repo/.github/hooks/duramen.json
rm /path/to/your/repo/.github/hooks/duramen-hook.sh
rm /path/to/your/repo/.github/hooks/duramen-hook.ps1
```
