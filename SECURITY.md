# Security Policy

## Reporting a Vulnerability

Duramen is a security tool — we take vulnerabilities seriously.

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, report them via email to the maintainers. Include:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Current |

## Security Design

Duramen follows these security principles:

- **Fail-closed**: If the authorization system fails (malformed input, missing binary, policy error), the default is deny
- **Deny-overrides**: Cedar `forbid` rules always win over `permit` rules, regardless of policy source
- **Hook integrity**: preToolUse hooks fire even when agents run with `--yolo` or `--allow-all-tools`
- **JSON safety**: Hook scripts use `jq`/`ConvertTo-Json` to prevent injection via policy names
- **Chained command detection**: `&&`/`||`/`;` chains are split and each sub-command is evaluated independently

## Known Limitations

- Pipe operators (`|`) within shell commands are not split — they're treated as a single command
- The `is_protected` attribute for files is heuristic-based (pattern matching on paths like `.env`, `.ssh/`)
- Plugin normalizers (external executables) are not yet implemented
- Audit log is append-only with no built-in rotation or encryption
