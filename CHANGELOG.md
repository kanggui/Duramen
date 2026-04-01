# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-31

### Added
- Core authorization engine with Cedar policy evaluation
- Four decision tiers: allow, audit, require-approval, deny
- Cedar schema with Agent, File, Command, Url, GitRef entity types
- Policy annotation support (@id, @name, @description, @advice)
- Cedar context population (tool_name, working_directory, file_patterns_affected)
- Principal attribute support (trust_level, session_id, user)

- Request adaptor with Copilot CLI and generic normalizers
- Command handler registry: git, rm, default handlers
- Chained command splitting (&&, ||, ;) with per-sub-command evaluation
- Enrichment pipeline: PathSensitivity, FileMetadata, NetworkDomain, Elevation enrichers
- Action classifiers: Destructive, PackageInstall

- Response formatters for Copilot CLI and generic JSON output
- Structured JSON-line audit logging with policy metadata
- Policy defaults compiled into binary at build time

- CLI with check, validate, init, audit subcommands
- Per-sub-command evaluation with worst-wins aggregation
- Schema-aware policy validation (uses local schema if present)
- Audit log querying with --since, --decision, --principal, --limit filters

- Copilot CLI preToolUse hook integration
- Hook scripts with local binary fallback and JSON-safe output
- Install scripts for one-command hook setup
- permissionDecision/permissionDecisionReason/ask protocol support

- 4 default Cedar policies: allow-default, deny-destructive, audit-file-writes, require-approval-sensitive
- 3 example policies: allow-all, deny-network, team-workflow
- Cedar schema with shell:execute, package:install, tool:unknown actions

- 219 tests (unit, integration, E2E, hook script)
- Criterion benchmarks for Cedar evaluation and E2E pipeline
- Windows path sanitization for Cedar UIDs

- Comprehensive documentation: README, scenarios, agent permission integration,
  adding new agents, adding command handlers, Cedar mapping reference
