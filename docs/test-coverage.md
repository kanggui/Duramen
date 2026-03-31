# Test Coverage

**Total: 219 tests** across 6 crates — unit tests, integration tests, hook script tests, and end-to-end pipeline tests.

## Summary by Crate

| Crate | Tests | Coverage Areas |
|-------|------:|----------------|
| `duramen-engine` | 54 | Policy evaluation, decision tiers, entity model, policy loading, schema validation, annotation extraction |
| `duramen-request-adaptor` | 101 | Copilot CLI normalization, git command classification, shell command parsing, destructive detection, chained commands |
| `duramen-response-formatter` | 11 | Copilot CLI and generic output formatting across all decision tiers, policy metadata |
| `duramen-audit` | 2 | JSONL audit log writing and append behavior |
| `duramen-policy-defaults` | 2 | Embedded policy and schema non-emptiness |
| `duramen` (CLI) | 48 | CLI argument handling, error exits, end-to-end pipeline, hook script protocol |

---

## Engine Crate (`duramen-engine`)

### Evaluator (`crates/engine/src/evaluator.rs`) — 10 unit tests

| Test | Intent | Type |
|------|--------|------|
| `permits_when_policy_allows` | A `permit` policy produces an `Allow` decision | Happy path |
| `denies_when_policy_forbids` | A `forbid` overrides `permit` (deny-overrides semantics) | Error case |
| `denies_when_no_policies_match` | Empty policy set defaults to `Deny` (fail-closed) | Edge case |
| `respects_resource_attributes_in_policy` | Cedar evaluates `resource.is_destructive` attribute correctly | Edge case |
| `extracts_policy_name_and_description_from_advice` | `@name`/`@description` annotations extracted on `@advice("audit")` | Happy path |
| `policy_name_is_none_without_annotation` | Missing annotations leave `policy_name`/`policy_description` as `None` | Edge case |
| `extracts_require_approval_annotations` | `@advice("require-approval")` produces `RequireApproval` with metadata in reason | Happy path |
| `rejects_malformed_policy_string` | Invalid Cedar syntax returns `PolicyParse` error | Error case |
| `rejects_invalid_schema_string` | Invalid schema string returns error from `from_policy_sources_with_schema` | Error case |
| `handles_non_boolean_resource_attributes` | Unsupported attribute types (arrays, nulls) are skipped without panic | Edge case |

### Decision (`crates/engine/src/decision.rs`) — 7 unit tests

| Test | Intent | Type |
|------|--------|------|
| `decision_tier_exit_codes` | All 4 tiers map to correct exit codes (0, 0, 2, 1) | Happy path |
| `decision_tier_from_str` | Valid strings parse to correct tiers; invalid string errors | Edge case |
| `decision_tier_serializes_lowercase` | JSON serialization uses kebab-case (`require-approval`) | Happy path |
| `authz_decision_is_allowed` | `Allow` and `Audit` are allowed; `Deny` is not | Boundary |
| `decision_tier_from_str_rejects_variations` | Uppercase, empty, and whitespace-padded strings rejected | Invalid input |
| `authz_decision_json_round_trip` | Full `AuthzDecision` with all fields serializes and deserializes | Happy path |
| `authz_decision_omits_none_fields_in_json` | `None` fields (`policy_id`, `policy_name`, etc.) omitted from JSON | Boundary |

### Entities (`crates/engine/src/entities.rs`) — 9 unit tests

| Test | Intent | Type |
|------|--------|------|
| `agent_principal_creation` | `AgentPrincipal::new` sets agent_type, defaults session/user to `None` | Happy path |
| `authz_resource_file` | File resource constructor sets type and ID | Happy path |
| `authz_resource_command` | Command resource constructor sets type and ID | Happy path |
| `authz_resource_url` | URL resource constructor sets type and ID | Happy path |
| `authz_resource_git_ref` | GitRef resource constructor sets type and ID | Happy path |
| `authz_request_round_trip_json` | `AuthzRequest` serialization/deserialization round-trip | Happy path |
| `raw_hook_payload_from_json` | Basic `RawHookPayload` deserialization | Happy path |
| `raw_hook_payload_aliases` | `toolName`/`toolArgs` aliases work (real Copilot CLI format) | Edge case |
| `raw_hook_payload_missing_optional_fields` | Missing `cwd`/`timestamp` default to `None` | Missing input |

### Policy Loader (`crates/engine/src/policy.rs`) — 8 unit tests

| Test | Intent | Type |
|------|--------|------|
| `loads_policies_from_directory` | Loads `.cedar` files and returns their contents | Happy path |
| `ignores_non_cedar_files` | Non-`.cedar` files are skipped | Edge case |
| `returns_error_on_invalid_policy` | Invalid Cedar syntax in file returns error | Error case |
| `loads_empty_directory` | Empty directory returns empty list | Empty input |
| `nonexistent_directory_returns_empty` | Missing directory returns empty list (not error) | Edge case |
| `load_merged_with_defaults_only` | Merged loading works with defaults and no repo/user dirs | Happy path |
| `load_merged_repo_overrides_defaults` | Repo policies are combined with defaults | Mixed sources |
| `load_merged_all_empty_sources` | All empty sources produce empty policy set | Empty input |

### Default Policies (`crates/engine/tests/default_policies_test.rs`) — 20 integration tests

| Test | Intent | Type |
|------|--------|------|
| `combined_allows_read_operations` | All read actions (`file:read`, `directory:list`, `git:status/log/diff`, `git::read`) allowed | Happy path |
| `combined_audits_file_writes_on_non_protected` | `file:create`/`file:edit` on non-protected files → `Audit` | Edge case |
| `combined_denies_force_push` | `git:force-push` → `Deny` | Error case |
| `combined_denies_destructive_operations` | `git::destructive` → `Deny` | Error case |
| `combined_denies_destructive_resource` | Resource with `is_destructive=true` → `Deny` | Error case |
| `combined_requires_approval_for_push_on_protected` | `git:push/commit/network/write` on protected refs → `RequireApproval` | Edge case |
| `combined_requires_approval_for_file_delete_non_protected` | Non-protected `file:delete` → `RequireApproval` | Edge case |
| `combined_denies_file_delete_on_protected` | Protected `file:delete` → `Deny` | Error case |
| `combined_denies_unknown_action` | Unknown action → `Deny` (default-deny) | Error case |
| `allow_read_only_permits_reads` | Read-only policy permits reads in isolation | Happy path |
| `allow_read_only_denies_writes` | Read-only policy does not permit writes | Error case |
| `audit_file_writes_produces_audit_tier` | Audit policy produces `Audit` tier | Happy path |
| `audit_file_writes_skips_protected` | Audit policy denies protected files | Error case |
| `deny_destructive_blocks_force_push` | Deny-destructive policy blocks force push | Error case |
| `deny_destructive_blocks_destructive_attribute` | Deny-destructive policy blocks `is_destructive=true` | Error case |
| `require_approval_sensitive_on_protected_push` | Require-approval policy triggers on protected push | Edge case |
| `require_approval_sensitive_skips_unprotected` | Require-approval policy doesn't cover unprotected refs | Error case |
| `default_policies_validate_against_schema` | All default policies pass Cedar schema validation | Happy path |
| `annotated_policies_return_metadata` | Decisions carry `policy_name` from `@name` annotations | Happy path |
| `schema_validation_rejects_invalid_policy` | Invalid policy fails schema validation | Error case |

---

## Request Adaptor Crate (`duramen-request-adaptor`)

### Copilot CLI Normalizer (`copilot_cli.rs`) — 37 unit tests

| Test | Intent | Type |
|------|--------|------|
| `normalizes_file_edit` | `edit` tool → `file:edit` with `is_protected=false` | Happy path |
| `normalizes_shell_command` | `cargo build` → `shell:cargo` with target resource | Happy path |
| `detects_destructive_command` | `sudo rm -rf /` → destructive + elevated | Error case |
| `parses_rm_command_with_target` | `rm -rf dist` → resolved path with cwd | Edge case |
| `parses_git_status_as_read` | `git status` → `git::read` | Happy path |
| `parses_git_log_as_read` | `git log` → `git::read` | Happy path |
| `parses_git_commit_as_write` | `git commit` → `git::write` | Happy path |
| `parses_git_push_as_network` | `git push origin main` → `git::network` with remote/ref | Happy path |
| `parses_git_force_push_as_destructive` | `git push --force` → `git::destructive` | Error case |
| `parses_git_reset_hard_as_destructive` | `git reset --hard` → `git::destructive` | Error case |
| `parses_git_branch_delete_as_destructive` | `git branch -D` → `git::destructive` | Error case |
| `parses_sudo_git_push_as_elevated` | `sudo git push` → `is_elevated=true` | Edge case |
| `parses_git_checkout_branch` | `git checkout` → `git::write` with branch | Happy path |
| `parses_git_fetch_as_network` | `git fetch` → `git::network` with remote | Happy path |
| `parses_git_branch_list_as_read` | `git branch` (list) → `git::read` | Happy path |
| `parses_curl_as_url_resource` | `curl https://...` → URL resource | Happy path |
| `normalizes_web_fetch` | `web_fetch` tool → `network:fetch` | Happy path |
| `normalizes_real_copilot_cli_format` | Real `toolName`/`toolArgs` string payload | Happy path |
| `normalizes_real_copilot_cli_destructive` | Real payload with destructive command | Error case |
| `normalizes_real_copilot_cli_file_edit` | Real payload for file edit | Happy path |
| `shell_command_no_args_uses_cwd` | Binary-only command uses cwd as resource | Edge case |
| `handles_empty_command_string` | Empty command doesn't panic | Invalid input |
| `strips_env_prefix` | `env cargo test` → strips `env`, parses `cargo` | Edge case |
| `strips_nohup_prefix` | `nohup cargo build` → strips `nohup` | Edge case |
| `detects_mkfs_as_destructive` | `mkfs.ext4` → destructive | Error case |
| `detects_dd_as_destructive` | `dd if=/dev/zero` → destructive | Error case |
| `parses_git_pull_as_network` | `git pull` → `git::network` | Happy path |
| `parses_git_add_as_write` | `git add .` → `git::write` | Happy path |
| `parses_git_merge_as_write` | `git merge` → `git::write` | Happy path |
| `parses_git_rebase_as_write` | `git rebase` → `git::write` | Happy path |
| `parses_git_stash_as_write` | `git stash` → `git::write` | Happy path |
| `parses_git_clone_as_network` | `git clone` → `git::network` | Happy path |
| `parses_git_clean_f_as_destructive` | `git clean -fd` → `git::destructive` | Error case |
| `parses_git_tag_as_read` | `git tag` (list) → `git::read` | Happy path |
| `unknown_tool_maps_to_tool_unknown` | Unknown tool → `tool:unknown` | Edge case |
| `file_patterns_affected_populated_for_file_tool` | File tool populates `file_patterns_affected` context | Happy path |
| `invalid_tool_args_string_handled` | Malformed toolArgs string doesn't panic | Invalid input |

### Git Command Handler (`commands/git.rs`) — 19 unit tests

| Test | Intent | Type |
|------|--------|------|
| `git_handler_binary_name` | Handler self-identifies as `git` | Happy path |
| `git_handler_parses_push_force` | `push --force` → destructive with ref | Error case |
| `git_handler_parses_status` | `status` → read | Happy path |
| `git_handler_parses_commit` | `commit` → write | Happy path |
| `git_handler_parses_pull` | `pull origin main` → network with ref | Happy path |
| `git_handler_parses_clone` | `clone` → network | Happy path |
| `git_handler_parses_add` | `add .` → write | Happy path |
| `git_handler_parses_merge` | `merge feature` → write | Happy path |
| `git_handler_parses_rebase` | `rebase main` → write | Happy path |
| `git_handler_parses_reset_soft` | `reset HEAD~1` → write (soft) | Happy path |
| `git_handler_parses_reset_hard` | `reset --hard HEAD~3` → destructive | Error case |
| `git_handler_parses_clean_fd` | `clean -fd` → destructive | Error case |
| `git_handler_parses_branch_delete_lowercase` | `branch -d` → destructive | Error case |
| `git_handler_parses_tag_read` | `tag` (list) → read | Happy path |
| `git_handler_parses_tag_delete` | `tag -d v1.0` → write | Edge case |
| `git_handler_parses_push_with_remote_and_ref` | `push upstream feature-branch` → network with remote attr | Happy path |
| `git_handler_defaults_unknown_subcommand_to_write` | Unknown subcommand → write (safe default) | Edge case |
| `git_handler_no_subcommand_defaults_to_status` | Empty args → read (defaults to status) | Edge case |

### Default Command Handler (`commands/default.rs`) — 5 unit tests

| Test | Intent | Type |
|------|--------|------|
| `default_handler_extracts_file_target` | Last non-flag arg → file resource with cwd resolution | Happy path |
| `default_handler_detects_url` | URL arg → URL resource | Happy path |
| `default_handler_falls_back_to_cwd` | Flag-only input → cwd as resource | Edge case |
| `default_handler_no_cwd_no_args` | No cwd, no args → `"."` fallback | Boundary |
| `default_handler_absolute_path` | Absolute path arg bypasses cwd resolution | Edge case |

### Generic Normalizer (`generic.rs`) — 2 unit tests

| Test | Intent | Type |
|------|--------|------|
| `generic_normalizer_parses_full_request` | Valid JSON args deserialize to `AuthzRequest` | Happy path |
| `generic_normalizer_rejects_invalid_payload` | Invalid JSON shape → `NormalizerError::Json` | Error case |

---

## Response Formatter Crate (`duramen-response-formatter`)

### Copilot CLI Formatter (`copilot_cli.rs`) — 6 unit tests

| Test | Intent | Type |
|------|--------|------|
| `copilot_allow_response` | `Allow` → `allowed=true`, exit 0 | Happy path |
| `copilot_deny_response` | `Deny` → `allowed=false`, exit 1, includes policy_id | Error case |
| `copilot_require_approval_prompts_user` | `RequireApproval` → `should_prompt_user=true`, exit 2 | Edge case |
| `copilot_audit_response` | `Audit` → `allowed=true`, `should_prompt_user=false`, exit 0 | Happy path |
| `copilot_response_includes_policy_metadata` | `policy_name`/`policy_description` included when set | Happy path |
| `copilot_response_omits_none_metadata` | `None` metadata fields omitted from JSON output | Boundary |

### Generic Formatter (`generic.rs`) — 5 unit tests

| Test | Intent | Type |
|------|--------|------|
| `formats_allow_as_json` | `Allow` → JSON with exit 0 | Happy path |
| `formats_deny_with_exit_code_1` | `Deny` → JSON with exit 1 | Error case |
| `formats_require_approval_with_exit_code_2` | `RequireApproval` → JSON with exit 2 | Edge case |
| `formats_audit_with_exit_code_0` | `Audit` → JSON with exit 0 | Happy path |
| `generic_includes_policy_metadata_when_present` | `policy_name` included in generic output | Happy path |

---

## Audit Crate (`duramen-audit`)

### Logger (`logger.rs`) — 2 unit tests

| Test | Intent | Type |
|------|--------|------|
| `writes_json_line_to_file` | Writes valid JSONL entry with all fields | Happy path |
| `appends_multiple_entries` | Multiple entries append (don't overwrite) | Edge case |

---

## Policy Defaults Crate (`duramen-policy-defaults`)

### Lib (`lib.rs`) — 2 unit tests

| Test | Intent | Type |
|------|--------|------|
| `default_policies_are_non_empty` | All 4 embedded policy strings are non-empty | Happy path |
| `schema_is_non_empty` | Embedded Cedar schema is non-empty | Happy path |

---

## CLI Crate (`duramen`) — Integration Tests

### Check (`check_test.rs`) — 6 tests

| Test | Intent | Type |
|------|--------|------|
| `check_allows_file_read` | Explicit args: `file:read` → exit 0 | Happy path |
| `check_denies_force_push` | Explicit args: `git:force-push` → exit 1 | Error case |
| `check_exits_3_on_missing_required_args` | Missing `--principal` → exit 3 | Error case |
| `check_exits_3_on_unknown_agent` | Unknown `--agent` → exit 3 | Error case |
| `check_exits_3_on_malformed_stdin_json` | Invalid JSON on stdin → exit 3 | Invalid input |
| `check_exits_3_on_invalid_resource_type` | Invalid `--resource-type` → exit 3 | Invalid input |

### Validate (`validate_test.rs`) — 4 tests

| Test | Intent | Type |
|------|--------|------|
| `validate_valid_policies` | Valid `.cedar` files → exit 0 | Happy path |
| `validate_rejects_invalid_policies` | Invalid Cedar syntax → exit 3 | Error case |
| `validate_missing_dir_exits_3` | Nonexistent directory → exit 3 | Error case |
| `validate_empty_directory` | Empty directory → exit 0 (valid, zero policies) | Empty input |

### Init (`init_test.rs`) — 2 tests

| Test | Intent | Type |
|------|--------|------|
| `init_creates_authz_directory` | Creates `.authz/` with schema and policy files | Happy path |
| `init_is_idempotent` | Re-running `init` succeeds without errors | Idempotency |

### E2E Pipeline (`e2e_pipeline_test.rs`) — 21 tests

| Test | Intent | Type |
|------|--------|------|
| `e2e_file_read_allowed` | Full pipeline: Copilot `view` tool → allow | Happy path |
| `e2e_file_edit_audited` | Full pipeline: Copilot `edit` tool → audit/allow | Edge case |
| `e2e_destructive_command_denied` | Full pipeline: `rm -rf /` → deny | Error case |
| `e2e_safe_shell_command_allowed` | Non-covered shell command → allow | Happy path |
| `e2e_force_push_denied` | Explicit `git:force-push` → deny | Error case |
| `e2e_web_fetch_allowed` | `web_fetch` → allowed | Happy path |
| `e2e_grep_allowed` | `grep` tool → allow (read operation) | Happy path |
| `e2e_create_file_audited` | `create` tool → audit/allow | Edge case |
| `e2e_unknown_tool_allowed` | Unknown tool → allowed | Happy path |
| `e2e_copilot_response_format_complete` | Output contains required Copilot response fields | Happy path |
| `e2e_real_copilot_cli_payload_format` | Real `toolName`/`toolArgs` format accepted | Happy path |
| `e2e_real_copilot_cli_destructive_denied` | Real destructive payload denied | Error case |
| `e2e_git_status_allowed` | `git status` through pipeline → allow | Happy path |
| `e2e_git_force_push_via_normalizer_denied` | `git push --force` through normalizer → deny | Error case |
| `e2e_git_reset_hard_denied` | `git reset --hard` through normalizer → deny | Error case |
| `e2e_empty_stdin_exits_3` | Empty stdin → exit 3 | Invalid input |
| `e2e_git_pull_through_normalizer` | `git pull` full pipeline | Happy path |
| `e2e_git_clone_through_normalizer` | `git clone` full pipeline | Happy path |
| `e2e_git_merge_through_normalizer` | `git merge` → deny (no permit for git::write) | Error case |
| `e2e_git_clean_fd_denied` | `git clean -fd` → deny (destructive) | Error case |
| `e2e_response_includes_policy_metadata` | Deny response includes policy metadata from annotations | Happy path |

---

## Coverage by Category

| Category | Tests | Notes |
|----------|------:|-------|
| Happy path (allow/permit) | 58 | All tools, git subcommands, payload formats |
| Error/deny cases | 48 | Destructive commands, protected resources, unknown actions |
| Edge cases (audit/approval) | 28 | Protected refs, non-protected deletes, prefix stripping |
| Invalid/missing input | 15 | Malformed JSON, empty stdin, missing args, bad types |
| Boundary conditions | 8 | None field omission, fallback defaults, empty directories |
| Schema validation | 4 | Valid schemas pass, invalid policies fail |
| Mixed sources | 2 | Merged policy loading with repo + defaults |
| Idempotency | 1 | Re-running init |
