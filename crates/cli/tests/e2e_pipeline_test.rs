use assert_cmd::Command;
use predicates::prelude::*;

/// Full pipeline: file read → normalizer → Cedar evaluation → Copilot CLI formatted allow
#[test]
fn e2e_file_read_allowed() {
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args(["check", "--agent", "copilot-cli"]);
    cmd.write_stdin(r#"{"tool":"view","args":{"path":"/src/main.rs"}}"#);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(r#""allowed": true"#))
        .stdout(predicate::str::contains(r#""should_prompt_user": false"#));
}

/// Full pipeline: file edit → normalizer (sets is_protected=false) → Cedar audit policy → Copilot CLI allow (audited)
#[test]
fn e2e_file_edit_audited() {
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args(["check", "--agent", "copilot-cli"]);
    cmd.write_stdin(r#"{"tool":"edit","args":{"path":"/src/lib.rs","old_str":"foo","new_str":"bar"}}"#);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(r#""allowed": true"#));
}

/// Full pipeline: destructive shell command → normalizer (shell:sudo, is_destructive) → Cedar deny → Copilot CLI formatted deny
#[test]
fn e2e_destructive_command_denied() {
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args(["check", "--agent", "copilot-cli"]);
    cmd.write_stdin(r#"{"tool":"powershell","args":{"command":"sudo rm -rf /"}}"#);
    cmd.assert()
        .code(1)
        .stdout(predicate::str::contains(r#""allowed": false"#))
        .stdout(predicate::str::contains(r#""should_prompt_user": false"#));
}

/// Full pipeline: safe shell command → normalizer → catch-all permit → allow
#[test]
fn e2e_safe_shell_command_allowed() {
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args(["check", "--agent", "copilot-cli"]);
    cmd.write_stdin(r#"{"tool":"powershell","args":{"command":"cargo build"}}"#);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(r#""allowed": true"#));
}

/// Full pipeline: git force-push → normalizer → Cedar forbid (unconditional) → deny
#[test]
fn e2e_force_push_denied() {
    // Note: The copilot-cli normalizer maps powershell/bash to shell:<binary>.
    // Force-push via git:force-push action requires the generic path.
    // This tests the CLI with explicit args to verify force-push denial.
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args(["check", "--principal", "CopilotCLI", "--action", "git:force-push",
              "--resource", "main", "--resource-type", "gitref"]);
    cmd.assert()
        .code(1)
        .stdout(predicate::str::contains(r#""deny""#));
}

/// Full pipeline: web fetch → normalizer → catch-all permit → allow
#[test]
fn e2e_web_fetch_allowed() {
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args(["check", "--agent", "copilot-cli"]);
    cmd.write_stdin(r#"{"tool":"web_fetch","args":{"url":"https://docs.rs/cedar-policy"}}"#);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(r#""allowed": true"#));
}

/// Full pipeline: grep (read operation) → normalizer → Cedar allow-read-only → allow
#[test]
fn e2e_grep_allowed() {
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args(["check", "--agent", "copilot-cli"]);
    cmd.write_stdin(r#"{"tool":"grep","args":{"pattern":"TODO","path":"/src"}}"#);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(r#""allowed": true"#));
}

/// Full pipeline: create file → normalizer (sets is_protected=false) → Cedar audit policy → Copilot CLI allow (audited)
#[test]
fn e2e_create_file_audited() {
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args(["check", "--agent", "copilot-cli"]);
    cmd.write_stdin(r#"{"tool":"create","args":{"path":"/src/new.rs","file_text":"fn main() {}"}}"#);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(r#""allowed": true"#));
}

/// Full pipeline: unknown tool → normalizer → catch-all permit → allow
#[test]
fn e2e_unknown_tool_allowed() {
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args(["check", "--agent", "copilot-cli"]);
    cmd.write_stdin(r#"{"tool":"some_future_tool","args":{"foo":"bar"}}"#);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(r#""allowed": true"#));
}

/// Verifies the Copilot CLI response format has all required fields
#[test]
fn e2e_copilot_response_format_complete() {
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args(["check", "--agent", "copilot-cli"]);
    cmd.write_stdin(r#"{"tool":"view","args":{"path":"/test.txt"}}"#);
    let output = cmd.output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();

    // Verify all expected fields exist
    assert!(parsed.get("allowed").is_some(), "missing 'allowed' field");
    assert!(parsed.get("message").is_some(), "missing 'message' field");
    assert!(parsed.get("should_prompt_user").is_some(), "missing 'should_prompt_user' field");
}

/// Full pipeline with REAL Copilot CLI payload format (toolName + toolArgs as JSON string)
#[test]
fn e2e_real_copilot_cli_payload_format() {
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args(["check", "--agent", "copilot-cli"]);
    cmd.write_stdin(r#"{"timestamp":1704614600000,"cwd":"/project","toolName":"view","toolArgs":"{\"path\":\"/src/main.rs\"}"}"#);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(r#""allowed": true"#));
}

/// Full pipeline: real Copilot CLI destructive command (shell:sudo) → deny
#[test]
fn e2e_real_copilot_cli_destructive_denied() {
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args(["check", "--agent", "copilot-cli"]);
    cmd.write_stdin(r#"{"timestamp":1704614600000,"cwd":"/project","toolName":"bash","toolArgs":"{\"command\":\"sudo rm -rf /\"}"}"#);
    cmd.assert()
        .code(1)
        .stdout(predicate::str::contains(r#""allowed": false"#));
}

/// Full pipeline: git status via normalizer → git::read → Cedar allow-read-only → allow
#[test]
fn e2e_git_status_allowed() {
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args(["check", "--agent", "copilot-cli"]);
    cmd.write_stdin(r#"{"tool":"bash","args":{"command":"git status"}}"#);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(r#""allowed": true"#));
}

/// Full pipeline: git push --force via normalizer → git::destructive → Cedar deny → deny
#[test]
fn e2e_git_force_push_via_normalizer_denied() {
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args(["check", "--agent", "copilot-cli"]);
    cmd.write_stdin(r#"{"tool":"bash","args":{"command":"git push --force origin main"}}"#);
    cmd.assert()
        .code(1)
        .stdout(predicate::str::contains(r#""allowed": false"#));
}

/// Full pipeline: git reset --hard via normalizer → git::destructive → Cedar deny → deny
#[test]
fn e2e_git_reset_hard_denied() {
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args(["check", "--agent", "copilot-cli"]);
    cmd.write_stdin(r#"{"tool":"bash","args":{"command":"git reset --hard HEAD~3"}}"#);
    cmd.assert()
        .code(1)
        .stdout(predicate::str::contains(r#""allowed": false"#));
}

#[test]
fn e2e_empty_stdin_exits_3() {
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args(["check", "--agent", "copilot-cli"])
        .write_stdin("");
    cmd.assert().code(3);
}

#[test]
fn e2e_git_pull_through_normalizer() {
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args(["check", "--agent", "copilot-cli"])
        .write_stdin(r#"{"tool":"bash","args":{"command":"git pull origin main"},"cwd":"/project"}"#);
    // git pull is git::network — allowed by default permit
    cmd.assert().success();
}

#[test]
fn e2e_git_clone_through_normalizer() {
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args(["check", "--agent", "copilot-cli"])
        .write_stdin(r#"{"tool":"bash","args":{"command":"git clone https://github.com/repo.git"},"cwd":"/project"}"#);
    // git clone is git::network — allowed by default permit
    cmd.assert().success();
}

#[test]
fn e2e_git_merge_through_normalizer() {
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args(["check", "--agent", "copilot-cli"])
        .write_stdin(r#"{"tool":"bash","args":{"command":"git merge feature"},"cwd":"/project"}"#);
    // git merge is git::write — allowed by default permit
    cmd.assert().success();
}

#[test]
fn e2e_git_clean_fd_denied() {
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args(["check", "--agent", "copilot-cli"])
        .write_stdin(r#"{"tool":"bash","args":{"command":"git clean -fd"},"cwd":"/project"}"#);
    cmd.assert().code(1);
}

#[test]
fn e2e_response_includes_policy_metadata() {
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args(["check", "--agent", "copilot-cli"])
        .write_stdin(r#"{"tool":"bash","args":{"command":"git push --force origin main"},"cwd":"/project"}"#);
    let output = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(parsed["allowed"], false);
    assert!(parsed["policy_name"].as_str().is_some(), "deny response must include policy_name");
    assert!(parsed["policy_description"].as_str().is_some(), "deny response must include policy_description");
}
