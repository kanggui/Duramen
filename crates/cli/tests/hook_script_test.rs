/// Integration tests for the PowerShell hook script.
///
/// These tests verify the full hook protocol: payload → hook script → duramen binary → response.
/// They ensure the hook script correctly:
///   - Parses multi-line JSON output from duramen
///   - Maps duramen's CopilotResponse fields to Copilot CLI's permissionDecision protocol
///   - Returns non-empty reason on deny/require-approval
///   - Returns "allow" for permitted actions
use std::process::Command;

fn hook_script_path() -> String {
    let manifest = env!("CARGO_MANIFEST_DIR");
    format!("{}\\..\\..\\hooks\\copilot-cli\\duramen-hook.ps1", manifest)
        .replace('/', "\\")
}

fn run_hook(payload: &str) -> (i32, String) {
    let output = Command::new("powershell")
        .args([
            "-ExecutionPolicy", "Bypass",
            "-NoProfile",
            "-File", &hook_script_path(),
        ])
        .env("PATH", format!("{}\\..\\..\\target\\debug;{}", env!("CARGO_MANIFEST_DIR"), std::env::var("PATH").unwrap_or_default()))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(payload.as_bytes()).ok();
            }
            child.wait_with_output()
        })
        .expect("failed to run hook script");

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (exit_code, stdout)
}

fn parse_hook_response(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("hook output is not valid JSON: {e}\nOutput: {stdout}"))
}

#[test]
fn hook_allows_file_read() {
    let (_, stdout) = run_hook(r#"{"tool":"view","args":{"path":"/src/main.rs"},"cwd":"/project"}"#);
    let response = parse_hook_response(&stdout);
    assert_eq!(response["permissionDecision"], "allow");
}

#[test]
fn hook_allows_safe_shell_command() {
    let (_, stdout) = run_hook(r#"{"tool":"bash","args":{"command":"cargo build"},"cwd":"/project"}"#);
    let response = parse_hook_response(&stdout);
    assert_eq!(response["permissionDecision"], "allow");
}

#[test]
fn hook_denies_force_push_with_reason() {
    let (_, stdout) = run_hook(
        r#"{"tool":"bash","args":{"command":"git push --force origin main"},"cwd":"/project"}"#,
    );
    let response = parse_hook_response(&stdout);
    assert_eq!(response["permissionDecision"], "deny");
    let reason = response["permissionDecisionReason"].as_str().unwrap_or("");
    assert!(!reason.is_empty(), "reason must not be empty on deny");
    assert!(
        reason.contains("Deny") || reason.contains("denied"),
        "reason should mention denial: {reason}"
    );
}

#[test]
fn hook_denies_destructive_command_with_reason() {
    let (_, stdout) = run_hook(
        r#"{"tool":"bash","args":{"command":"git reset --hard HEAD~3"},"cwd":"/project"}"#,
    );
    let response = parse_hook_response(&stdout);
    assert_eq!(response["permissionDecision"], "deny");
    let reason = response["permissionDecisionReason"].as_str().unwrap_or("");
    assert!(!reason.is_empty(), "reason must not be empty on deny");
    assert!(
        reason.contains("destructive") || reason.contains("Deny"),
        "reason should describe the blocking policy: {reason}"
    );
}

#[test]
fn hook_denies_rm_rf_with_reason() {
    let (_, stdout) = run_hook(
        r#"{"tool":"bash","args":{"command":"rm -rf /"},"cwd":"/project"}"#,
    );
    let response = parse_hook_response(&stdout);
    assert_eq!(response["permissionDecision"], "deny");
    let reason = response["permissionDecisionReason"].as_str().unwrap_or("");
    assert!(!reason.is_empty(), "reason must not be empty on deny");
}

#[test]
fn hook_denies_chained_destructive_with_reason() {
    let (_, stdout) = run_hook(
        r#"{"tool":"bash","args":{"command":"git log && git reset --hard HEAD~2"},"cwd":"/project"}"#,
    );
    let response = parse_hook_response(&stdout);
    assert_eq!(response["permissionDecision"], "deny");
    let reason = response["permissionDecisionReason"].as_str().unwrap_or("");
    assert!(!reason.is_empty(), "reason must not be empty on deny for chained commands");
}

#[test]
fn hook_response_is_valid_json() {
    // Even on error (invalid input), the hook should return valid JSON
    let (_, stdout) = run_hook("not json at all{{{");
    let response = parse_hook_response(&stdout);
    assert!(
        response.get("permissionDecision").is_some(),
        "hook must always return permissionDecision field"
    );
}

#[test]
fn hook_allows_file_edit() {
    let (_, stdout) = run_hook(
        r#"{"tool":"edit","args":{"path":"/src/lib.rs"},"cwd":"/project"}"#,
    );
    let response = parse_hook_response(&stdout);
    // File edits are audited (allow + log), hook should return "allow"
    assert_eq!(response["permissionDecision"], "allow");
}

#[test]
fn hook_allows_git_status() {
    let (_, stdout) = run_hook(
        r#"{"tool":"bash","args":{"command":"git status"},"cwd":"/project"}"#,
    );
    let response = parse_hook_response(&stdout);
    assert_eq!(response["permissionDecision"], "allow");
}

// Tests using the real Copilot CLI payload format (toolName/toolArgs as string)

#[test]
fn hook_real_copilot_format_allow() {
    let (_, stdout) = run_hook(
        r#"{"timestamp":1704614600000,"cwd":"/project","toolName":"bash","toolArgs":"{\"command\":\"git status\"}"}"#,
    );
    let response = parse_hook_response(&stdout);
    assert_eq!(response["permissionDecision"], "allow");
}

#[test]
fn hook_real_copilot_format_deny_with_reason() {
    let (_, stdout) = run_hook(
        r#"{"timestamp":1704614600000,"cwd":"/project","toolName":"bash","toolArgs":"{\"command\":\"git push --force origin main\"}"}"#,
    );
    let response = parse_hook_response(&stdout);
    assert_eq!(response["permissionDecision"], "deny");
    let reason = response["permissionDecisionReason"].as_str().unwrap_or("");
    assert!(!reason.is_empty(), "real Copilot format must return reason on deny");
    assert!(reason.contains("denied") || reason.contains("Deny"), "reason: {reason}");
}

#[test]
fn hook_denies_git_branch_delete() {
    let (_, stdout) = run_hook(
        r#"{"tool":"bash","args":{"command":"git branch -D old-feature"},"cwd":"/project"}"#,
    );
    let response = parse_hook_response(&stdout);
    assert_eq!(response["permissionDecision"], "deny");
    let reason = response["permissionDecisionReason"].as_str().unwrap_or("");
    assert!(!reason.is_empty());
}
