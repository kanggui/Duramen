use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn check_allows_file_read() {
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args([
        "check",
        "--principal",
        "CopilotCLI",
        "--action",
        "file:read",
        "--resource",
        "/src/main.rs",
        "--resource-type",
        "file",
    ]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("allow").or(predicate::str::contains("audit")));
}

#[test]
fn check_denies_force_push() {
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args([
        "check",
        "--principal",
        "CopilotCLI",
        "--action",
        "git:force-push",
        "--resource",
        "main",
        "--resource-type",
        "gitref",
    ]);
    cmd.assert()
        .code(1)
        .stdout(predicate::str::contains("deny"));
}

#[test]
fn check_exits_3_on_missing_required_args() {
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args(["check", "--principal", "CopilotCLI"]);
    cmd.assert().code(3);
}

#[test]
fn check_exits_3_on_unknown_agent() {
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args(["check", "--agent", "nonexistent-agent"])
        .write_stdin(r#"{"tool":"edit","args":{"path":"/test.rs"}}"#);
    cmd.assert().code(3);
}

#[test]
fn check_exits_3_on_malformed_stdin_json() {
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args(["check", "--agent", "copilot-cli"])
        .write_stdin("not json at all{{{");
    cmd.assert().code(3);
}

#[test]
fn check_exits_3_on_invalid_resource_type() {
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args([
        "check",
        "--principal",
        "test",
        "--action",
        "file:read",
        "--resource",
        "/test",
        "--resource-type",
        "bogus",
    ]);
    cmd.assert().code(3);
}
