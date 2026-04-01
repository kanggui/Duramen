use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn validate_valid_policies() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("test.cedar"),
        r#"permit(principal, action, resource);"#,
    )
    .unwrap();
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args(["validate", "--policy-dir", dir.path().to_str().unwrap()]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("valid"));
}

#[test]
fn validate_rejects_invalid_policies() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("bad.cedar"), "not valid cedar!!!!").unwrap();
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args(["validate", "--policy-dir", dir.path().to_str().unwrap()]);
    cmd.assert().code(3);
}

#[test]
fn validate_missing_dir_exits_3() {
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args([
        "validate",
        "--policy-dir",
        "/nonexistent/path/that/does/not/exist",
    ]);
    cmd.assert().code(3);
}

#[test]
fn validate_empty_directory() {
    let dir = TempDir::new().unwrap();
    let policy_dir = dir.path().join("policies");
    std::fs::create_dir(&policy_dir).unwrap();

    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.args(["validate", "--policy-dir", policy_dir.to_str().unwrap()]);
    cmd.assert().success();
}
