use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn init_creates_authz_directory() {
    let dir = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.current_dir(dir.path());
    cmd.arg("init");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("initialized"));

    // Verify files were created
    assert!(dir
        .path()
        .join(".authz")
        .join("schema.cedarschema")
        .exists());
    assert!(dir
        .path()
        .join(".authz")
        .join("deny-destructive.cedar")
        .exists());
    assert!(dir
        .path()
        .join(".authz")
        .join("allow-default.cedar")
        .exists());
}

#[test]
fn init_is_idempotent() {
    let dir = TempDir::new().unwrap();
    let mut cmd1 = Command::cargo_bin("duramen").unwrap();
    cmd1.current_dir(dir.path());
    cmd1.arg("init");
    cmd1.assert().success();

    // Run init again — reports directory already exists
    let mut cmd2 = Command::cargo_bin("duramen").unwrap();
    cmd2.current_dir(dir.path());
    cmd2.arg("init");
    cmd2.assert().code(1);

    // Files should still exist from first init
    assert!(dir
        .path()
        .join(".authz")
        .join("schema.cedarschema")
        .exists());
}

#[test]
fn init_creates_all_policy_files() {
    let dir = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("duramen").unwrap();
    cmd.current_dir(dir.path());
    cmd.arg("init");
    cmd.assert().success();

    let authz = dir.path().join(".authz");
    assert!(authz.join("schema.cedarschema").exists());
    assert!(authz.join("allow-default.cedar").exists());
    assert!(authz.join("audit-file-writes.cedar").exists());
    assert!(authz.join("deny-destructive.cedar").exists());
    assert!(authz.join("require-approval-sensitive.cedar").exists());
}
