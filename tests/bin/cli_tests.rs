use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::TempDir;

fn setup_env() -> (TempDir, PathBuf, PathBuf) {
    let td = tempfile::tempdir().expect("tempdir");
    let cfg_home = td.path().join("config");
    let cache_home = td.path().join("cache");
    let data_home = td.path().join("data");
    fs::create_dir_all(&cfg_home).unwrap();
    fs::create_dir_all(&cache_home).unwrap();
    fs::create_dir_all(&data_home).unwrap();
    (td, cfg_home, cache_home)
}

fn write_yaml_config(xdg_config_home: &Path, password_file: &Path, run_profile: Option<&str>) {
    let app_dir = xdg_config_home.join("gman");
    fs::create_dir_all(&app_dir).unwrap();
    let cfg = if let Some(profile) = run_profile {
        format!(
            r#"default_provider: local
providers:
  - name: local
    type: local
    password_file: {}
run_configs:
  - name: {}
    secrets: ["api_key"]
"#,
            password_file.display(),
            profile
        )
    } else {
        format!(
            r#"default_provider: local
providers:
  - name: local
    type: local
    password_file: {}
"#,
            password_file.display()
        )
    };
    // Confy with yaml feature typically uses .yml; write both to be safe.
    fs::write(app_dir.join("config.yml"), &cfg).unwrap();
    fs::write(app_dir.join("config.yaml"), &cfg).unwrap();
}

#[test]
#[cfg(unix)]
fn cli_config_no_changes() {
	let (td, xdg_cfg, xdg_cache) = setup_env();
	let pw_file = td.path().join("pw.txt");
	fs::write(&pw_file, b"pw\n").unwrap();
	write_yaml_config(&xdg_cfg, &pw_file, None);

	// Create a no-op editor script that exits successfully without modifying the file
	let editor = td.path().join("noop-editor.sh");
	fs::write(&editor, b"#!/bin/sh\nexit 0\n").unwrap();
	let mut perms = fs::metadata(&editor).unwrap().permissions();
	perms.set_mode(0o755);
	fs::set_permissions(&editor, perms).unwrap();

	let mut cmd = Command::cargo_bin("gman").unwrap();
	cmd.env("XDG_CONFIG_HOME", &xdg_cfg)
		.env("XDG_CACHE_HOME", &xdg_cache)
		.env("EDITOR", &editor)
		.arg("config");

	cmd.assert()
		.success()
		.stdout(predicate::str::contains("No changes made to configuration"));
}

#[test]
#[cfg(unix)]
fn cli_config_updates_and_persists() {
	let (td, xdg_cfg, xdg_cache) = setup_env();
	let pw_file = td.path().join("pw.txt");
	fs::write(&pw_file, b"pw\n").unwrap();
	write_yaml_config(&xdg_cfg, &pw_file, None);

	// Editor script appends a valid run_configs section to the YAML file
	let editor = td.path().join("append-run-config.sh");
	let script = r#"#!/bin/sh
FILE="$1"
cat >> "$FILE" <<'EOF'
run_configs:
  - name: echo
    secrets: ["api_key"]
EOF
exit 0
"#;
	fs::write(&editor, script.as_bytes()).unwrap();
	let mut perms = fs::metadata(&editor).unwrap().permissions();
	perms.set_mode(0o755);
	fs::set_permissions(&editor, perms).unwrap();

	let mut cmd = Command::cargo_bin("gman").unwrap();
	cmd.env("XDG_CONFIG_HOME", &xdg_cfg)
		.env("XDG_CACHE_HOME", &xdg_cache)
		.env("EDITOR", &editor)
		.arg("config");

	cmd.assert()
		.success()
		.stdout(predicate::str::contains("Configuration updated successfully"));

	// Verify that the config file now contains the run_configs key
	let cfg_path = xdg_cfg.join("gman").join("config.yml");
	let written = fs::read_to_string(&cfg_path).expect("config file readable");
	assert!(written.contains("run_configs:"));
	assert!(written.contains("name: echo"));
}

#[test]
fn cli_shows_help() {
    let (_td, cfg, cache) = setup_env();
    let mut cmd = Command::cargo_bin("gman").unwrap();
    cmd.env("XDG_CACHE_HOME", &cache)
        .env("XDG_CONFIG_HOME", &cfg)
        .arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Usage").or(predicate::str::contains("Add")));
}

#[test]
fn cli_completions_bash() {
    let (_td, cfg, cache) = setup_env();
    let mut cmd = Command::cargo_bin("gman").unwrap();
    cmd.env("XDG_CACHE_HOME", &cache)
        .env("XDG_CONFIG_HOME", &cfg)
        .args(["completions", "bash"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("_gman").or(predicate::str::contains("complete -F")));
}

#[test]
fn cli_add_get_list_update_delete_roundtrip() {
    let (td, xdg_cfg, xdg_cache) = setup_env();
    let pw_file = td.path().join("pw.txt");
    fs::write(&pw_file, b"testpw\n").unwrap();
    write_yaml_config(&xdg_cfg, &pw_file, None);

    // add
    let mut add = Command::cargo_bin("gman").unwrap();
    add.env("XDG_CONFIG_HOME", &xdg_cfg)
        .env("XDG_CACHE_HOME", &xdg_cache)
        .stdin(Stdio::piped())
        .args(["add", "my_api_key"]);
    let mut child = add.spawn().unwrap();
    use std::io::Write as _;
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"super_secret\n")
        .unwrap();
    let add_out = child.wait_with_output().unwrap();
    assert!(add_out.status.success());

    // get (text)
    let mut get = Command::cargo_bin("gman").unwrap();
    get.env("XDG_CONFIG_HOME", &xdg_cfg)
        .env("XDG_CACHE_HOME", &xdg_cache)
        .args(["get", "my_api_key"]);
    get.assert()
        .success()
        .stdout(predicate::str::contains("super_secret"));

    // get as JSON
    let mut get_json = Command::cargo_bin("gman").unwrap();
    get_json
        .env("XDG_CONFIG_HOME", &xdg_cfg)
        .env("XDG_CACHE_HOME", &xdg_cache)
        .args(["--output", "json", "get", "my_api_key"]);
    get_json.assert().success().stdout(
        predicate::str::contains("my_api_key").and(predicate::str::contains("super_secret")),
    );

    // list
    let mut list = Command::cargo_bin("gman").unwrap();
    list.env("XDG_CONFIG_HOME", &xdg_cfg)
        .env("XDG_CACHE_HOME", &xdg_cache)
        .arg("list");
    list.assert()
        .success()
        .stdout(predicate::str::contains("my_api_key"));

    // update
    let mut update = Command::cargo_bin("gman").unwrap();
    update
        .env("XDG_CONFIG_HOME", &xdg_cfg)
        .env("XDG_CACHE_HOME", &xdg_cache)
        .stdin(Stdio::piped())
        .args(["update", "my_api_key"]);
    let mut child = update.spawn().unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"new_val\n")
        .unwrap();
    let upd_out = child.wait_with_output().unwrap();
    assert!(upd_out.status.success());

    // get again
    let mut get2 = Command::cargo_bin("gman").unwrap();
    get2.env("XDG_CONFIG_HOME", &xdg_cfg)
        .env("XDG_CACHE_HOME", &xdg_cache)
        .args(["get", "my_api_key"]);
    get2.assert()
        .success()
        .stdout(predicate::str::contains("new_val"));

    // delete
    let mut del = Command::cargo_bin("gman").unwrap();
    del.env("XDG_CONFIG_HOME", &xdg_cfg)
        .env("XDG_CACHE_HOME", &xdg_cache)
        .args(["delete", "my_api_key"]);
    del.assert().success();

    // get should now fail
    let mut get_missing = Command::cargo_bin("gman").unwrap();
    get_missing
        .env("XDG_CONFIG_HOME", &xdg_cfg)
        .env("XDG_CACHE_HOME", &xdg_cache)
        .args(["get", "my_api_key"]);
    get_missing.assert().failure();
}

#[test]
fn cli_wrap_dry_run_env_injection() {
    let (td, xdg_cfg, xdg_cache) = setup_env();
    let pw_file = td.path().join("pw.txt");
    fs::write(&pw_file, b"pw\n").unwrap();
    write_yaml_config(&xdg_cfg, &pw_file, Some("echo"));

    // Add the secret so the profile can read it
    let mut add = Command::cargo_bin("gman").unwrap();
    add.env("XDG_CONFIG_HOME", &xdg_cfg)
        .env("XDG_CACHE_HOME", &xdg_cache)
        .stdin(Stdio::piped())
        .args(["add", "api_key"]);
    let mut child = add.spawn().unwrap();
    use std::io::Write as _;
    child.stdin.as_mut().unwrap().write_all(b"value\n").unwrap();
    let add_out = child.wait_with_output().unwrap();
    assert!(add_out.status.success());

    // Dry-run wrapping: prints preview command
    let mut wrap = Command::cargo_bin("gman").unwrap();
    wrap.env("XDG_CONFIG_HOME", &xdg_cfg)
        .env("XDG_CACHE_HOME", &xdg_cache)
        .arg("--dry-run")
        .args(["echo", "hello"]);
    wrap.assert().success().stdout(
        predicate::str::contains("Command to be executed:").or(predicate::str::contains("echo")),
    );
}
