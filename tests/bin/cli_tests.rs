use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::TempDir;

fn gman_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_gman"))
}

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
    fs::write(app_dir.join("config.yml"), &cfg).unwrap();
    fs::write(app_dir.join("config.yaml"), &cfg).unwrap();
}

fn create_password_file(path: &Path, content: &[u8]) {
    fs::write(path, content).unwrap();
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[test]
#[cfg(unix)]
fn cli_config_no_changes() {
    let (td, xdg_cfg, xdg_cache) = setup_env();
    let pw_file = td.path().join("pw.txt");
    create_password_file(&pw_file, b"pw\n");
    write_yaml_config(&xdg_cfg, &pw_file, None);

    let editor = td.path().join("noop-editor.sh");
    fs::write(&editor, b"#!/bin/sh\nexit 0\n").unwrap();
    let mut perms = fs::metadata(&editor).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&editor, perms).unwrap();

    let mut cmd = Command::new(gman_bin());
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
    create_password_file(&pw_file, b"pw\n");
    write_yaml_config(&xdg_cfg, &pw_file, None);

    let editor = td.path().join("append-run-config.sh");
    // Note: We need a small sleep to ensure the file modification timestamp changes.
    // The dialoguer Editor uses file modification time to detect changes, and on fast
    // systems the edit can complete within the same timestamp granularity.
    let script = r#"#!/bin/sh
FILE="$1"
sleep 0.1
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

    let mut cmd = Command::new(gman_bin());
    cmd.env("XDG_CONFIG_HOME", &xdg_cfg)
        .env("XDG_CACHE_HOME", &xdg_cache)
        .env("EDITOR", &editor)
        .arg("config");

    cmd.assert().success().stdout(predicate::str::contains(
        "Configuration updated successfully",
    ));

    let cfg_path = xdg_cfg.join("gman").join("config.yml");
    let written = fs::read_to_string(&cfg_path).expect("config file readable");
    assert!(written.contains("run_configs:"));
    assert!(written.contains("name: echo"));
}

#[test]
fn cli_shows_help() {
    let (_td, cfg, cache) = setup_env();
    let mut cmd = Command::new(gman_bin());
    cmd.env("XDG_CACHE_HOME", &cache)
        .env("XDG_CONFIG_HOME", &cfg)
        .arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Usage").or(predicate::str::contains("Add")));
}

#[test]
fn cli_add_get_list_update_delete_roundtrip() {
    let (td, xdg_cfg, xdg_cache) = setup_env();
    let pw_file = td.path().join("pw.txt");
    create_password_file(&pw_file, b"testpw\n");
    write_yaml_config(&xdg_cfg, &pw_file, None);

    let mut add = Command::new(gman_bin());
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

    let mut get = Command::new(gman_bin());
    get.env("XDG_CONFIG_HOME", &xdg_cfg)
        .env("XDG_CACHE_HOME", &xdg_cache)
        .args(["get", "my_api_key"]);
    get.assert()
        .success()
        .stdout(predicate::str::contains("super_secret"));

    let mut get_json = Command::new(gman_bin());
    get_json
        .env("XDG_CONFIG_HOME", &xdg_cfg)
        .env("XDG_CACHE_HOME", &xdg_cache)
        .args(["--output", "json", "get", "my_api_key"]);
    get_json.assert().success().stdout(
        predicate::str::contains("my_api_key").and(predicate::str::contains("super_secret")),
    );

    let mut list = Command::new(gman_bin());
    list.env("XDG_CONFIG_HOME", &xdg_cfg)
        .env("XDG_CACHE_HOME", &xdg_cache)
        .arg("list");
    list.assert()
        .success()
        .stdout(predicate::str::contains("my_api_key"));

    let mut update = Command::new(gman_bin());
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

    let mut get2 = Command::new(gman_bin());
    get2.env("XDG_CONFIG_HOME", &xdg_cfg)
        .env("XDG_CACHE_HOME", &xdg_cache)
        .args(["get", "my_api_key"]);
    get2.assert()
        .success()
        .stdout(predicate::str::contains("new_val"));

    let mut del = Command::new(gman_bin());
    del.env("XDG_CONFIG_HOME", &xdg_cfg)
        .env("XDG_CACHE_HOME", &xdg_cache)
        .args(["delete", "my_api_key"]);
    del.assert().success();

    let mut get_missing = Command::new(gman_bin());
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
    create_password_file(&pw_file, b"pw\n");
    write_yaml_config(&xdg_cfg, &pw_file, Some("echo"));

    let mut add = Command::new(gman_bin());
    add.env("XDG_CONFIG_HOME", &xdg_cfg)
        .env("XDG_CACHE_HOME", &xdg_cache)
        .stdin(Stdio::piped())
        .args(["add", "api_key"]);
    let mut child = add.spawn().unwrap();
    use std::io::Write as _;
    child.stdin.as_mut().unwrap().write_all(b"value\n").unwrap();
    let add_out = child.wait_with_output().unwrap();
    assert!(add_out.status.success());

    let mut wrap = Command::new(gman_bin());
    wrap.env("XDG_CONFIG_HOME", &xdg_cfg)
        .env("XDG_CACHE_HOME", &xdg_cache)
        .arg("--dry-run")
        .args(["echo", "hello"]);
    wrap.assert().success().stdout(
        predicate::str::contains("Command to be executed:").or(predicate::str::contains("echo")),
    );
}
