use crate::command::preview_command;
use anyhow::{anyhow, Context, Result};
use clap_complete::CompletionCandidate;
use futures::future::join_all;
use gman::config::{load_config, Config, RunConfig};
use log::{debug, error};
use regex::Regex;
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tokio::runtime::Handle;

const ARG_FORMAT_PLACEHOLDER_KEY: &str = "{{key}}";
const ARG_FORMAT_PLACEHOLDER_VALUE: &str = "{{value}}";

pub async fn wrap_and_run_command(
    provider: Option<String>,
    config: &Config,
    tokens: Vec<OsString>,
    profile_name: Option<String>,
    dry_run: bool,
) -> Result<()> {
    let (prog, args) = tokens
        .split_first()
        .with_context(|| "need a command to run")?;
    let run_config_profile_name = if let Some(ref profile_name) = profile_name {
        profile_name.as_str()
    } else {
        prog.to_str()
            .ok_or_else(|| anyhow!("failed to convert program name to string"))?
    };
    let run_config_opt = config.run_configs.as_ref().and_then(|configs| {
        configs
            .iter()
            .find(|c| c.name.as_deref() == Some(run_config_profile_name))
    });
    if let Some(run_cfg) = run_config_opt {
        let mut provider_config =
            config.extract_provider_config(provider.or(run_cfg.provider.clone()))?;
        let secrets_provider = provider_config.extract_provider();
        let secrets_result_futures = run_cfg
            .secrets
            .as_ref()
            .ok_or_else(|| {
                anyhow!("No secrets configured for run profile '{run_config_profile_name}'")
            })?
            .iter()
            .map(async |key| {
                debug!(
                    "Retrieving secret '{key}' for run profile '{}'",
                    run_config_profile_name
                );
                secrets_provider.get_secret(key).await.ok().map_or_else(
                    || {
                        debug!("Failed to fetch secret '{key}' from secret provider");
                        (
                            key,
                            Err(anyhow!(
                                "Failed to fetch secret '{key}' from secret provider"
                            )),
                        )
                    },
                    |value| {
                        if dry_run {
                            (key, Ok("*****".into()))
                        } else {
                            (key, Ok(value))
                        }
                    },
                )
            });
        let secrets_result = join_all(secrets_result_futures).await;
        let err = secrets_result
            .iter()
            .filter(|(_, r)| r.is_err())
            .collect::<Vec<_>>();
        if !err.is_empty() {
            return Err(anyhow!(
                "Failed to fetch {} secrets from secret provider. {}",
                err.len(),
                err.iter()
                    .map(|(k, _)| format!("\n'{}'", k))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        let secrets = secrets_result
            .into_iter()
            .map(|(k, r)| (k.as_str(), r.unwrap()))
            .collect::<HashMap<_, _>>();
        let mut cmd_def = Command::new(prog);
        if run_cfg.flag.is_some() {
            let args = parse_args(args, run_cfg, secrets.clone(), dry_run)?;
            run_cmd(cmd_def.args(&args), dry_run)?;
        } else if run_cfg.files.is_some() {
            let injected_files = generate_files_secret_injections(secrets, run_cfg)
                .with_context(|| "failed to inject secrets into files")?;
            for (file, original_content, new_content) in &injected_files {
                if dry_run {
                    println!("Would inject secrets into file '{}'", file.display());
                } else {
                    match fs::write(file, new_content).with_context(|| {
                        format!(
                            "failed to write injected content to file '{}'",
                            file.display()
                        )
                    }) {
                        Ok(_) => {
                            debug!("Injected secrets into file '{}'", file.display());
                        }
                        Err(e) => {
                            error!(
                                "Failed to inject secrets into file '{}': {}",
                                file.display(),
                                e
                            );
                            debug!("Restoring original content to file '{}'", file.display());
                            fs::write(file, original_content).with_context(|| format!("failed to restore original content to file '{}' after injection failure: {}", file.display(), e))?;
                            return Err(e);
                        }
                    }
                }
            }
            match run_cmd(cmd_def.args(args), dry_run) {
                Ok(_) => {
                    if !dry_run {
                        for (file, original_content, _) in &injected_files {
                            debug!("Restoring original content to file '{}'", file.display());
                            fs::write(file, original_content).with_context(|| {
                                format!(
                                    "failed to restore original content to file '{}'",
                                    file.display()
                                )
                            })?;
                        }
                    }
                }
                Err(e) => {
                    if !dry_run {
                        for (file, original_content, _) in &injected_files {
                            error!(
                                "Command execution failed, restoring original content to file '{}'",
                                file.display()
                            );
                            debug!("Restoring original content to file '{}'", file.display());
                            fs::write(file, original_content).with_context(|| format!("failed to restore original content to file '{}' after command execution failure: {}", file.display(), e))?;
                        }
                    }
                    return Err(e);
                }
            }
        } else {
            run_cmd(cmd_def.args(args).envs(secrets), dry_run)?;
        }
    } else {
        debug!("No run profile found for '{run_config_profile_name}'");
        return Err(anyhow!(
            "No run profile found for '{run_config_profile_name}'"
        ));
    }
    Ok(())
}

fn generate_files_secret_injections(
    secrets: HashMap<&str, String>,
    run_config: &RunConfig,
) -> Result<Vec<(PathBuf, String, String)>> {
    let re = Regex::new(r"\{\{(.+)}}")?;
    let mut results = Vec::new();
    for file in run_config
        .files
        .as_ref()
        .with_context(|| "no files configured for run profile")?
    {
        debug!(
            "Generating file with injected secrets for '{}'",
            file.display()
        );
        let original_content = fs::read_to_string(file).with_context(|| {
            format!(
                "failed to read file for secrets injection: '{}'",
                file.display()
            )
        })?;
        let new_content = re.replace_all(&original_content, |caps: &regex::Captures| {
            secrets
                .get(&caps[1])
                .map(|s| s.as_str())
                .unwrap_or(&caps[0])
                .to_string()
        });
        results.push((
            file.into(),
            original_content.to_string(),
            new_content.to_string(),
        ));
    }
    Ok(results)
}

pub fn run_cmd(cmd: &mut Command, dry_run: bool) -> Result<()> {
    if dry_run {
        println!("Command to be executed: {}", preview_command(cmd));
    } else {
        cmd.status()
            .with_context(|| format!("failed to execute command '{:?}'", cmd))?;
    }
    Ok(())
}

pub fn parse_args(
    args: &[OsString],
    run_config: &RunConfig,
    secrets: HashMap<&str, String>,
    dry_run: bool,
) -> Result<Vec<OsString>> {
    let mut args = args.to_vec();
    let flag = run_config
        .flag
        .as_ref()
        .ok_or_else(|| anyhow!("flag must be set if arg_format is set"))?;
    let flag_position = run_config
        .flag_position
        .ok_or_else(|| anyhow!("flag_position must be set if flag is set"))?;
    let arg_format = run_config
        .arg_format
        .as_ref()
        .ok_or_else(|| anyhow!("arg_format must be set if flag is set"))?;
    if flag_position > args.len() {
        secrets.iter().for_each(|(k, v)| {
            let v = if dry_run { "*****" } else { v };
            args.push(OsString::from(flag));
            args.push(OsString::from(
                arg_format
                    .replace(ARG_FORMAT_PLACEHOLDER_KEY, k)
                    .replace(ARG_FORMAT_PLACEHOLDER_VALUE, v),
            ));
        })
    } else {
        secrets.iter().for_each(|(k, v)| {
            let v = if dry_run { "*****" } else { v };
            args.insert(
                flag_position,
                OsString::from(
                    arg_format
                        .replace(ARG_FORMAT_PLACEHOLDER_KEY, k)
                        .replace(ARG_FORMAT_PLACEHOLDER_VALUE, v),
                ),
            );
            args.insert(flag_position, OsString::from(flag));
        })
    }
    Ok(args)
}

pub fn run_config_completer(current: &OsStr) -> Vec<CompletionCandidate> {
    let cur = current.to_string_lossy();
    match load_config(true) {
        Ok(config) => {
            if let Some(run_configs) = config.run_configs {
                run_configs
                    .iter()
                    .filter(|rc| {
                        rc.name
                            .as_ref()
                            .expect("run config has no name")
                            .starts_with(&*cur)
                    })
                    .map(|rc| {
                        CompletionCandidate::new(rc.name.as_ref().expect("run config has no name"))
                    })
                    .collect()
            } else {
                vec![]
            }
        }
        Err(_) => vec![],
    }
}

pub fn provider_completer(current: &OsStr) -> Vec<CompletionCandidate> {
    let cur = current.to_string_lossy();
    match load_config(true) {
        Ok(config) => config
            .providers
            .iter()
            .filter(|pc| {
                pc.name
                    .as_ref()
                    .expect("run config has no name")
                    .starts_with(&*cur)
            })
            .map(|pc| CompletionCandidate::new(pc.name.as_ref().expect("provider has no name")))
            .collect(),
        Err(_) => vec![],
    }
}

pub fn secrets_completer(current: &OsStr) -> Vec<CompletionCandidate> {
    let cur = current.to_string_lossy();
    match load_config(true) {
        Ok(config) => {
            let mut provider_config = match config.extract_provider_config(None) {
                Ok(pc) => pc,
                Err(_) => return vec![],
            };
            let secrets_provider = provider_config.extract_provider();
            let h = Handle::current();
            tokio::task::block_in_place(|| h.block_on(secrets_provider.list_secrets()))
                .unwrap_or_default()
                .into_iter()
                .filter(|s| s.starts_with(&*cur))
                .map(CompletionCandidate::new)
                .collect()
        }
        Err(_) => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::generate_files_secret_injections;
    use gman::config::{Config, RunConfig};
    use pretty_assertions::{assert_eq, assert_str_eq};
    use serial_test::serial;
    use std::collections::HashMap;
    use std::env as std_env;
    use std::ffi::OsString;
    use tempfile::tempdir;

    #[test]
    fn test_generate_files_secret_injections() {
        let mut secrets = HashMap::new();
        secrets.insert("testing/SOME-secret", "value1".to_string());
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "{{testing/SOME-secret}}").unwrap();

        let run_config = RunConfig {
            name: Some("test".to_string()),
            provider: None,
            secrets: Some(vec!["testing/SOME-secret".to_string()]),
            files: Some(vec![file_path.clone()]),
            flag: None,
            flag_position: None,
            arg_format: None,
        };

        let result = generate_files_secret_injections(secrets, &run_config).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, file_path);
        assert_str_eq!(result[0].1, "{{testing/SOME-secret}}");
        assert_str_eq!(result[0].2, "value1");
    }

    #[test]
    fn test_parse_args_insert_and_append() {
        let run_config = RunConfig {
            name: Some("docker".into()),
            provider: None,
            secrets: Some(vec!["api_key".into()]),
            files: None,
            flag: Some("-e".into()),
            flag_position: Some(1),
            arg_format: Some("{{key}}={{value}}".into()),
        };
        let mut secrets = HashMap::new();
        secrets.insert("API_KEY", "xyz".into());

        // Insert at position
        let args = vec![OsString::from("run"), OsString::from("image")];
        let out = parse_args(&args, &run_config, secrets.clone(), true).unwrap();
        assert_eq!(
            out,
            vec!["run", "-e", "API_KEY=*****", "image"]
                .into_iter()
                .map(OsString::from)
                .collect::<Vec<_>>()
        );

        // Append when position beyond len
        let run_config2 = RunConfig {
            flag_position: Some(99),
            ..run_config.clone()
        };
        let out2 = parse_args(&args, &run_config2, secrets, true).unwrap();
        assert_eq!(
            out2,
            vec!["run", "image", "-e", "API_KEY=*****"]
                .into_iter()
                .map(OsString::from)
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn test_wrap_and_run_command_no_profile() {
        let cfg = Config::default();
        let tokens = vec![OsString::from("echo"), OsString::from("hi")];
        let err = wrap_and_run_command(None, &cfg, tokens, None, true)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("No run profile found"));
    }

    #[tokio::test]
    async fn test_wrap_and_run_command_env_injection_dry_run() {
        // Create a config with a matching run profile for command "echo"
        let run_cfg = RunConfig {
            name: Some("echo".into()),
            provider: None,
            secrets: Some(vec!["api_key".into()]),
            files: None,
            flag: None,
            flag_position: None,
            arg_format: None,
        };
        let cfg = Config {
            run_configs: Some(vec![run_cfg]),
            ..Config::default()
        };

        let tokens = vec![OsString::from("echo"), OsString::from("hello")];
        let err = wrap_and_run_command(None, &cfg, tokens, None, true)
            .await
            .expect_err("expected failed secret resolution in dry_run");
        assert!(err.to_string().contains("Failed to fetch"));
    }

    #[test]
    #[serial]
    fn test_run_config_completer_filters_by_prefix() {
        let td = tempdir().unwrap();
        let xdg = td.path().join("xdg");
        let app_dir = xdg.join("gman");
        fs::create_dir_all(&app_dir).unwrap();
        unsafe { std_env::set_var("XDG_CONFIG_HOME", &xdg) };

        let yaml = indoc::indoc! {
            "---
            default_provider: local
            providers:
              - name: local
                type: local
            run_configs:
              - name: echo
                secrets: [API_KEY]
              - name: docker
                secrets: [DB_PASSWORD]
              - name: aws
                secrets: [AWS_ACCESS_KEY_ID]
            "
        };
        fs::write(app_dir.join("config.yml"), yaml).unwrap();

        let out = run_config_completer(OsStr::new("do"));
        assert_eq!(out.len(), 1);
        // Compare via debug string to avoid depending on crate internals
        let rendered = format!("{:?}", &out[0]);
        assert!(rendered.contains("docker"), "got: {}", rendered);

        unsafe { std_env::remove_var("XDG_CONFIG_HOME") };
    }

    #[test]
    #[serial]
    fn test_provider_completer_lists_matching_providers() {
        let td = tempdir().unwrap();
        let xdg = td.path().join("xdg");
        let app_dir = xdg.join("gman");
        fs::create_dir_all(&app_dir).unwrap();
        unsafe { std_env::set_var("XDG_CONFIG_HOME", &xdg) };

        let yaml = indoc::indoc! {
            "---
            default_provider: local
            providers:
              - name: local
                type: local
              - name: prod
                type: local
            run_configs:
              - name: echo
                secrets: [API_KEY]
            "
        };
        fs::write(app_dir.join("config.yml"), yaml).unwrap();

        // Prefix 'p' should match only 'prod'
        let out = provider_completer(OsStr::new("p"));
        assert_eq!(out.len(), 1);
        let rendered = format!("{:?}", &out[0]);
        assert!(rendered.contains("prod"), "got: {}", rendered);

        // Empty prefix returns at least both providers
        let out_all = provider_completer(OsStr::new(""));
        assert!(out_all.len() >= 2);

        unsafe { std_env::remove_var("XDG_CONFIG_HOME") };
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_secrets_completer_filters_keys_by_prefix() {
        let td = tempdir().unwrap();
        let xdg = td.path().join("xdg");
        let app_dir = xdg.join("gman");
        fs::create_dir_all(&app_dir).unwrap();
        unsafe { std_env::set_var("XDG_CONFIG_HOME", &xdg) };

        let yaml = indoc::indoc! {
            "---
            default_provider: local
            providers:
              - name: local
                type: local
            run_configs:
              - name: echo
                secrets: [API_KEY]
            "
        };
        fs::write(app_dir.join("config.yml"), yaml).unwrap();

        // Seed a minimal vault with keys (values are irrelevant for listing)
        let vault_yaml = indoc::indoc! {
            "---
            API_KEY: dummy
            DB_PASSWORD: dummy
            AWS_ACCESS_KEY_ID: dummy
            "
        };
        fs::write(app_dir.join("vault.yml"), vault_yaml).unwrap();

        let out = secrets_completer(OsStr::new("AWS"));
        assert_eq!(out.len(), 1);
        let rendered = format!("{:?}", &out[0]);
        assert!(rendered.contains("AWS_ACCESS_KEY_ID"), "got: {}", rendered);

        let out2 = secrets_completer(OsStr::new("DB_"));
        assert_eq!(out2.len(), 1);
        let rendered2 = format!("{:?}", &out2[0]);
        assert!(rendered2.contains("DB_PASSWORD"), "got: {}", rendered2);

        unsafe { std_env::remove_var("XDG_CONFIG_HOME") };
    }
}
