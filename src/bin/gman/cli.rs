use crate::command::preview_command;
use anyhow::{Context, Result, anyhow};
use futures::future::join_all;
use gman::config::{Config, RunConfig};
use gman::providers::SecretProvider;
use log::{debug, error};
use regex::Regex;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const ARG_FORMAT_PLACEHOLDER_KEY: &str = "{{key}}";
const ARG_FORMAT_PLACEHOLDER_VALUE: &str = "{{value}}";

pub async fn wrap_and_run_command(
    secrets_provider: &mut dyn SecretProvider,
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
    let re = Regex::new(r"\{\{([A-Za-z0-9_]+)\}\}")?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::generate_files_secret_injections;
    use gman::config::{Config, RunConfig};
    use pretty_assertions::{assert_eq, assert_str_eq};
    use std::collections::HashMap;
    use std::ffi::OsString;

    struct DummyProvider;
    #[async_trait::async_trait]
    impl SecretProvider for DummyProvider {
        fn name(&self) -> &'static str {
            "Dummy"
        }
        async fn get_secret(&self, key: &str) -> Result<String> {
            Ok(format!("{}_VAL", key))
        }
        async fn set_secret(&self, _key: &str, _value: &str) -> Result<()> {
            Ok(())
        }
        async fn delete_secret(&self, _key: &str) -> Result<()> {
            Ok(())
        }
        async fn sync(&mut self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_generate_files_secret_injections() {
        let mut secrets = HashMap::new();
        secrets.insert("SECRET1", "value1".to_string());
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "{{SECRET1}}").unwrap();

        let run_config = RunConfig {
            name: Some("test".to_string()),
            secrets: Some(vec!["SECRET1".to_string()]),
            files: Some(vec![file_path.clone()]),
            flag: None,
            flag_position: None,
            arg_format: None,
        };

        let result = generate_files_secret_injections(secrets, &run_config).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, file_path);
        assert_str_eq!(result[0].1, "{{SECRET1}}");
        assert_str_eq!(result[0].2, "value1");
    }

    #[test]
    fn test_parse_args_insert_and_append() {
        let run_config = RunConfig {
            name: Some("docker".into()),
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
        let mut dummy = DummyProvider;
        let prov: &mut dyn SecretProvider = &mut dummy;
        let tokens = vec![OsString::from("echo"), OsString::from("hi")];
        let err = wrap_and_run_command(prov, &cfg, tokens, None, true)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("No run profile found"));
    }

    #[tokio::test]
    async fn test_wrap_and_run_command_env_injection_dry_run() {
        // Create a config with a matching run profile for command "echo"
        let run_cfg = RunConfig {
            name: Some("echo".into()),
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
        let mut dummy = DummyProvider;
        let prov: &mut dyn SecretProvider = &mut dummy;

        // Capture stderr for dry_run preview
        let tokens = vec![OsString::from("echo"), OsString::from("hello")];
        // Best-effort: ensure function does not error under dry_run
        let res = wrap_and_run_command(prov, &cfg, tokens, None, true).await;
        assert!(res.is_ok());
        // Not asserting output text to keep test platform-agnostic
    }
}
