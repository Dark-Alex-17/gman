use crate::command::preview_command;
use anyhow::{Context, Result, anyhow};
use heck::ToSnakeCase;
use log::{debug, error};
use regex::Regex;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use gman::config::{Config, RunConfig};
use gman::providers::SecretProvider;

const ARG_FORMAT_PLACEHOLDER_KEY: &str = "{{key}}";
const ARG_FORMAT_PLACEHOLDER_VALUE: &str = "{{value}}";
pub fn wrap_and_run_command(
    secrets_provider: Box<dyn SecretProvider>,
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
        configs.iter().filter(|c| c.name.is_some()).find(|c| {
            c.name.as_ref().expect("failed to unwrap run config name") == run_config_profile_name
        })
    });
    if let Some(run_cfg) = run_config_opt {
        let secrets_result = run_cfg
            .secrets
            .as_ref()
            .expect("no secrets configured for run profile")
            .iter()
            .map(|key| {
                let secret_name = key.to_snake_case().to_uppercase();
                debug!(
                    "Retrieving secret '{secret_name}' for run profile '{}'",
                    run_config_profile_name
                );
                secrets_provider
                    .get_secret(config, key.to_snake_case().to_uppercase().as_str())
                    .ok()
                    .map_or_else(
                        || {
                            debug!("Failed to fetch secret '{secret_name}' from secret provider");
                            (
                                key.to_uppercase(),
                                Err(anyhow!(
                                    "Failed to fetch secret '{secret_name}' from secret provider"
                                )),
                            )
                        },
                        |value| {
                            if dry_run {
                                (key.to_uppercase(), Ok("*****".into()))
                            } else {
                                (key.to_uppercase(), Ok(value))
                            }
                        },
                    )
            });
        let err = secrets_result
            .clone()
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
            .map(|(k, r)| (k, r.unwrap()))
            .collect::<HashMap<_, _>>();
        let mut cmd_def = Command::new(prog);
        if run_cfg.flag.is_some() {
            let args = parse_args(args, run_cfg, secrets.clone(), dry_run)?;
            run_cmd(cmd_def.args(&args), dry_run)?;
        } else if run_cfg.files.is_some() {
            let injected_files = generate_files_secret_injections(secrets.clone(), run_cfg)
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
                            fs::write(file, original_content)                                        .with_context(|| format!("failed to restore original content to file '{}' after injection failure: {}", file.display(), e))?;
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
                            fs::write(file, original_content)                                        .with_context(|| format!("failed to restore original content to file '{}' after command execution failure: {}", file.display(), e))?;
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
    secrets: HashMap<String, String>,
    run_config: &RunConfig,
) -> Result<Vec<(&PathBuf, String, String)>> {
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
                .get(&caps[1].to_snake_case().to_uppercase())
                .map(|s| s.as_str())
                .unwrap_or(&caps[0])
                .to_string()
        });
        results.push((file, original_content.to_string(), new_content.to_string()));
    }
    Ok(results)
}
pub fn run_cmd(cmd: &mut Command, dry_run: bool) -> Result<()> {
    if dry_run {
        eprintln!("Command to be executed: {}", preview_command(cmd));
    } else {
        cmd.status()
            .with_context(|| format!("failed to execute command '{:?}'", cmd))?;
    }
    Ok(())
}
pub fn parse_args(
    args: &[OsString],
    run_config: &RunConfig,
    secrets: HashMap<String, String>,
    dry_run: bool,
) -> Result<Vec<OsString>> {
    let args = args.to_vec();
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
    let mut args = args.to_vec();
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
