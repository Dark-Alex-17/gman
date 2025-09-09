use clap::{
    CommandFactory, Parser, ValueEnum, crate_authors, crate_description, crate_name, crate_version,
};
use std::collections::HashMap;
use std::ffi::OsString;

use crate::command::preview_command;
use anyhow::{Context, Result, anyhow};
use clap::Subcommand;
use crossterm::execute;
use crossterm::terminal::{LeaveAlternateScreen, disable_raw_mode};
use gman::config::{Config, RunConfig};
use gman::providers::local::LocalProvider;
use gman::providers::{SecretProvider, SupportedProvider};
use heck::ToSnakeCase;
use log::debug;
use std::io::{self, IsTerminal, Read, Write};
use std::panic;
use std::panic::PanicHookInfo;
use std::process::Command;
use validator::Validate;

mod command;
mod utils;

const ARG_FORMAT_PLACEHOLDER_KEY: &str = "{key}";
const ARG_FORMAT_PLACEHOLDER_VALUE: &str = "{value}";

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, ValueEnum)]
#[clap(rename_all = "lower")]
pub enum ProviderKind {
    Local,
}

impl From<ProviderKind> for SupportedProvider {
    fn from(k: ProviderKind) -> Self {
        match k {
            ProviderKind::Local => SupportedProvider::Local(LocalProvider::default()),
        }
    }
}

#[derive(Debug, Parser)]
#[command(
	name = crate_name!(),
	author = crate_authors!(),
	version = crate_version!(),
	about = crate_description!(),
	help_template = "\
{before-help}{name} {version}
{author-with-newline}
{about-with-newline}
{usage-heading} {usage}

{all-args}{after-help}"
)]
struct Cli {
    /// Specify the output format
    #[arg(short, long, value_enum)]
    output: Option<OutputFormat>,

    /// Specify the secret provider to use (defaults to 'provider' in config or 'local')
    #[arg(long, value_enum)]
    provider: Option<ProviderKind>,

    /// Specify a run profile to use when wrapping a command
    #[arg(long)]
    profile: Option<String>,

    /// Output the command that will be run instead of executing it
    #[arg(long)]
    dry_run: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Clone, Debug)]
enum Commands {
    /// Add a secret to the configured secret provider
    Add {
        /// Name of the secret to store
        name: String,
    },

    /// Decrypt a secret and print the plaintext
    Get {
        /// Name of the secret to retrieve
        name: String,
    },

    /// Update an existing secret in the configured secret provider
    Update {
        /// Name of the secret to update
        name: String,
    },

    /// Delete a secret from the configured secret provider
    Delete {
        /// Name of the secret to delete
        name: String,
    },

    /// List all secrets stored in the configured secret provider (if supported by the provider)
    /// If a provider does not support listing secrets, this command will return an error.
    List {},

    /// Sync secrets with remote storage (if supported by the provider)
    Sync {},

    /// Wrap the provided command and supply it with secrets as environment variables or as
    /// configured in a corresponding run profile
    #[command(external_subcommand)]
    External(Vec<OsString>),

    /// Generate shell completion scripts
    Completions {
        /// The shell to generate the script for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

fn main() -> Result<()> {
    log4rs::init_config(utils::init_logging_config())?;
    panic::set_hook(Box::new(|info| {
        panic_hook(info);
    }));
    let cli = Cli::parse();
    let mut config = load_config(&cli)?;
    let secrets_provider = config.extract_provider();

    match cli.command {
        Commands::Add { name } => {
            let plaintext =
                read_all_stdin().with_context(|| "unable to read plaintext from stdin")?;
            let snake_case_name = name.to_snake_case();
            secrets_provider
                .set_secret(&config, &snake_case_name, plaintext.trim_end())
                .map(|_| match cli.output {
                    Some(_) => (),
                    None => println!("✓ Secret '{snake_case_name}' added to the vault."),
                })?;
        }
        Commands::Get { name } => {
            let snake_case_name = name.to_snake_case();
            secrets_provider
                .get_secret(&config, &snake_case_name)
                .map(|secret| match cli.output {
                    Some(OutputFormat::Json) => {
                        let json_output = serde_json::json!({
                            snake_case_name: secret
                        });
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json_output)
                                .expect("failed to serialize secret to JSON")
                        );
                    }
                    Some(OutputFormat::Text) | None => {
                        println!("{}", secret);
                    }
                })?;
        }
        Commands::Update { name } => {
            let plaintext =
                read_all_stdin().with_context(|| "unable to read plaintext from stdin")?;
            let snake_case_name = name.to_snake_case();
            secrets_provider
                .update_secret(&config, &snake_case_name, plaintext.trim_end())
                .map(|_| match cli.output {
                    Some(_) => (),
                    None => println!("✓ Secret '{snake_case_name}' updated in the vault."),
                })?;
        }
        Commands::Delete { name } => {
            let snake_case_name = name.to_snake_case();
            secrets_provider
                .delete_secret(&snake_case_name)
                .map(|_| match cli.output {
                    None => println!("✓ Secret '{snake_case_name}' deleted from the vault."),
                    Some(_) => (),
                })?;
        }
        Commands::List {} => {
            let secrets = secrets_provider.list_secrets()?;
            if secrets.is_empty() {
                match cli.output {
                    Some(OutputFormat::Json) => {
                        let json_output = serde_json::json!([]);
                        println!("{}", serde_json::to_string_pretty(&json_output)?);
                    }
                    Some(OutputFormat::Text) => (),
                    None => println!("The vault is empty."),
                }
            } else {
                match cli.output {
                    Some(OutputFormat::Json) => {
                        let json_output = serde_json::json!(secrets);
                        println!("{}", serde_json::to_string_pretty(&json_output)?);
                        return Ok(());
                    }
                    Some(OutputFormat::Text) | None => {
                        for key in &secrets {
                            println!("{}", key);
                        }
                    }
                }
            }
        }
        Commands::Sync {} => {
            secrets_provider
                .sync(&mut config)
                .map(|_| match cli.output {
                    None => println!("✓ Secrets synchronized with remote"),
                    Some(_) => (),
                })?;
        }
        Commands::External(tokens) => {
            wrap_and_run_command(secrets_provider, &config, tokens, cli.profile, cli.dry_run)?;
        }
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            let bin_name = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, bin_name, &mut io::stdout());
        }
    }

    Ok(())
}

fn load_config(cli: &Cli) -> Result<Config> {
    let mut config: Config = confy::load("gman", "config")?;
    config.validate()?;
    if let Some(local_password_file) = Config::local_provider_password_file() {
        config.password_file = Some(local_password_file);
    }

    if let Some(provider_kind) = &cli.provider {
        let provider: SupportedProvider = provider_kind.clone().into();
        config.provider = provider.into();
    }

    Ok(config)
}

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
        let secrets_result =
            run_cfg
                .secrets
                .as_ref()
                .expect("no secrets configured for run profile")
                .iter()
                .map(|key| {
                    let secret_name = key.to_snake_case();
                    debug!(
                        "Retrieving secret '{secret_name}' for run profile '{}'",
                        run_config_profile_name
                    );
                    secrets_provider
                    .get_secret(&config, key.to_snake_case().as_str())
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
                        |value| if dry_run {
													(key.to_uppercase(), Ok("*****".into()))
												} else {
													(key.to_uppercase(), Ok(value))
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
            run_cmd(&mut cmd_def.args(&args), dry_run)?;
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

fn run_cmd(cmd: &mut Command, dry_run: bool) -> Result<()> {
    if dry_run {
        eprintln!("Command to be executed: {}", preview_command(cmd));
    } else {
        cmd.status()
            .with_context(|| format!("failed to execute command '{:?}'", cmd))?;
    }
    Ok(())
}

fn parse_args(
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

fn read_all_stdin() -> Result<String> {
    if io::stdin().is_terminal() {
        #[cfg(not(windows))]
        eprintln!("Enter the text to encrypt, then press Ctrl-D twice to finish input");
        #[cfg(windows)]
        eprintln!("Enter the text to encrypt, then press Ctrl-Z to finish input");
        io::stderr().flush()?;
    }
    let mut buf = String::new();
    let stdin_tty = io::stdin().is_terminal();
    let stdout_tty = io::stdout().is_terminal();
    io::stdin().read_to_string(&mut buf)?;

    if stdin_tty && stdout_tty && !buf.ends_with('\n') {
        let mut out = io::stdout().lock();
        out.write_all(b"\n")?;
        out.flush()?;
    }
    Ok(buf)
}

#[cfg(debug_assertions)]
fn panic_hook(info: &PanicHookInfo<'_>) {
    use backtrace::Backtrace;
    use crossterm::style::Print;

    let location = info.location().unwrap();

    let msg = match info.payload().downcast_ref::<&'static str>() {
        Some(s) => *s,
        None => match info.payload().downcast_ref::<String>() {
            Some(s) => &s[..],
            None => "Box<Any>",
        },
    };

    let stacktrace: String = format!("{:?}", Backtrace::new()).replace('\n', "\n\r");

    disable_raw_mode().unwrap();
    execute!(
        io::stdout(),
        LeaveAlternateScreen,
        Print(format!(
            "thread '<unnamed>' panicked at '{msg}', {location}\n\r{stacktrace}"
        )),
    )
    .unwrap();
}

#[cfg(not(debug_assertions))]
fn panic_hook(info: &PanicHookInfo<'_>) {
    use human_panic::{handle_dump, metadata, print_msg};

    let meta = metadata!();
    let file_path = handle_dump(&meta, info);
    disable_raw_mode().unwrap();
    execute!(io::stdout(), LeaveAlternateScreen).unwrap();
    print_msg(file_path, &meta).expect("human-panic: printing error message to console failed");
}
