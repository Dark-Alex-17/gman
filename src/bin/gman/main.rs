use crate::cli::run_config_completer;
use crate::cli::secrets_completer;
use anyhow::{Context, Result};
use clap::Subcommand;
use clap::{
	crate_authors, crate_description, crate_name, crate_version, CommandFactory, Parser, ValueEnum,
};
use clap_complete::{ArgValueCompleter, CompleteEnv};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, LeaveAlternateScreen};
use gman::config::{get_config_file_path, load_config, Config};
use std::ffi::OsString;
use std::io::{self, IsTerminal, Read, Write};
use std::panic::PanicHookInfo;

use crate::cli::wrap_and_run_command;
use crate::utils::persist_config_file;
use dialoguer::Editor;
use std::panic;
use std::process::exit;
use validator::Validate;

mod cli;
mod command;
mod utils;

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Parser)]
#[command(
	name = crate_name!(),
	author = crate_authors!(),
	version = crate_version!(),
	about = crate_description!(),
	arg_required_else_help = true,
	help_template = "\
{before-help}{name} {version}
{author-with-newline}
{about-with-newline}
{usage-heading} {usage}

{all-args}{after-help}"
)]
struct Cli {
    /// Specify the output format
    #[arg(short, long, global = true, value_enum, env = "GMAN_OUTPUT")]
    output: Option<OutputFormat>,

    /// Specify the secret provider to use (defaults to 'default_provider' in config (usually 'local'))
    #[arg(long, global = true, env = "GMAN_PROVIDER", value_parser = ["local", "aws_secrets_manager", "azure_key_vault", "gcp_secret_manager", "gopass"])]
    provider: Option<String>,

    /// Specify a run profile to use when wrapping a command
    #[arg(long, short, add = ArgValueCompleter::new(run_config_completer))]
    profile: Option<String>,

    /// Output the command that will be run instead of executing it
    #[arg(long, global = true)]
    dry_run: bool,

    /// Print the log file path and exit
    #[arg(long, global = true)]
    show_log_path: bool,

    /// Print the config file path and exit
    #[arg(long, global = true)]
    show_config_path: bool,

    #[command(subcommand)]
    command: Option<Commands>,
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
				#[arg(add = ArgValueCompleter::new(secrets_completer))]
        name: String,
    },

    /// Update an existing secret in the configured secret provider (if supported by the provider)
    /// If a provider does not support updating secrets, this command will return an error.
    Update {
        /// Name of the secret to update
				#[arg(add = ArgValueCompleter::new(secrets_completer))]
        name: String,
    },

    /// Delete a secret from the configured secret provider
    Delete {
        /// Name of the secret to delete
				#[arg(add = ArgValueCompleter::new(secrets_completer))]
        name: String,
    },

    /// List all secrets stored in the configured secret provider (if supported by the provider)
    /// If a provider does not support listing secrets, this command will return an error.
    List {},

    /// Sync secrets with remote storage (if supported by the provider)
    Sync {},

    /// Open and edit the config file in the default text editor
    Config {},

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

#[tokio::main]
async fn main() -> Result<()> {
    if let Err(e) = log4rs::init_config(utils::init_logging_config()) {
        eprintln!("Failed to initialize logging: {e}");
    }
    panic::set_hook(Box::new(|info| {
        panic_hook(info);
    }));
    CompleteEnv::with_factory(Cli::command).complete();
    let cli = Cli::parse();

    if cli.show_log_path {
        println!("{}", utils::get_log_path().display());
        return Ok(());
    }
    if cli.show_config_path {
        println!("{}", get_config_file_path()?.display());
        return Ok(());
    }
    if cli.command.is_none() {
        Cli::command().print_help()?;
        println!();
        exit(1);
    }

    let config = load_config()?;
    let mut provider_config = config.extract_provider_config(cli.provider.clone())?;
    let secrets_provider = provider_config.extract_provider();

    match cli.command.with_context(|| "no command provided")? {
        Commands::Add { name } => {
            let plaintext =
                read_all_stdin().with_context(|| "unable to read plaintext from stdin")?;
            secrets_provider
                .set_secret(&name, plaintext.trim_end())
                .await
                .map(|_| match cli.output {
                    Some(_) => (),
                    None => println!("✓ Secret '{name}' added to the vault."),
                })?;
        }
        Commands::Get { name } => {
            secrets_provider
                .get_secret(&name)
                .await
                .map(|secret| match cli.output {
                    Some(OutputFormat::Json) => {
                        let json_output = serde_json::json!({
                            name: secret
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
            secrets_provider
                .update_secret(&name, plaintext.trim_end())
                .await
                .map(|_| match cli.output {
                    Some(_) => (),
                    None => println!("✓ Secret '{name}' updated in the vault."),
                })?;
        }
        Commands::Delete { name } => {
            secrets_provider.delete_secret(&name).await.map(|_| {
                if cli.output.is_none() {
                    println!("✓ Secret '{name}' deleted from the vault.")
                }
            })?;
        }
        Commands::List {} => {
            let secrets = secrets_provider.list_secrets().await?;
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
        Commands::Config {} => {
            let config_yaml = serde_yaml::to_string(&config)
                .with_context(|| "failed to serialize existing configuration")?;
            let new_config = Editor::new()
                .edit(&config_yaml)
                .with_context(|| "unable to process user changes")?;
            if new_config.is_none() {
                println!("✗ No changes made to configuration");
                return Ok(());
            }

            let new_config = new_config.unwrap();
            let new_config: Config = serde_yaml::from_str(&new_config)
                .with_context(|| "failed to parse updated configuration")?;
            new_config
                .validate()
                .with_context(|| "updated configuration is invalid")?;
            persist_config_file(&new_config)?;
            println!("✓ Configuration updated successfully");
        }
        Commands::Sync {} => {
            secrets_provider.sync().await.map(|_| {
                if cli.output.is_none() {
                    println!("✓ Secrets synchronized with remote")
                }
            })?;
        }
        Commands::External(tokens) => {
            wrap_and_run_command(cli.provider, &config, tokens, cli.profile, cli.dry_run).await?;
        }
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            let bin_name = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, bin_name, &mut io::stdout());
        }
    }

    Ok(())
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
