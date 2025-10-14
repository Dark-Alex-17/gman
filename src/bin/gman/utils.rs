use anyhow::{Context, Result};
use gman::config::{Config, get_config_file_path};
use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Root};
use log4rs::encode::pattern::PatternEncoder;
use std::path::PathBuf;
use std::{env, fs};

pub fn init_logging_config() -> log4rs::Config {
    let encoder = Box::new(PatternEncoder::new(
        "{d(%Y-%m-%d %H:%M:%S%.3f)(utc)} <{i}> [{l}] {f}:{L} - {m}{n}",
    ));

    let file_appender = FileAppender::builder()
        .encoder(encoder.clone())
        .build(get_log_path());

    match file_appender {
        Ok(file) => log4rs::Config::builder()
            .appender(Appender::builder().build("logfile", Box::new(file)))
            .build(
                Root::builder()
                    .appender("logfile")
                    .build(LevelFilter::Debug),
            )
            .unwrap(),
        Err(e) => {
            eprintln!(
                "File logging disabled ({}). Falling back to console logging.",
                e
            );
            let console = ConsoleAppender::builder().encoder(encoder).build();
            log4rs::Config::builder()
                .appender(Appender::builder().build("console", Box::new(console)))
                .build(
                    Root::builder()
                        .appender("console")
                        .build(LevelFilter::Debug),
                )
                .unwrap()
        }
    }
}

pub fn get_log_path() -> PathBuf {
    let base_dir = dirs::cache_dir().unwrap_or_else(env::temp_dir);
    let log_dir = base_dir.join(env!("CARGO_CRATE_NAME"));

    let dir = if let Err(e) = fs::create_dir_all(&log_dir) {
        eprintln!(
            "Failed to create log directory '{}': {}",
            log_dir.display(),
            e
        );
        env::temp_dir()
    } else {
        log_dir
    };

    dir.join("gman.log")
}

pub fn persist_config_file(config: &Config) -> Result<()> {
    let config_path =
        get_config_file_path().with_context(|| "unable to determine config file path")?;
    let ext = config_path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml") {
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let s = serde_yaml::to_string(config)?;
        fs::write(&config_path, s)
            .with_context(|| format!("failed to write {}", config_path.display()))?;
    } else {
        confy::store(env!("CARGO_CRATE_NAME"), "config", config)
            .with_context(|| "failed to save updated config via confy")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::utils::get_log_path;

    #[test]
    fn test_get_log_path() {
        let log_path = get_log_path();
        assert!(log_path.ends_with("gman.log"));
        assert!(log_path.parent().is_some());
    }
}
