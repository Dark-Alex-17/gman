use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Root};
use log4rs::encode::pattern::PatternEncoder;
use std::fs;
use std::path::PathBuf;

pub fn init_logging_config() -> log4rs::Config {
    let encoder = Box::new(PatternEncoder::new(
        "{d(%Y-%m-%d %H:%M:%S%.3f)(utc)} <{i}> [{l}] {f}:{L} - {m}{n}",
    ));

    // Prefer file logging, but fall back to console if we cannot create/open the file.
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
    // Use a cache directory on all platforms; fall back to temp dir as a last resort.
    let base_dir = dirs::cache_dir().unwrap_or_else(std::env::temp_dir);
    let log_dir = base_dir.join("gman");

    // Best-effort: create the directory; if it fails, write directly into temp dir.
    let dir = if let Err(e) = fs::create_dir_all(&log_dir) {
        eprintln!(
            "Failed to create log directory '{}': {}",
            log_dir.display(),
            e
        );
        std::env::temp_dir()
    } else {
        log_dir
    };

    dir.join("gman.log")
}

#[cfg(test)]
mod tests {
    use crate::utils::get_log_path;

    #[test]
    fn test_get_log_path() {
        let log_path = get_log_path();
        assert!(log_path.ends_with("gman.log"));
        // Parent directory may be cache dir or temp dir; ensure it is a valid path component.
        assert!(log_path.parent().is_some());
    }
}
