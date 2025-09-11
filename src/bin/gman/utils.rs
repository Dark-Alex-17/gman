use log::LevelFilter;
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Root};
use log4rs::encode::pattern::PatternEncoder;
use std::fs;
use std::path::PathBuf;

pub fn init_logging_config() -> log4rs::Config {
    let logfile = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "{d(%Y-%m-%d %H:%M:%S%.3f)(utc)} <{i}> [{l}] {f}:{L} - {m}{n}",
        )))
        .build(get_log_path())
        .unwrap();

    log4rs::Config::builder()
        .appender(Appender::builder().build("logfile", Box::new(logfile)))
        .build(
            Root::builder()
                .appender("logfile")
                .build(LevelFilter::Debug),
        )
        .unwrap()
}

pub fn get_log_path() -> PathBuf {
    let mut log_path = if cfg!(target_os = "linux") {
        dirs::cache_dir().unwrap_or_else(|| PathBuf::from("~/.cache"))
    } else if cfg!(target_os = "macos") {
        dirs::home_dir().unwrap().join("Library/Logs")
    } else {
        dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("C:\\Logs"))
    };

    log_path.push("gman");

    if let Err(e) = fs::create_dir_all(&log_path) {
        eprintln!("Failed to create log directory: {e:?}");
    }

    log_path.push("gman.log");
    log_path
}

#[cfg(test)]
mod tests {
    use crate::utils::get_log_path;

    #[test]
    fn test_get_log_path() {
        let log_path = get_log_path();
        if cfg!(target_os = "linux") {
            assert!(log_path.ends_with(".cache/gman/gman.log"));
        } else if cfg!(target_os = "macos") {
            assert!(log_path.ends_with("Library/Logs/gman/gman.log"));
        } else if cfg!(target_os = "windows") {
            assert!(log_path.ends_with("Logs\\gman\\gman.log"));
        }
    }
}
