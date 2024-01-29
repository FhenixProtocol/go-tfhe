use std::env;
use std::time::SystemTime;

pub const LOG_LEVEL_ENV_VAR: &str = "LOG_LEVEL";
pub const LOG_FILE_ENV_VAR: &str = "LOG_FILE";

pub(crate) fn init_logger() -> Result<(), fern::InitError> {
    let default_log_level = log::LevelFilter::Info;
    let default_log_file = "go-tfhe.log";

    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{} [{}] {}",
                record.level(),
                humantime::format_rfc3339_seconds(SystemTime::now()),
                message
            ))
        })
        .level(get_log_level(default_log_level))
        .chain(std::io::stderr())
        .chain(
            fern::log_file(
                get_logfile(default_log_file)
            )?)
        .apply()?;

    Ok(())
}

pub fn log_level_from_str(env_log_level: &str) -> Option<log::LevelFilter> {
    let uppercase = &env_log_level.to_uppercase()[..];
    match uppercase {
        "ERROR" => Some(log::LevelFilter::Error),
        "WARN" => Some(log::LevelFilter::Warn),
        "INFO" => Some(log::LevelFilter::Info),
        "DEBUG" => Some(log::LevelFilter::Debug),
        "TRACE" => Some(log::LevelFilter::Trace),
        _ => None,
    }
}

pub fn get_log_level(default: log::LevelFilter) -> log::LevelFilter {
    // TODO: read from config when it is implemented
    let env_level = &env::var(LOG_LEVEL_ENV_VAR).unwrap_or_default();
    match log_level_from_str(env_level) {
        Some(level) => {
            if level > default {
                default
            } else {
                level
            }
        }
        None => default,
    }
}

pub fn get_logfile(default: &str) -> String {
    // TODO: read from config when it is implemented
    match env::var(LOG_FILE_ENV_VAR) {
        Ok(env_file) => env_file,
        Err(_) => default.to_string(),
    }
}