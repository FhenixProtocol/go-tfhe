use std::env;
pub(crate) const LOG_LEVEL_ENV_VAR: &str = "LOG_LEVEL";
pub fn log_level_from_str(env_log_level: &str) -> Option<log::Level> {
    let uppercase = &env_log_level.to_uppercase()[..];
    match uppercase {
        "ERROR" => Some(log::Level::Error),
        "WARN" => Some(log::Level::Warn),
        "INFO" => Some(log::Level::Info),
        "DEBUG" => Some(log::Level::Debug),
        "TRACE" => Some(log::Level::Trace),
        _ => None,
    }
}

pub(crate) fn get_log_level(default: log::Level) -> log::Level {
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
