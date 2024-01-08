use thiserror::Error;

#[cfg(feature = "backtraces")]
use std::backtrace::Backtrace;

#[derive(Error, Debug)]
pub enum RustError {
    #[error("Empty argument: {}", name)]
    GenericError {
        name: String,
        #[cfg(feature = "backtraces")]
        backtrace: Backtrace,
    },
    MathPanic {
        name: String,
        #[cfg(feature = "backtraces")]
        backtrace: Backtrace,
    },
}

impl RustError {
    pub fn generic_error<T: Into<String>>(name: T) -> Self {
        RustError::GenericError {
            name: name.into(),
            #[cfg(feature = "backtraces")]
            backtrace: Backtrace::capture(),
        }
    }

    pub fn math_panic<T: Into<String>>(name: T) -> Self {
        RustError::MathPanic {
            name: name.into(),
            #[cfg(feature = "backtraces")]
            backtrace: Backtrace::capture(),
        }
    }
}

impl From<std::str::Utf8Error> for RustError {
    fn from(source: std::str::Utf8Error) -> Self {
        RustError::generic_error(source.to_string())
    }
}

impl From<std::string::FromUtf8Error> for RustError {
    fn from(source: std::string::FromUtf8Error) -> Self {
        RustError::generic_error(source.to_string())
    }
}
