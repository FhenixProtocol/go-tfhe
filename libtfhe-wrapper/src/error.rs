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
    #[error("Panic during math operation: {}", name)]
    MathPanic {
        name: String,
        #[cfg(feature = "backtraces")]
        backtrace: Backtrace,
    },
    #[error("Panic during cast operation: {}", name)]
    CastPanic {
        name: String,
        #[cfg(feature = "backtraces")]
        backtrace: Backtrace,
    },
    #[error("Panic during encrypt operation: {}", name)]
    EncryptPanic {
        name: String,
        #[cfg(feature = "backtraces")]
        backtrace: Backtrace,
    },
    #[error("Panic during decrypt operation: {}", name)]
    DecryptPanic {
        name: String,
        #[cfg(feature = "backtraces")]
        backtrace: Backtrace,
    },
    #[error("Panic during trivial encrypt operation: {}", name)]
    TrivialEncryptPanic {
        name: String,
        #[cfg(feature = "backtraces")]
        backtrace: Backtrace,
    },
    #[error("Panic during expand compressed operation: {}", name)]
    ExpandPanic {
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

    pub fn cast_panic<T: Into<String>>(name: T) -> Self {
        RustError::CastPanic {
            name: name.into(),
            #[cfg(feature = "backtraces")]
            backtrace: Backtrace::capture(),
        }
    }

    pub fn encrypt_panic<T: Into<String>>(name: T) -> Self {
        RustError::EncryptPanic {
            name: name.into(),
            #[cfg(feature = "backtraces")]
            backtrace: Backtrace::capture(),
        }
    }

    pub fn decrypt_panic<T: Into<String>>(name: T) -> Self {
        RustError::DecryptPanic {
            name: name.into(),
            #[cfg(feature = "backtraces")]
            backtrace: Backtrace::capture(),
        }
    }

    pub fn trivial_encrypt_panic<T: Into<String>>(name: T) -> Self {
        RustError::TrivialEncryptPanic {
            name: name.into(),
            #[cfg(feature = "backtraces")]
            backtrace: Backtrace::capture(),
        }
    }

    pub fn expand_compressed_panic<T: Into<String>>(name: T) -> Self {
        RustError::ExpandPanic {
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
