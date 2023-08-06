#![cfg_attr(feature = "backtraces", feature(backtrace))]
#![allow(clippy::not_unsafe_ptr_arg_deref, clippy::missing_safety_doc)]
pub mod api;
mod encryption;
pub(crate) mod error;
pub mod keys;
pub(crate) mod math;
pub mod memory;
pub(crate) mod serialization;
mod version;

//pub use api;
pub use version::version_str;
