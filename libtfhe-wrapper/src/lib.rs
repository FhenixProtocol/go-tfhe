#![cfg_attr(feature = "backtraces", feature(backtrace))]
#![allow(clippy::not_unsafe_ptr_arg_deref, clippy::missing_safety_doc)]

pub mod api;
pub(crate) mod encryption;
pub(crate) mod error;
pub(crate) mod keys;
pub(crate) mod math;
pub(crate) mod serialization;
// mod types;

//pub use api;
