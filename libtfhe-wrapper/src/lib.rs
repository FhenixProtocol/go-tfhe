#![cfg_attr(feature = "backtraces", feature(backtrace))]
#![allow(clippy::not_unsafe_ptr_arg_deref, clippy::missing_safety_doc)]

pub mod api;
pub mod encryption;
pub mod error;

#[cfg(target_arch = "wasm32")]
pub(crate) mod imports;

pub(crate) mod cast;
pub mod keys;
pub(crate) mod logger;
pub(crate) mod math;
pub(crate) mod serialization;

use ctor::ctor;
#[ctor]
fn init_logger() {
    let default_log_level = log::Level::Info;
    simple_logger::init_with_level(logger::get_log_level(default_log_level)).unwrap();
}
