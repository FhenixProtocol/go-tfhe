#[cfg(not((target_arch = "wasm32")))]
pub mod ffi;

#[cfg(not((target_arch = "wasm32")))]
pub use ffi::api::*;

#[cfg((target_arch = "wasm32"))]
pub mod wasm;

#[cfg((target_arch = "wasm32"))]
pub use wasm::api::*;
