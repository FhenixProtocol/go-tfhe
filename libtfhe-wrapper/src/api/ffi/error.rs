use crate::api::ffi::memory::UnmanagedVector;
use crate::error::RustError;
#[cfg(not(target_arch = "wasm32"))]
use errno::{set_errno, Errno};

/// cbindgen:prefix-with-name
#[repr(i32)]
#[cfg(not(target_arch = "wasm32"))]
enum ErrnoValue {
    Success = 0,
    Other = 1,
    #[allow(dead_code)]
    OutOfGas = 2,
}

pub fn clear_error() {
    #[cfg(not(target_arch = "wasm32"))]
    set_errno(Errno(ErrnoValue::Success as i32));
}

pub fn set_error(err: RustError, error_msg: Option<&mut UnmanagedVector>) {
    if let Some(error_msg) = error_msg {
        let msg: Vec<u8> = err.to_string().into();
        *error_msg = UnmanagedVector::new(Some(msg));
    } else {
        // The caller provided a nil pointer for the error message.
        // That's not nice but we can live with it.
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let errno = ErrnoValue::Other as i32;
        set_errno(Errno(errno));
    }
}

/// If `result` is Ok, this returns the Ok value and clears [errno].
/// Otherwise it returns a null pointer, writes the error message to `error_msg` and sets [errno].
///
/// [errno]: https://utcc.utoronto.ca/~cks/space/blog/programming/GoCgoErrorReturns
#[allow(dead_code)]
pub fn handle_c_error_ptr<T>(
    result: Result<*mut T, RustError>,
    error_msg: Option<&mut UnmanagedVector>,
) -> *mut T {
    match result {
        Ok(value) => {
            clear_error();
            value
        }
        Err(error) => {
            set_error(error, error_msg);
            std::ptr::null_mut()
        }
    }
}

/// If `result` is Ok, this returns the binary representation of the Ok value and clears [errno].
/// Otherwise it returns an empty vector, writes the error message to `error_msg` and sets [errno].
///
/// [errno]: https://utcc.utoronto.ca/~cks/space/blog/programming/GoCgoErrorReturns
pub fn handle_c_error_binary<T>(
    result: Result<T, RustError>,
    error_msg: Option<&mut UnmanagedVector>,
) -> Vec<u8>
where
    T: Into<Vec<u8>>,
{
    match result {
        Ok(value) => {
            clear_error();
            value.into()
        }
        Err(error) => {
            set_error(error, error_msg);
            Vec::new()
        }
    }
}

/// If `result` is Ok, this returns the Ok value and clears [errno].
/// Otherwise it returns the default value, writes the error message to `error_msg` and sets [errno].
///
/// [errno]: https://utcc.utoronto.ca/~cks/space/blog/programming/GoCgoErrorReturns
pub fn handle_c_error_default<T>(
    result: Result<T, RustError>,
    error_msg: Option<&mut UnmanagedVector>,
) -> T
where
    T: Default,
{
    match result {
        Ok(value) => {
            clear_error();
            value
        }
        Err(error) => {
            set_error(error, error_msg);
            Default::default()
        }
    }
}
