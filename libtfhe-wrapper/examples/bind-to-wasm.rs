#![feature()]
use std::ffi::c_char;
use tfhe_wrapper::api::{banana, version};
// use tfhe_wrapper::api::wasm::memory::{ByteSliceView, UnmanagedVector};
// use tfhe_wrapper::api::{encrypt, math_operation};
// use tfhe_wrapper::api::{version, FheUintType, Op};

// #[no_mangle]
// pub unsafe extern "C" fn generate_fhe_keys() -> u32 {
//     generate_full_keys(
//         "./keys/cks".to_string(),
//         "./keys/sks".to_string(),
//         "./keys/pks".to_string()
//     );
//
//     0
// }

#[no_mangle]
pub unsafe extern "C" fn get_version() -> *const c_char {
    version()
}

// #[no_mangle]
// pub unsafe extern "C" fn perform_operation(
//     lhs: ByteSliceView,
//     rhs: ByteSliceView,
//     operation: Op,
//     uint_type: FheUintType,
//     err_msg: Option<&mut UnmanagedVector>,
// ) -> UnmanagedVector {
//     math_operation(lhs, rhs, operation, uint_type, err_msg)
// }
//
// #[no_mangle]
// pub unsafe extern "C" fn encrypt_wasm(
//     plaintext: u64,
//     int_type: u32,
//     mut ret: *mut u8,
//     mut ret_len: u32,
// ) -> i32 {
//     let temp = UnmanagedVector::new(None);
//
//     let encrypted = encrypt(plaintext, int_type.into(), None);
//
//     ret = encrypted.ptr;
//     ret_len = encrypted.len as u32;
//
//     return 0;
// }

fn main() {
    unsafe { banana() }
    // unsafe { generate_fhe_keys() }
}
