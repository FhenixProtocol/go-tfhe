use crate::keys::{CLIENT_KEY, PUBLIC_KEY, SERVER_KEY};
use std::panic::catch_unwind;
use tfhe::{set_server_key, ClientKey, CompactPublicKey, ServerKey};

use crate::math::{op_uint16, op_uint32, op_uint8};

use crate::error::{handle_c_error_binary, handle_c_error_default, RustError};

use crate::memory::{ByteSliceView, UnmanagedVector};

/// cbindgen:prefix-with-name
#[repr(i32)]
pub enum Op {
    Add = 0,
    Sub = 1,
    Mul = 2,
    Lt = 3,
    Lte = 4,
}

/// cbindgen:prefix-with-name
#[repr(i32)]
pub enum FheUintType {
    Uint8 = 0,
    Uint16 = 1,
    Uint32 = 2,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct c_void {}

#[no_mangle]
pub unsafe extern "C" fn math_operation(
    lhs: ByteSliceView,
    rhs: ByteSliceView,
    operation: Op,
    uint_type: FheUintType,
    err_msg: Option<&mut UnmanagedVector>,
) -> UnmanagedVector {
    match uint_type {
        FheUintType::Uint8 => op_uint8(lhs, rhs, operation, err_msg),
        FheUintType::Uint16 => op_uint16(lhs, rhs, operation, err_msg),
        FheUintType::Uint32 => op_uint32(lhs, rhs, operation, err_msg),
    }
}

#[no_mangle]
pub unsafe extern "C" fn deserialize_server_key(
    key: ByteSliceView,
    err_msg: Option<&mut UnmanagedVector>,
) -> bool {
    println!("TOMMM In deserialize_server_key()");
    let r: Result<bool, RustError> = catch_unwind(|| {
        let maybe_key_deserialized =
            bincode::deserialize::<ServerKey>(key.read().unwrap()).unwrap();

        set_server_key(maybe_key_deserialized.clone());

        let mut server_key_guard = SERVER_KEY.lock().unwrap();
        server_key_guard.set_key(maybe_key_deserialized);

        println!("TOMMM In deserialize_server_key() server key: {:?}", key);

        true
    })
    .map_err(|err| {
        eprintln!("Panic in deserialize_server_key: {:?}", err);
        RustError::generic_error("lol")
    });

    handle_c_error_default(r, err_msg)
}

#[no_mangle]
pub unsafe extern "C" fn deserialize_client_key(
    key: ByteSliceView,
    err_msg: Option<&mut UnmanagedVector>,
) -> bool {
    let client_key_slice = key.read().unwrap();

    let r = deserialize_client_key_safe(client_key_slice);

    handle_c_error_default(r, err_msg)
}

pub fn deserialize_client_key_safe(key: &[u8]) -> Result<bool, RustError> {
    let r: Result<bool, RustError> = catch_unwind(|| {
        let maybe_key_deserialized = bincode::deserialize::<ClientKey>(key).unwrap();

        let mut client_key = CLIENT_KEY.lock().unwrap();
        *client_key = Some(maybe_key_deserialized);

        true
    })
    .map_err(|err| {
        eprintln!("Panic in deserialize_client_key: {:?}", err);
        RustError::generic_error("lol")
    });
    r
}

#[no_mangle]
pub unsafe extern "C" fn deserialize_public_key(
    key: ByteSliceView,
    err_msg: Option<&mut UnmanagedVector>,
) -> bool {
    let public_key_slice = key.read().unwrap();

    let r = deserialize_public_key_safe(public_key_slice);

    handle_c_error_default(r, err_msg)
}

pub fn deserialize_public_key_safe(key: &[u8]) -> Result<bool, RustError> {
    let r: Result<bool, RustError> = catch_unwind(|| {
        let maybe_key_deserialized = bincode::deserialize::<CompactPublicKey>(key).unwrap();

        let mut public_key = PUBLIC_KEY.lock().unwrap();
        *public_key = Some(maybe_key_deserialized);

        true
    })
    .map_err(|err| {
        eprintln!("Panic in deserialize_public_key: {:?}", err);
        RustError::generic_error(":(")
    });
    r
}

#[no_mangle]
pub unsafe extern "C" fn get_public_key(err_msg: Option<&mut UnmanagedVector>) -> UnmanagedVector {
    let public_key_guard = PUBLIC_KEY.lock().unwrap();

    let r: Result<Vec<u8>, RustError> = catch_unwind(|| {
        let public_key = match *public_key_guard {
            Some(ref ck) => ck,
            None => {
                panic!("Public Key not set");
            } // Return an error or handle this case appropriately.
        };

        bincode::serialize(public_key).unwrap()
    })
    .map_err(|err| {
        eprintln!("Panic in deserialize_public_key: {:?}", err);
        RustError::generic_error(":(")
    });

    let result = handle_c_error_binary(r, err_msg);
    UnmanagedVector::new(Some(result))
}
