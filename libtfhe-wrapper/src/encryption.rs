use crate::api::FheUintType;
use crate::error::{handle_c_error_binary, handle_c_error_default, RustError};
use crate::keys::{CLIENT_KEY, PUBLIC_KEY, SERVER_KEY};
use crate::memory::{ByteSliceView, UnmanagedVector};
use crate::serialization::{deserialize_fhe_uint16, deserialize_fhe_uint32, deserialize_fhe_uint8};
use std::panic::{catch_unwind, UnwindSafe};

use tfhe::prelude::FheTrivialEncrypt;
use tfhe::{
    CompactFheUint16, CompactFheUint32, CompactFheUint8,
    CompactPublicKey, FheUint16, FheUint32, FheUint8,
};

use tfhe::core_crypto::prelude::CastInto;
use tfhe::prelude::*;
use tfhe::ClientKey;

#[no_mangle]
pub unsafe extern "C" fn encrypt(
    msg: u64,
    int_type: FheUintType,
    err_msg: Option<&mut UnmanagedVector>,
) -> UnmanagedVector {
    let r = encrypt_safe(msg, int_type);

    let result = handle_c_error_binary(r, err_msg);
    UnmanagedVector::new(Some(result))
}

pub fn encrypt_safe(msg: u64, int_type: FheUintType) -> Result<Vec<u8>, RustError> {
    let public_key_guard = PUBLIC_KEY.lock().unwrap();

    let r: Result<Vec<u8>, RustError> = catch_unwind(|| {
        let public_key = match *public_key_guard {
            Some(ref ck) => ck,
            None => panic!("Client key not set"), // Return an error or handle this case appropriately.
        };

        let r = match int_type {
            FheUintType::Uint8 => {
                _encrypt_impl::<_, CompactFheUint8, FheUint8>(msg as u8, false, public_key)
            }
            FheUintType::Uint16 => {
                _encrypt_impl::<_, CompactFheUint16, FheUint16>(msg as u16, false, public_key)
            }
            FheUintType::Uint32 => {
                _encrypt_impl::<_, CompactFheUint32, FheUint32>(msg as u32, false, public_key)
            }
        };

        // let enc = FheUint8::encrypt(msg as u8, client_key);
        //
        // // let now = std::time::Instant::now();
        // let r = bincode::serialize(&enc).unwrap();
        // let stop = now.elapsed().as_micros();

        // println!("Serialize u8 took: {}us", stop);
        r
    })
        .map_err(|err| {
            eprintln!("Panic in encrypt: {:?}", err);

            match *public_key_guard {
                Some(ref ck) => println!("public key: {:?}", ck),
                None => println!("Public key not set"), // Return an error or handle this case appropriately.
            };

            RustError::generic_error("lol2")
        });
    r
}

#[no_mangle]
pub unsafe extern "C" fn trivial_encrypt(
    msg: u64,
    int_type: FheUintType,
    err_msg: Option<&mut UnmanagedVector>,
) -> UnmanagedVector {
    let server_key_guard = SERVER_KEY.lock().unwrap();

    let r: Result<Vec<u8>, RustError> = catch_unwind(|| {
        match *server_key_guard {
            true => {}
            false => panic!("Server key not set"), // Return an error or handle this case appropriately.
        };

        let r = match int_type {
            FheUintType::Uint8 => _encrypt_trivial_impl::<_, FheUint8>(msg as u8, false),
            FheUintType::Uint16 => _encrypt_trivial_impl::<_, FheUint16>(msg as u16, false),
            FheUintType::Uint32 => _encrypt_trivial_impl::<_, FheUint32>(msg as u32, false),
        };

        r
    })
    .map_err(|err| {
        eprintln!("Panic in trivial_encrypt: {:?}", err);
        RustError::generic_error("panic in trivial encrypt")
    });

    let result = handle_c_error_binary(r, err_msg);
    UnmanagedVector::new(Some(result))
}

fn _encrypt_trivial_impl<T, Expanded>(value: T, expanded: bool) -> Vec<u8>
where
    T: std::fmt::Display,
    Expanded: FheTrivialEncrypt<T>,
    Expanded: serde::Serialize,
{
    // todo: separate serialization from encryption so we can change it on-the-fly
    let result =
        bincode::serialize(&Expanded::encrypt_trivial(value)).expect("ciphertext serialization");

    result
}

fn _encrypt_impl<T, Compact, Expanded>(
    value: T,
    expanded: bool,
    public_key: &CompactPublicKey,
) -> Vec<u8>
where
    T: std::fmt::Display,
    Compact: FheTryEncrypt<T, CompactPublicKey>,
    Compact: serde::Serialize,
    Expanded: FheEncrypt<T, CompactPublicKey>,
    Expanded: serde::Serialize,
{
    let result = if expanded {
        bincode::serialize(&Expanded::encrypt(value, public_key)).expect("ciphertext serialization")
    } else {
        bincode::serialize(&Compact::try_encrypt(value, public_key).unwrap()).expect("ciphertext serialization")
    };

    result
}

#[no_mangle]
pub unsafe extern "C" fn decrypt(
    ciphertext: ByteSliceView,
    int_type: FheUintType,
    err_msg: Option<&mut UnmanagedVector>,
) -> u64 {
    let ciphertext_slice = ciphertext.read().unwrap();

    let r = decrypt_safe(ciphertext_slice, int_type);

    let result = handle_c_error_default(r, err_msg);
    result
}

pub fn decrypt_safe(ciphertext: &[u8], int_type: FheUintType) -> Result<u64, RustError> {
    let client_key_guard = CLIENT_KEY.lock().unwrap();

    let r: Result<u64, RustError> = catch_unwind(|| {
        let client_key = match *client_key_guard {
            Some(ref ck) => ck,
            None => panic!("Client key not set"), // Return an error or handle this case appropriately.
        };

        let res = match int_type {
            FheUintType::Uint8 => {
                _impl_decrypt_u8(deserialize_fhe_uint8(ciphertext).unwrap(), client_key)
            }
            FheUintType::Uint16 => {
                _impl_decrypt_u16(deserialize_fhe_uint16(ciphertext).unwrap(), client_key)
            }
            FheUintType::Uint32 => {
                _impl_decrypt_u32(deserialize_fhe_uint32(ciphertext).unwrap(), client_key)
            }
        };

        res
    })
        .map_err(|err| {
            eprintln!("Panic in client_key_encrypt_fhe_uint8: {:?}", err);
            RustError::generic_error("lol2")
        });
    r
}

// the way this is implemented cannot be parsed generically :(
fn _impl_decrypt_u32(ciphertext: FheUint32, client_key: &ClientKey) -> u64 {
    // let now = std::time::Instant::now();
    let dec: u32 = ciphertext.decrypt(client_key);
    // let stop = now.elapsed().as_micros();
    // println!("Decrypt u32 took: {}us", stop);

    let r = dec as u64;
    r
}

// the way this is implemented cannot be parsed generically :(
fn _impl_decrypt_u16(ciphertext: FheUint16, client_key: &ClientKey) -> u64 {
    // let now = std::time::Instant::now();
    let dec: u16 = ciphertext.decrypt(client_key);
    // let stop = now.elapsed().as_micros();
    // println!("Decrypt u32 took: {}us", stop);

    let r = dec as u64;
    r
}

// the way this is implemented cannot be parsed generically :(
fn _impl_decrypt_u8(ciphertext: FheUint8, client_key: &ClientKey) -> u64 {
    // let now = std::time::Instant::now();
    let dec: u8 = ciphertext.decrypt(client_key);
    // let stop = now.elapsed().as_micros();
    // println!("Decrypt u32 took: {}us", stop);

    let r = dec as u64;
    r
}
