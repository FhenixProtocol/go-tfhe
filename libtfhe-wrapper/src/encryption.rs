use crate::api::FheUintType;
use crate::error::{handle_c_error_binary, handle_c_error_default, RustError};
use crate::keys::{CLIENT_KEY, PUBLIC_KEY, SERVER_KEY};
use crate::memory::{ByteSliceView, UnmanagedVector};
use crate::serialization::{deserialize_fhe_uint16, deserialize_fhe_uint32, deserialize_fhe_uint8};
use std::panic::{catch_unwind};

use tfhe::prelude::FheTrivialEncrypt;
use tfhe::{
    CompactFheUint16, CompactFheUint32, CompactFheUint8,
    CompactPublicKey, FheUint16, FheUint32, FheUint8,
};

use tfhe::prelude::*;
use tfhe::ClientKey;


#[no_mangle]
pub unsafe extern "C" fn expand_compressed(
    ciphertext: ByteSliceView,
    int_type: FheUintType,
    err_msg: Option<&mut UnmanagedVector>,
) -> UnmanagedVector {
    let r = expand_compressed_safe(ciphertext.read().unwrap(), int_type);

    let result = handle_c_error_binary(r, err_msg);
    UnmanagedVector::new(Some(result))

}

fn expand_compressed_safe(ciphertext: &[u8], int_type: FheUintType) -> Result<Vec<u8>, RustError> {
    match int_type {
        FheUintType::Uint8 => {
            let value: FheUint8 = deserialize_fhe_uint8(ciphertext, true).map_err(
                |e| RustError::generic_error(format!("failed to deserialize compressed u8: {:?}", e))
            )?;

            bincode::serialize(&value).map_err(|e| RustError::generic_error(format!("failed to serialize compressed value: {:?}", e)))
        }
        FheUintType::Uint16 => {
            let value: FheUint16 = deserialize_fhe_uint16(ciphertext, true).map_err(
                |e| RustError::generic_error(format!("failed to deserialize compressed u16: {:?}", e))
            )?;

            bincode::serialize(&value).map_err(|e| RustError::generic_error(format!("failed to serialize compressed value: {:?}", e)))
        }
        FheUintType::Uint32 => {
            let value: FheUint32 = deserialize_fhe_uint32(ciphertext, true).map_err(
                |e| RustError::generic_error(format!("failed to deserialize compressed u32: {:?}", e))
            )?;

            bincode::serialize(&value).map_err(|e| RustError::generic_error(format!("failed to serialize compressed value: {:?}", e)))
        }
    }
}

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

        match int_type {
            FheUintType::Uint8 => {
                _encrypt_impl::<_, CompactFheUint8, FheUint8>(msg as u8, true, public_key)
            }
            FheUintType::Uint16 => {
                _encrypt_impl::<_, CompactFheUint16, FheUint16>(msg as u16, true, public_key)
            }
            FheUintType::Uint32 => {
                _encrypt_impl::<_, CompactFheUint32, FheUint32>(msg as u32, true, public_key)
            }
        }

        // let enc = FheUint8::encrypt(msg as u8, client_key);
        //
        // // let now = std::time::Instant::now();
        // let r = bincode::serialize(&enc).unwrap();
        // let stop = now.elapsed().as_micros();

        // println!("Serialize u8 took: {}us", stop);
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

        match int_type {
            FheUintType::Uint8 => _encrypt_trivial_impl::<_, FheUint8>(msg as u8),
            FheUintType::Uint16 => _encrypt_trivial_impl::<_, FheUint16>(msg as u16),
            FheUintType::Uint32 => _encrypt_trivial_impl::<_, FheUint32>(msg as u32),
        }
    })
    .map_err(|err| {
        eprintln!("Panic in trivial_encrypt: {:?}", err);
        RustError::generic_error("panic in trivial encrypt")
    });

    let result = handle_c_error_binary(r, err_msg);
    UnmanagedVector::new(Some(result))
}

fn _encrypt_trivial_impl<T, Expanded>(value: T) -> Vec<u8>
where
    T: std::fmt::Display,
    Expanded: FheTrivialEncrypt<T>,
    Expanded: serde::Serialize,
{
    // todo: separate serialization from encryption so we can change it on-the-fly
    bincode::serialize(&Expanded::encrypt_trivial(value)).expect("ciphertext serialization")
}

fn _encrypt_impl<T, Compact, Expanded>(
    value: T,
    compact: bool,
    public_key: &CompactPublicKey,
) -> Vec<u8>
where
    T: std::fmt::Display,
    Compact: FheTryEncrypt<T, CompactPublicKey>,
    Compact: serde::Serialize,
    Expanded: FheEncrypt<T, CompactPublicKey>,
    Expanded: serde::Serialize,
{
    if !compact {
        bincode::serialize(&Expanded::encrypt(value, public_key)).expect("ciphertext serialization")
    } else {
        bincode::serialize(&Compact::try_encrypt(value, public_key).unwrap()).expect("ciphertext serialization")
    }
}

#[no_mangle]
pub unsafe extern "C" fn decrypt(
    ciphertext: ByteSliceView,
    int_type: FheUintType,
    err_msg: Option<&mut UnmanagedVector>,
) -> u64 {
    let ciphertext_slice = ciphertext.read().unwrap();

    let r = decrypt_safe(ciphertext_slice, int_type);

    handle_c_error_default(r, err_msg)
}

pub fn decrypt_safe(ciphertext: &[u8], int_type: FheUintType) -> Result<u64, RustError> {
    let client_key_guard = CLIENT_KEY.lock().unwrap();

    let client_key = match *client_key_guard {
        Some(ref ck) => ck,
        None => return Err(RustError::generic_error("Client key not set")), // Return an error or handle this case appropriately.
    };

    let res = match int_type {
        FheUintType::Uint8 => {
            _impl_decrypt_u8(deserialize_fhe_uint8(ciphertext, false).map_err(|err| {
                eprintln!("Error decrypting u8: {:?}", err);
                RustError::generic_error("Error decrypting u8")
            })?, client_key)
        }
        FheUintType::Uint16 => {
            _impl_decrypt_u16(deserialize_fhe_uint16(ciphertext, false).map_err(|err| {
                eprintln!("Error decrypting u16: {:?}", err);
                RustError::generic_error("Error decrypting u16")
            })?, client_key)
        }
        FheUintType::Uint32 => {
            _impl_decrypt_u32(deserialize_fhe_uint32(ciphertext, false).map_err(|err| {
                eprintln!("Error decrypting u32: {:?}", err);
                RustError::generic_error("Error decrypting u32")
            })?, client_key)
        }
    };
    Ok(res)
}

// the way this is implemented cannot be parsed generically :(
fn _impl_decrypt_u32(ciphertext: FheUint32, client_key: &ClientKey) -> u64 {
    // let now = std::time::Instant::now();
    let decrypt_value: u32 = ciphertext.decrypt(client_key);
    // let stop = now.elapsed().as_micros();
    // println!("Decrypt u32 took: {}us", stop);

    decrypt_value as u64
}

// the way this is implemented cannot be parsed generically :(
fn _impl_decrypt_u16(ciphertext: FheUint16, client_key: &ClientKey) -> u64 {
    // let now = std::time::Instant::now();
    let decrypt_value: u16 = ciphertext.decrypt(client_key);
    // let stop = now.elapsed().as_micros();
    // println!("Decrypt u32 took: {}us", stop);

    decrypt_value as u64
}

// the way this is implemented cannot be parsed generically :(
fn _impl_decrypt_u8(ciphertext: FheUint8, client_key: &ClientKey) -> u64 {
    // let now = std::time::Instant::now();
    let decrypt_value: u8 = ciphertext.decrypt(client_key);
    // let stop = now.elapsed().as_micros();
    // println!("Decrypt u32 took: {}us", stop);

    decrypt_value as u64
}
