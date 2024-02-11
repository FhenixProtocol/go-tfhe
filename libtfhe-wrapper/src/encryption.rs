use crate::api::FheUintType;
use crate::error::RustError;
use crate::keys::GlobalKeys;
use crate::serialization::{deserialize_fhe_uint16, deserialize_fhe_uint32, deserialize_fhe_uint8};

use tfhe::prelude::FheTrivialEncrypt;

use tfhe::{
    CompactFheUint16, CompactFheUint32, CompactFheUint8, CompactPublicKey, FheUint16, FheUint32,
    FheUint8,
};

use tfhe::prelude::*;
use tfhe::ClientKey;

use std::panic::catch_unwind;

pub fn expand_compressed_safe(
    ciphertext: &[u8],
    int_type: FheUintType,
) -> Result<Vec<u8>, RustError> {
    let result = catch_unwind(|| match int_type {
        FheUintType::Uint8 => {
            let value: FheUint8 = deserialize_fhe_uint8(ciphertext, true).map_err(|e| {
                RustError::generic_error(format!("failed deserializing compressed u8: {:?}", e))
            })?;

            bincode::serialize(&value).map_err(|e| {
                RustError::generic_error(format!("failed serializing compressed value: {:?}", e))
            })
        }
        FheUintType::Uint16 => {
            let value: FheUint16 = deserialize_fhe_uint16(ciphertext, true).map_err(|e| {
                RustError::generic_error(format!("failed deserializing compressed u16: {:?}", e))
            })?;

            bincode::serialize(&value).map_err(|e| {
                RustError::generic_error(format!("failed serializing compressed value: {:?}", e))
            })
        }
        FheUintType::Uint32 => {
            let value: FheUint32 = deserialize_fhe_uint32(ciphertext, true).map_err(|e| {
                RustError::generic_error(format!("failed deserializing compressed u32: {:?}", e))
            })?;

            bincode::serialize(&value).map_err(|e| {
                RustError::generic_error(format!("failed serializing compressed value: {:?}", e))
            })
        }
    });

    match result {
        Ok(Ok(x)) => Ok(x),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(RustError::math_panic(format!(
            "panic in expand compressed: {:#?}",
            e.downcast_ref::<&str>()
        ))),
    }
}
pub fn encrypt_safe(msg: u64, int_type: FheUintType) -> Result<Vec<u8>, RustError> {
    let public_key = match GlobalKeys::get_public_key() {
        Some(key) => Ok(key),
        None => Err(RustError::generic_error("public key not set")), // Return an error or handle this case appropriately.
    }?;

    let result = catch_unwind(|| match int_type {
        FheUintType::Uint8 => {
            _encrypt_impl::<_, CompactFheUint8, FheUint8>(msg as u8, true, public_key)
        }
        FheUintType::Uint16 => {
            _encrypt_impl::<_, CompactFheUint16, FheUint16>(msg as u16, true, public_key)
        }
        FheUintType::Uint32 => {
            _encrypt_impl::<_, CompactFheUint32, FheUint32>(msg as u32, true, public_key)
        }
    });

    match result {
        Ok(Ok(x)) => Ok(x),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(RustError::math_panic(format!(
            "panic in encrypt_safe: {:#?}",
            e.downcast_ref::<&str>()
        ))),
    }
}

pub fn trivial_encrypt_safe(msg: u64, int_type: FheUintType) -> Result<Vec<u8>, RustError> {
    GlobalKeys::refresh_server_key_for_thread();
    let result = catch_unwind(|| match int_type {
        FheUintType::Uint8 => _encrypt_trivial_impl::<_, FheUint8>(msg as u8),
        FheUintType::Uint16 => _encrypt_trivial_impl::<_, FheUint16>(msg as u16),
        FheUintType::Uint32 => _encrypt_trivial_impl::<_, FheUint32>(msg as u32),
    });

    match result {
        Ok(Ok(x)) => Ok(x),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(RustError::math_panic(format!(
            "panic in trivial encrypt: {:#?}",
            e.downcast_ref::<&str>()
        ))),
    }
}

pub fn decrypt_safe(ciphertext: &[u8], int_type: FheUintType) -> Result<u64, RustError> {
    let client_key = match GlobalKeys::get_client_key() {
        Some(ck) => Ok(ck),
        None => Err(RustError::generic_error("client key not set")),
    }?;

    catch_unwind(|| match int_type {
        FheUintType::Uint8 => _impl_decrypt_u8(
            deserialize_fhe_uint8(ciphertext, false).expect("failed deserializing u8"),
            client_key,
        ),
        FheUintType::Uint16 => _impl_decrypt_u16(
            deserialize_fhe_uint16(ciphertext, false).expect("failed deserializing u16"),
            client_key,
        ),
        FheUintType::Uint32 => _impl_decrypt_u32(
            deserialize_fhe_uint32(ciphertext, false).expect("failed deserializing u32"),
            client_key,
        ),
    }).map_err(|e| {
        log::error!("Panic occurred during decryption: {:#?}", e);
        RustError::generic_error("Panic occurred during decryption")
    })
}

fn _encrypt_trivial_impl<T, Expanded>(value: T) -> Result<Vec<u8>, RustError>
where
    T: std::fmt::Display,
    Expanded: FheTrivialEncrypt<T>,
    Expanded: serde::Serialize,
{
    // todo: separate serialization from encryption so we can change it on-the-fly
    bincode::serialize(&Expanded::encrypt_trivial(value)).map_err(|err| {
        log::error!("failed serializing trivial encryption: {:?}", err);
        RustError::generic_error("failed serializing trivial encryption")
    })
}

fn _encrypt_impl<T, Compact, Expanded>(
    value: T,
    compact: bool,
    public_key: &CompactPublicKey,
) -> Result<Vec<u8>, RustError>
where
    T: std::fmt::Display,
    Compact: FheTryEncrypt<T, CompactPublicKey>,
    Compact: serde::Serialize,
    Expanded: FheEncrypt<T, CompactPublicKey>,
    Expanded: serde::Serialize,
{
    if !compact {
        bincode::serialize(&Expanded::encrypt(value, public_key)).map_err(|err| {
            log::error!("failed serializing value: {:?}", err);
            RustError::generic_error("ciphertext serialization error")
        })
    } else {
        let encrypted = &Compact::try_encrypt(value, public_key).map_err(|err| {
            log::error!("failed encrypting value: {:?}", err);
            RustError::generic_error("encrypt failed")
        })?;
        bincode::serialize(encrypted).map_err(|err| {
            log::error!("failed serializing value: {:?}", err);
            RustError::generic_error("ciphertext serialization error")
        })
    }
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
