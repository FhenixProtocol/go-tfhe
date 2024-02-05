use crate::api::{FheUintType, PlaintextNumber};
use crate::error::RustError;
use crate::keys::GlobalKeys;
use crate::serialization::{
    deserialize_fhe_uint128, deserialize_fhe_uint16, deserialize_fhe_uint256,
    deserialize_fhe_uint32, deserialize_fhe_uint64, deserialize_fhe_uint8,
};
use primitive_types::U256;

use tfhe::prelude::FheTrivialEncrypt;

use tfhe::{
    CompactFheUint128, CompactFheUint16, CompactFheUint256, CompactFheUint32, CompactFheUint64,
    CompactFheUint8, CompactPublicKey, FheUint128, FheUint16, FheUint256, FheUint32, FheUint64,
    FheUint8,
};

use tfhe::prelude::*;
use tfhe::ClientKey;

pub fn expand_compressed_safe(
    ciphertext: &[u8],
    int_type: FheUintType,
) -> Result<Vec<u8>, RustError> {
    match int_type {
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
        FheUintType::Uint64 => {
            let value: FheUint64 = deserialize_fhe_uint64(ciphertext, true).map_err(|e| {
                RustError::generic_error(format!("failed deserializing compressed u32: {:?}", e))
            })?;

            bincode::serialize(&value).map_err(|e| {
                RustError::generic_error(format!("failed serializing compressed value: {:?}", e))
            })
        }
        FheUintType::Uint128 => {
            let value: FheUint128 = deserialize_fhe_uint128(ciphertext, true).map_err(|e| {
                RustError::generic_error(format!("failed deserializing compressed u32: {:?}", e))
            })?;

            bincode::serialize(&value).map_err(|e| {
                RustError::generic_error(format!("failed serializing compressed value: {:?}", e))
            })
        }
        FheUintType::Uint256 => {
            let value: FheUint256 = deserialize_fhe_uint256(ciphertext, true).map_err(|e| {
                RustError::generic_error(format!("failed deserializing compressed u32: {:?}", e))
            })?;

            bincode::serialize(&value).map_err(|e| {
                RustError::generic_error(format!("failed serializing compressed value: {:?}", e))
            })
        }
    }
}
pub fn encrypt_safe(msg: U256, int_type: FheUintType) -> Result<Vec<u8>, RustError> {
    let public_key = match GlobalKeys::get_public_key() {
        Some(key) => Ok(key),
        None => Err(RustError::generic_error("public key not set")), // Return an error or handle this case appropriately.
    }?;

    match int_type {
        FheUintType::Uint8 => {
            _encrypt_impl::<_, CompactFheUint8, FheUint8>(msg.as_u32() as u8, true, public_key)
        }
        FheUintType::Uint16 => {
            _encrypt_impl::<_, CompactFheUint16, FheUint16>(msg.as_u32() as u16, true, public_key)
        }
        FheUintType::Uint32 => {
            _encrypt_impl::<_, CompactFheUint32, FheUint32>(msg.as_u32(), true, public_key)
        }
        FheUintType::Uint64 => {
            _encrypt_impl::<_, CompactFheUint64, FheUint64>(msg.as_u64(), true, public_key)
        }
        FheUintType::Uint128 => {
            _encrypt_impl::<_, CompactFheUint128, FheUint128>(msg.as_u128(), true, public_key)
        }
        FheUintType::Uint256 => {
            let mut bytes = [0u8; 32];
            msg.to_big_endian(bytes.as_mut_slice());

            let mut zama_u256 = tfhe::integer::U256::default();

            zama_u256.copy_from_be_byte_slice(bytes.as_slice());

            let encrypted =
                &CompactFheUint256::try_encrypt(zama_u256, public_key).map_err(|err| {
                    log::error!("failed encrypting value: {:?}", err);
                    RustError::generic_error("encrypt failed")
                })?;
            bincode::serialize(encrypted).map_err(|err| {
                log::error!("failed serializing value: {:?}", err);
                RustError::generic_error("ciphertext serialization error")
            })
        }
    }
}

pub fn trivial_encrypt_safe(msg: U256, int_type: FheUintType) -> Result<Vec<u8>, RustError> {
    GlobalKeys::refresh_server_key_for_thread();
    match int_type {
        FheUintType::Uint8 => _encrypt_trivial_impl::<_, FheUint8>(msg.as_u32() as u8),
        FheUintType::Uint16 => _encrypt_trivial_impl::<_, FheUint16>(msg.as_u32() as u16),
        FheUintType::Uint32 => _encrypt_trivial_impl::<_, FheUint32>(msg.as_u32()),
        FheUintType::Uint64 => _encrypt_trivial_impl::<_, FheUint64>(msg.as_u64()),
        FheUintType::Uint128 => _encrypt_trivial_impl::<_, FheUint128>(msg.as_u128()),
        FheUintType::Uint256 => {
            panic!("Not supported yet")
        }
    }
}

pub fn decrypt_safe(
    ciphertext: &[u8],
    int_type: FheUintType,
) -> Result<PlaintextNumber, RustError> {
    let client_key = match GlobalKeys::get_client_key() {
        Some(ck) => Ok(ck),
        None => Err(RustError::generic_error("client key not set")),
    }?;

    let mut return_value = [0u8; 32];

    let res = match int_type {
        FheUintType::Uint8 => _impl_decrypt_u8(
            deserialize_fhe_uint8(ciphertext, false).map_err(|err| {
                log::error!("failed decrypting u8: {:?}", err);
                RustError::generic_error("Failed decrypting u8")
            })?,
            client_key,
        ),
        FheUintType::Uint16 => _impl_decrypt_u16(
            deserialize_fhe_uint16(ciphertext, false).map_err(|err| {
                log::error!("failed decrypting u16: {:?}", err);
                RustError::generic_error("Failed decrypting u16")
            })?,
            client_key,
        ),
        FheUintType::Uint32 => _impl_decrypt_u32(
            deserialize_fhe_uint32(ciphertext, false).map_err(|err| {
                log::error!("failed decrypting u32: {:?}", err);
                RustError::generic_error("Failed decrypting u32")
            })?,
            client_key,
        ),
        FheUintType::Uint64 => _impl_decrypt_u64(
            deserialize_fhe_uint64(ciphertext, false).map_err(|err| {
                log::error!("failed decrypting u64: {:?}", err);
                RustError::generic_error("Failed decrypting u64")
            })?,
            client_key,
        ),
        FheUintType::Uint128 => _impl_decrypt_u128(
            deserialize_fhe_uint128(ciphertext, false).map_err(|err| {
                log::error!("failed decrypting u128: {:?}", err);
                RustError::generic_error("Failed decrypting u128")
            })?,
            client_key,
        ),
        FheUintType::Uint256 => _impl_decrypt_u256(
            deserialize_fhe_uint256(ciphertext, false).map_err(|err| {
                log::error!("failed decrypting u256: {:?}", err);
                RustError::generic_error("Failed decrypting u256")
            })?,
            client_key,
        ),
    };
    res.to_big_endian(return_value.as_mut_slice());
    Ok(return_value)
}

fn _encrypt_trivial_impl<T, Expanded>(value: T) -> Result<Vec<u8>, RustError>
where
    T: std::fmt::Debug,
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
    T: std::fmt::Debug,
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
fn _impl_decrypt_u32(ciphertext: FheUint32, client_key: &ClientKey) -> U256 {
    // let now = std::time::Instant::now();
    let decrypt_value: u32 = ciphertext.decrypt(client_key);
    // let stop = now.elapsed().as_micros();
    // println!("Decrypt u32 took: {}us", stop);

    U256::from(decrypt_value)
}

// the way this is implemented cannot be parsed generically :(
fn _impl_decrypt_u16(ciphertext: FheUint16, client_key: &ClientKey) -> U256 {
    // let now = std::time::Instant::now();
    let decrypt_value: u16 = ciphertext.decrypt(client_key);
    // let stop = now.elapsed().as_micros();
    // println!("Decrypt u32 took: {}us", stop);

    U256::from(decrypt_value)
}

// the way this is implemented cannot be parsed generically :(
fn _impl_decrypt_u8(ciphertext: FheUint8, client_key: &ClientKey) -> U256 {
    // let now = std::time::Instant::now();
    let decrypt_value: u8 = ciphertext.decrypt(client_key);
    // let stop = now.elapsed().as_micros();
    // println!("Decrypt u32 took: {}us", stop);

    U256::from(decrypt_value)
}

fn _impl_decrypt_u64(ciphertext: FheUint64, client_key: &ClientKey) -> U256 {
    // let now = std::time::Instant::now();
    let decrypt_value: u64 = ciphertext.decrypt(client_key);
    // let stop = now.elapsed().as_micros();
    // println!("Decrypt u32 took: {}us", stop);

    U256::from(decrypt_value)
}

fn _impl_decrypt_u128(ciphertext: FheUint128, client_key: &ClientKey) -> U256 {
    // let now = std::time::Instant::now();
    let decrypt_value: u128 = ciphertext.decrypt(client_key);
    // let stop = now.elapsed().as_micros();
    // println!("Decrypt u32 took: {}us", stop);

    U256::from(decrypt_value)
}

fn _impl_decrypt_u256(ciphertext: FheUint256, client_key: &ClientKey) -> U256 {
    // let now = std::time::Instant::now();
    let decrypt_value: tfhe::integer::U256 = ciphertext.decrypt(client_key);

    let mut bytes = [0u8; 32];
    decrypt_value.copy_to_be_byte_slice(bytes.as_mut_slice());
    U256::from_big_endian(&bytes)
    // let stop = now.elapsed().as_micros();
    // println!("Decrypt u32 took: {}us", stop);
}
