use crate::api::ffi::error::{handle_c_error_binary, handle_c_error_default, set_error};
use crate::api::ffi::memory::{ByteSliceView, UnmanagedVector};
use crate::api::FheUintType::{Uint16, Uint32, Uint8};
use crate::encryption::{decrypt_safe, encrypt_safe, expand_compressed_safe, trivial_encrypt_safe};
use crate::error::RustError;
#[cfg(target_arch = "wasm32")]
use crate::imports::{console_log, wavm_halt_and_set_finished};
use crate::keys::{deserialize_public_key_safe, load_server_key_safe, deserialize_client_key_safe, generate_keys_safe};
use crate::keys::GlobalKeys;
use crate::math::{op_uint16, op_uint32, op_uint8};

/// cbindgen:prefix-with-name
#[repr(i32)]
#[derive(Debug)]
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

impl From<u32> for FheUintType {
    fn from(value: u32) -> Self {
        match value {
            0 => Uint8,
            1 => Uint16,
            2 => Uint32,
            _ => Uint32,
        }
    }
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct c_void {}

pub fn write_keys_to_file(
    cks: Vec<u8>,
    cks_path: &str,
    pks: Vec<u8>,
    pks_path: &str,
    sks: Vec<u8>,
    sks_path: &str) -> bool {
    if let Err(e) = std::fs::write(cks_path, cks) {
        println!(
            "Failed to write cks to path: {:?}. Error: {:?}",
            cks_path, e
        );
        return false;
    };

    if let Err(e) = std::fs::write(sks_path, sks) {
        println!(
            "Failed to write sks to path: {:?}. Error: {:?}",
            sks_path, e
        );
        return false;
    };

    if let Err(e) = std::fs::write(pks_path, pks) {
        println!(
            "Failed to write pks to path: {:?}. Error: {:?}",
            pks_path, e
        );
        return false;
    };

    true

}

#[no_mangle]
pub unsafe extern "C" fn generate_full_keys(
    path_to_cks: *const std::ffi::c_char,
    path_to_sks: *const std::ffi::c_char,
    path_to_pks: *const std::ffi::c_char,
) -> bool {
    let (c_str_cks, c_str_sks, c_str_pks) = unsafe {
        (
            std::ffi::CStr::from_ptr(path_to_cks),
            std::ffi::CStr::from_ptr(path_to_sks),
            std::ffi::CStr::from_ptr(path_to_pks),
        )
    };

    let cks_path_str = match c_str_cks.to_str() {
        Err(_) => return false,
        Ok(s) => s,
    };

    let sks_path_str = match c_str_sks.to_str() {
        Err(_) => return false,
        Ok(s) => s,
    };

    let pks_path_str = match c_str_pks.to_str() {
        Err(_) => return false,
        Ok(s) => s,
    };

    let (cks, sks, pks) = generate_keys_safe();

    write_keys_to_file(cks, cks_path_str, pks, pks_path_str, sks, sks_path_str)
}

#[no_mangle]
pub unsafe extern "C" fn math_operation(
    lhs: ByteSliceView,
    rhs: ByteSliceView,
    operation: Op,
    uint_type: FheUintType,
    err_msg: Option<&mut UnmanagedVector>,
) -> UnmanagedVector {
    let (lhs_slice, rhs_slice) = match (lhs.read(), rhs.read()) {
        (Some(k1), Some(k2)) => (k1, k2),
        _ => {
            log::debug!("Failed to decode one or more inputs");
            set_error(
                RustError::generic_error("failed to read input server key"),
                err_msg,
            );
            return UnmanagedVector::none();
        }
    };

    let result = match uint_type {
        FheUintType::Uint8 => op_uint8(lhs_slice, rhs_slice, operation),
        FheUintType::Uint16 => op_uint16(lhs_slice, rhs_slice, operation),
        FheUintType::Uint32 => op_uint32(lhs_slice, rhs_slice, operation),
    };

    let result = handle_c_error_binary(result, err_msg);
    UnmanagedVector::new(Some(result))
}

#[no_mangle]
pub unsafe extern "C" fn load_server_key(
    key: ByteSliceView,
    err_msg: Option<&mut UnmanagedVector>,
) {
    if let Some(server_key_slice) = key.read() {
        let r = load_server_key_safe(server_key_slice);

        handle_c_error_default(r, err_msg)
    } else {
        log::debug!("Failed to read input server key");
        set_error(
            RustError::generic_error("failed to read input server key"),
            err_msg,
        );
    }
}

#[no_mangle]
pub unsafe extern "C" fn load_client_key(
    key: ByteSliceView,
    err_msg: Option<&mut UnmanagedVector>,
) {
    if let Some(client_key_slice) = key.read() {
        let r = deserialize_client_key_safe(client_key_slice);

        handle_c_error_default(r, err_msg)
    } else {
        log::debug!("Failed to read input client key");
        set_error(
            RustError::generic_error("failed to read input client key"),
            err_msg,
        );
    };
}

#[no_mangle]
pub unsafe extern "C" fn load_public_key(
    key: ByteSliceView,
    err_msg: Option<&mut UnmanagedVector>,
) {
    if let Some(public_key_slice) = key.read() {
        let r = deserialize_public_key_safe(public_key_slice);

        handle_c_error_default(r, err_msg)
    } else {
        log::debug!("Failed to read input public key");
        set_error(
            RustError::generic_error("failed to read public key"),
            err_msg,
        );
    }
}

#[no_mangle]
pub unsafe extern "C" fn get_public_key(err_msg: Option<&mut UnmanagedVector>) -> UnmanagedVector {
    let public_key = GlobalKeys::get_public_key();

    if public_key.is_none() {
        set_error(RustError::generic_error("public key not set"), err_msg);
        return UnmanagedVector::none();
    }

    let serialized = bincode::serialize(public_key.unwrap()).map_err(|err| {
        log::debug!("failed to serialize public key: {:?}", err);
        RustError::generic_error("public key not set")
    });

    let result = handle_c_error_binary(serialized, err_msg);
    UnmanagedVector::new(Some(result))
}

#[no_mangle]
pub unsafe extern "C" fn expand_compressed(
    ciphertext: ByteSliceView,
    int_type: FheUintType,
    err_msg: Option<&mut UnmanagedVector>,
) -> UnmanagedVector {
    let ciphertext_slice = ciphertext.read();

    if ciphertext_slice.is_none() {
        set_error(
            RustError::generic_error("ciphertext cannot be empty"),
            err_msg,
        );
        return UnmanagedVector::none();
    }

    let r = expand_compressed_safe(ciphertext_slice.unwrap(), int_type);

    let result = handle_c_error_binary(r, err_msg);
    UnmanagedVector::new(Some(result))
}

#[no_mangle]
pub unsafe extern "C" fn trivial_encrypt(
    msg: u64,
    int_type: FheUintType,
    err_msg: Option<&mut UnmanagedVector>,
) -> UnmanagedVector {
    let r = trivial_encrypt_safe(msg, int_type);

    let result = handle_c_error_binary(r, err_msg);
    UnmanagedVector::new(Some(result))
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

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub unsafe extern "C" fn banana() {
    // let cks_bytes = include_bytes!("../../../keys/tfhe/cks");
    // let sks_bytes = include_bytes!("../../../keys/tfhe/sks");
    // let pks_bytes = include_bytes!("../../../keys/tfhe/pks");

    // let cks = bincode::deserialize::<ClientKey>(cks_bytes).unwrap();
    // let sks = bincode::deserialize::<ServerKey>(sks_bytes).unwrap();
    // let pks = bincode::deserialize::<CompactPublicKey>(pks_bytes).unwrap();

    console_log("gm");

    console_log("generting keys (~15 seconds)...");

    let config = ConfigBuilder::all_disabled()
        .enable_custom_integers(KEYGEN_PARAMS, None)
        .build();
    let (cks, sks) = generate_keys(config);
    let pks: CompactPublicKey = CompactPublicKey::new(&cks);

    console_log("set_client_key...");

    match GlobalKeys::set_client_key(cks) {
        Ok(_) => {}
        Err(err) => {
            console_log(format!("error: {:?}", err).as_str());
            panic!("error: {:?}", err);
        }
    }

    console_log("set_server_key...");

    tfhe::set_server_key(sks);

    console_log("set_public_key...");

    match GlobalKeys::set_public_key(pks) {
        Ok(_) => {}
        Err(err) => {
            console_log(format!("error: {:?}", err).as_str());
            panic!("error: {:?}", err);
        }
    }

    console_log("encrypt_safe(10)...");

    let ten = match encrypt_safe(10, Uint8) {
        Ok(ten) => ten,
        Err(err) => {
            console_log(format!("error: {:?}", err).as_str());
            panic!("error: {:?}", err);
        }
    };

    console_log("encrypt_safe(20)...");

    let twenty = match encrypt_safe(20, Uint8) {
        Ok(ten) => ten,
        Err(err) => {
            console_log(format!("error: {:?}", err).as_str());
            panic!("error: {:?}", err);
        }
    };

    console_log("res = op_uint8(10, 20, add)...");

    let res = match op_uint8(ten.as_slice(), twenty.as_slice(), Op::Add) {
        Ok(res) => res,
        Err(err) => {
            console_log(format!("error: {:?}", err).as_str());
            panic!("error: {:?}", err);
        }
    };

    console_log("decrypt_safe(res)...");

    match decrypt_safe(res.as_slice(), Uint8) {
        Ok(decrypted) => {
            console_log(format!("decrypted: {}", decrypted).as_str());

            if decrypted != 30 {
                panic!(
                    "error: got wrong decrypted value. Expected: {}, got: {}",
                    30, decrypted
                );
            }
        }
        Err(err) => {
            console_log(format!("error: {:?}", err).as_str());
            panic!("error: {:?}", err);
        }
    }

    wavm_halt_and_set_finished();
}

#[no_mangle]
pub unsafe extern "C" fn decrypt(
    ciphertext: ByteSliceView,
    int_type: FheUintType,
    err_msg: Option<&mut UnmanagedVector>,
) -> u64 {
    let ciphertext_slice = ciphertext.read();

    if ciphertext_slice.is_none() {
        set_error(
            RustError::generic_error("ciphertext cannot be empty"),
            err_msg,
        );
        return 0;
    }

    let r = decrypt_safe(ciphertext_slice.unwrap(), int_type);

    handle_c_error_default(r, err_msg)
}

