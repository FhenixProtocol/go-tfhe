use crate::api::ffi::error::{handle_c_error_binary, handle_c_error_default, set_error};
use crate::api::ffi::memory::{ByteSliceView, UnmanagedVector};
use crate::cast::*;
use crate::encryption::{decrypt_safe, encrypt_safe, expand_compressed_safe, trivial_encrypt_safe};
use crate::error::RustError;
use crate::keys::GlobalKeys;
use crate::keys::{
    deserialize_client_key_safe, deserialize_public_key_safe, generate_keys_safe,
    load_server_key_safe,
};

use crate::math::{
    op_uint16, op_uint32, op_uint8, unary_op_uint16, unary_op_uint32, unary_op_uint8,
};

use std::panic::catch_unwind;

#[cfg(target_arch = "wasm32")]
use tfhe::{
    generate_keys, shortint::parameters::PARAM_MESSAGE_2_CARRY_2_COMPACT_PK as KEYGEN_PARAMS,
    CompactPublicKey, ConfigBuilder,
};

#[cfg(target_arch = "wasm32")]
use crate::imports::{console_log, wavm_halt_and_set_finished};

/// cbindgen:prefix-with-name
#[repr(i32)]
#[derive(Debug)]
pub enum Op {
    Add = 0,
    Sub = 1,
    Mul = 2,
    Lt = 3,
    Lte = 4,
    Div = 5,
    Gt = 6,
    Gte = 7,
    Rem = 8,
    BitAnd = 9,
    BitOr = 10,
    BitXor = 11,
    Eq = 12,
    Ne = 13,
    Min = 14,
    Max = 15,
    Shl = 16,
    Shr = 17
}

#[repr(i32)]
#[derive(Debug)]
pub enum UnaryOp {
    Not = 0,
}

impl From<u32> for UnaryOp {
    fn from(value: u32) -> Self {
        match value {
            0 => UnaryOp::Not,
            _ => UnaryOp::Not,
        }
    }
}

impl From<u32> for Op {
    fn from(value: u32) -> Self {
        match value {
            0 => Op::Add,
            1 => Op::Sub,
            2 => Op::Mul,
            3 => Op::Lt,
            4 => Op::Lte,
            5 => Op::Div,
            6 => Op::Gt,
            7 => Op::Gte,
            8 => Op::Rem,
            9 => Op::BitAnd,
            10 => Op::BitOr,
            11 => Op::BitXor,
            12 => Op::Eq,
            13 => Op::Ne,
            14 => Op::Min,
            15 => Op::Max,
            16 => Op::Shl,
            17 => Op::Shr,
            _ => Op::Add,
        }
    }
}

/// cbindgen:prefix-with-name
#[repr(i32)]
#[derive(Clone, Copy, Debug)]
pub enum FheUintType {
    Uint8 = 0,
    Uint16 = 1,
    Uint32 = 2,
}

impl From<u32> for FheUintType {
    fn from(value: u32) -> Self {
        match value {
            0 => FheUintType::Uint8,
            1 => FheUintType::Uint16,
            2 => FheUintType::Uint32,
            _ => FheUintType::Uint32,
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
    sks_path: &str,
) -> bool {
    if let Err(e) = std::fs::write(cks_path, cks) {
        log::error!("failed writing cks to path: {:?}. Error: {:?}", cks_path, e);
        return false;
    };

    if let Err(e) = std::fs::write(sks_path, sks) {
        log::error!("failed writing sks to path: {:?}. Error: {:?}", sks_path, e);
        return false;
    };

    if let Err(e) = std::fs::write(pks_path, pks) {
        log::error!("failed writing pks to path: {:?}. Error: {:?}", pks_path, e);
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

#[cfg(target_arch = "wasm32")]
#[no_mangle]
#[allow(improper_ctypes_definitions)]
// todo: When we actually integrate this it's going to be a challenge to make sure
// wasm and non-wasm return the exact same results - as such, maybe we should transition
// away from cgo structs in the ffi for the amd64 target as well? :(
pub unsafe extern "C" fn math_operation_wasm(
    lhs: *mut u8,
    lhs_len: u64,
    rhs: *const u8,
    rhs_len: u64,
    operation: u32,
    uint_type: u32,
) -> (*const u8, u64) {
    let lhs_slice: &[u8] = unsafe { std::slice::from_raw_parts(lhs, lhs_len as usize) };
    let rhs_slice: &[u8] = unsafe { std::slice::from_raw_parts(rhs, rhs_len as usize) };
    let op_type = Op::from(operation);
    let fhe_type = FheUintType::from(uint_type);

    let err: Option<&mut UnmanagedVector> = None;

    let x = math_operation(
        ByteSliceView::new(lhs_slice),
        ByteSliceView::new(rhs_slice),
        op_type,
        fhe_type,
        err,
    );
    // if err.is_none() {
    //     return (null(), 0)
    // }
    return (x.ptr, x.len as u64);
}

pub fn math_operation_helper(
    lhs: &[u8],
    rhs: &[u8],
    operation: Op,
    uint_type: FheUintType,
) -> Result<Vec<u8>, RustError> {
    let result = catch_unwind(|| {
        match uint_type {
            FheUintType::Uint8 => op_uint8(lhs, rhs, operation),
            FheUintType::Uint16 => op_uint16(lhs, rhs, operation),
            FheUintType::Uint32 => op_uint32(lhs, rhs, operation),
        }
    });

    match result {
        Ok(Ok(x)) => Ok(x),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(RustError::math_panic(format!("panic in math operation: {:#?}", e.downcast_ref::<&str>()))),
    }
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
            log::error!("failed decoding one or more inputs");
            set_error(
                RustError::generic_error("failed reading input server key"),
                err_msg,
            );
            return UnmanagedVector::none();
        }
    };

    let inner_result = math_operation_helper(lhs_slice, rhs_slice, operation, uint_type);

    let result = handle_c_error_binary(inner_result, err_msg);
    UnmanagedVector::new(Some(result))
}

#[no_mangle]
pub unsafe extern "C" fn unary_math_operation(
    lhs: ByteSliceView,
    operation: UnaryOp,
    uint_type: FheUintType,
    err_msg: Option<&mut UnmanagedVector>,
) -> UnmanagedVector {
    let lhs_slice = match lhs.read() {
        Some(k1) => k1,
        _ => {
            log::debug!("Failed to decode input");
            set_error(
                RustError::generic_error("failed to read input server key"),
                err_msg,
            );
            return UnmanagedVector::none();
        }
    };

    let result = unary_operation_helper(lhs_slice, operation, uint_type);

    let result = handle_c_error_binary(result, err_msg);
    UnmanagedVector::new(Some(result))
}

fn unary_operation_helper(lhs_slice: &[u8], operation: UnaryOp, uint_type: FheUintType) -> Result<Vec<u8>, RustError> {
    let result_may_panic = catch_unwind(|| {
        match uint_type {
            FheUintType::Uint8 => unary_op_uint8(lhs_slice, operation),
            FheUintType::Uint16 => unary_op_uint16(lhs_slice, operation),
            FheUintType::Uint32 => unary_op_uint32(lhs_slice, operation),
        }
    });

    let result = match result_may_panic {
        Ok(Ok(x)) => Ok(x),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(RustError::math_panic(format!("panic in math operation: {:#?}", e.downcast_ref::<&str>()))),
    };
    result
}

#[no_mangle]
pub unsafe extern "C" fn cast_operation(
    val: ByteSliceView,
    from_type: FheUintType,
    to_type: FheUintType,
    err_msg: Option<&mut UnmanagedVector>,
) -> UnmanagedVector {
    let val_slice = match val.read() {
        Some(v1) => v1,
        _ => {
            log::error!("failed decoding an input");
            set_error(
                RustError::generic_error("failed reading input server key"),
                err_msg,
            );
            return UnmanagedVector::none();
        }
    };

    let inner_result = match from_type {
        FheUintType::Uint8 => match to_type {
            FheUintType::Uint8 => Ok(val_slice.to_vec()),
            FheUintType::Uint16 => cast_from_uint8_to_uint16(val_slice),
            FheUintType::Uint32 => cast_from_uint8_to_uint32(val_slice),
        },
        FheUintType::Uint16 => match to_type {
            FheUintType::Uint8 => cast_from_uint16_to_uint8(val_slice),
            FheUintType::Uint16 => Ok(val_slice.to_vec()),
            FheUintType::Uint32 => cast_from_uint16_to_uint32(val_slice),
        },
        FheUintType::Uint32 => match to_type {
            FheUintType::Uint8 => cast_from_uint32_to_uint8(val_slice),
            FheUintType::Uint16 => cast_from_uint32_to_uint16(val_slice),
            FheUintType::Uint32 => Ok(val_slice.to_vec()),
        },
    };

    let result = handle_c_error_binary(inner_result, err_msg);
    UnmanagedVector::new(Some(result))
}

#[no_mangle]
pub unsafe extern "C" fn cmux(
    control: ByteSliceView,
    if_true: ByteSliceView,
    if_false: ByteSliceView,
    uint_type: FheUintType,
    err_msg: Option<&mut UnmanagedVector>,
) -> UnmanagedVector {
    let (control_slice, if_true_slice, if_false_slice) =
        match (control.read(), if_true.read(), if_false.read()) {
            (Some(k1), Some(k2), Some(k3)) => (k1, k2, k3),
            _ => {
                log::error!("failed decoding an input");
                set_error(
                    RustError::generic_error("failed reading input server key"),
                    err_msg,
                );
                return UnmanagedVector::none();
            }
        };


    let result = perform_cmux(uint_type, control_slice, if_true_slice, if_false_slice);
    if result.is_err() {
        let result = handle_c_error_binary(result, err_msg);
        return UnmanagedVector::new(Some(result));
    }

    UnmanagedVector::new(Some(result.unwrap()))
}

/// Perform a conditional multiplexer (cmux) operation on Fully Homomorphic Encryption (FHE) data.
///
/// The cmux operation selects between `if_true_slice` and `if_false_slice` based on the `control_slice`.
/// If the `control_slice` is `1`, `if_true_slice` is selected; otherwise, `if_false_slice` is selected.
///
/// Basically the logic is:
///     let mask = if control == 0 { zero() } else { max_value() };
//      return (if_true & mask) | (if_false & !mask);
///
/// # Parameters
/// - `uint_type`: The FHE uint type indicating the size and properties of the encrypted data.
/// - `control_slice`: A slice representing the control bit in encrypted form.
/// - `if_true_slice`: A slice representing the 'true' option in encrypted form.
/// - `if_false_slice`: A slice representing the 'false' option in encrypted form.
///
/// # Returns
/// A `Result` containing either the encrypted result of the cmux operation or a `RustError`.
///
/// # Errors
/// Returns an error if any of the FHE operations fail.
fn perform_cmux(uint_type: FheUintType, control_slice: &[u8], if_true_slice: &[u8], if_false_slice: &[u8]) -> Result<Vec<u8>, RustError> {
    // Encrypt a 0 value as a base for creating a mask.
    let mut mask = trivial_encrypt_safe(0, uint_type)?;
    // Subtract the control slice from the mask, effectively creating an encryption of (0 - control).
    mask = math_operation_helper(mask.as_slice(), control_slice, Op::Sub, uint_type)?;

    // Invert the mask - either 0 or 0xFFFF....
    let inv_mask = unary_operation_helper(mask.as_slice(), UnaryOp::Not, uint_type)?;

    // Perform a bitwise AND operation on the mask and the if_true_slice.
    let left =
        math_operation_helper(mask.as_slice(), if_true_slice, Op::BitAnd, uint_type)?;

    // Perform a bitwise AND operation on the inverted mask and the if_false_slice.
    let right =
        math_operation_helper(inv_mask.as_slice(), if_false_slice, Op::BitAnd, uint_type)?;

    // Perform a bitwise OR operation on the two intermediate results.
    math_operation_helper(
        left.as_slice(),
        right.as_slice(),
        Op::BitOr,
        uint_type,
    )
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
        log::error!("failed reading input server key");
        set_error(
            RustError::generic_error("failed reading input server key"),
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
        log::error!("failed reading input client key");
        set_error(
            RustError::generic_error("failed reading input client key"),
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
        log::error!("failed reading input public key");
        set_error(
            RustError::generic_error("failed reading public key"),
            err_msg,
        );
    }
}

#[no_mangle]
pub unsafe extern "C" fn get_public_key(err_msg: Option<&mut UnmanagedVector>) -> UnmanagedVector {
    let public_key = GlobalKeys::get_public_key();

    if public_key.is_none() {
        log::error!("public key not set");
        set_error(RustError::generic_error("public key not set"), err_msg);
        return UnmanagedVector::none();
    }

    let serialized = bincode::serialize(public_key.unwrap()).map_err(|err| {
        log::error!("failed serializing public key: {:?}", err);
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
        log::error!("ciphertext cannot be empty");
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

#[no_mangle]
pub unsafe extern "C" fn decrypt(
    ciphertext: ByteSliceView,
    int_type: FheUintType,
    err_msg: Option<&mut UnmanagedVector>,
) -> u64 {
    let ciphertext_slice = ciphertext.read();

    if ciphertext_slice.is_none() {
        log::error!("ciphertext cannot be empty");
        set_error(
            RustError::generic_error("ciphertext cannot be empty"),
            err_msg,
        );
        return 0;
    }

    let r = decrypt_safe(ciphertext_slice.unwrap(), int_type);

    handle_c_error_default(r, err_msg)
}

// #[cfg(target_arch = "wasm32")]
// #[no_mangle]
// pub unsafe extern "C" fn banana() {
//     // let cks_bytes = include_bytes!("../../../keys/tfhe/cks");
//     // let sks_bytes = include_bytes!("../../../keys/tfhe/sks");
//     // let pks_bytes = include_bytes!("../../../keys/tfhe/pks");
//
//     // let cks = bincode::deserialize::<ClientKey>(cks_bytes).unwrap();
//     // let sks = bincode::deserialize::<ServerKey>(sks_bytes).unwrap();
//     // let pks = bincode::deserialize::<CompactPublicKey>(pks_bytes).unwrap();
//
//     console_log("gm");
//
//     console_log("generting keys (~15 seconds)...");
//
//     let config = ConfigBuilder::all_disabled()
//         .enable_custom_integers(KEYGEN_PARAMS, None)
//         .build();
//     let (cks, sks) = generate_keys(config);
//     let pks: CompactPublicKey = CompactPublicKey::new(&cks);
//
//     console_log("set_client_key...");
//
//     match GlobalKeys::set_client_key(cks) {
//         Ok(_) => {}
//         Err(err) => {
//             console_log(format!("error: {:?}", err).as_str());
//             panic!("error: {:?}", err);
//         }
//     }
//
//     console_log("set_server_key...");
//
//     tfhe::set_server_key(sks);
//
//     console_log("set_public_key...");
//
//     match GlobalKeys::set_public_key(pks) {
//         Ok(_) => {}
//         Err(err) => {
//             console_log(format!("error: {:?}", err).as_str());
//             panic!("error: {:?}", err);
//         }
//     }
//
//     console_log("encrypt_safe(10)...");
//
//     let ten = match encrypt_safe(10, FheUintType::Uint8) {
//         Ok(ten) => ten,
//         Err(err) => {
//             console_log(format!("error: {:?}", err).as_str());
//             panic!("error: {:?}", err);
//         }
//     };
//
//     console_log("encrypt_safe(20)...");
//
//     let twenty = match encrypt_safe(20, FheUintType::Uint8) {
//         Ok(ten) => ten,
//         Err(err) => {
//             console_log(format!("error: {:?}", err).as_str());
//             panic!("error: {:?}", err);
//         }
//     };
//
//     console_log("res = op_uint8(10, 20, add)...");
//
//     let res = match op_uint8(ten.as_slice(), twenty.as_slice(), Op::Add) {
//         Ok(res) => res,
//         Err(err) => {
//             console_log(format!("error: {:?}", err).as_str());
//             panic!("error: {:?}", err);
//         }
//     };
//
//     console_log("decrypt_safe(res)...");
//
//     match decrypt_safe(res.as_slice(), FheUintType::Uint8) {
//         Ok(decrypted) => {
//             console_log(format!("decrypted: {}", decrypted).as_str());
//
//             if decrypted != 30 {
//                 panic!(
//                     "error: got wrong decrypted value. Expected: {}, got: {}",
//                     30, decrypted
//                 );
//             }
//         }
//         Err(err) => {
//             console_log(format!("error: {:?}", err).as_str());
//             panic!("error: {:?}", err);
//         }
//     }
//
//     wavm_halt_and_set_finished();
// }
