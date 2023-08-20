use crate::api::Op;
use crate::error::{handle_c_error_binary, RustError};
use crate::keys::SERVER_KEY;
use crate::memory::{ByteSliceView, UnmanagedVector};
use serde::Serialize;
use std::ops::{Add, Mul, Sub};
use std::panic::{catch_unwind, UnwindSafe};
use tfhe::prelude::FheOrd;
use tfhe::prelude::*;
use tfhe::{FheUint16, FheUint32, FheUint8};

use crate::serialization::{deserialize_fhe_uint16, deserialize_fhe_uint32, deserialize_fhe_uint8};

#[no_mangle]
pub unsafe extern "C" fn op_uint8(
    lhs: ByteSliceView,
    rhs: ByteSliceView,
    operation: Op,
    err_msg: Option<&mut UnmanagedVector>,
) -> UnmanagedVector {

    let lhs_slice = lhs.read().unwrap();
    let rhs_slice = rhs.read().unwrap();

    common_op(
        deserialize_fhe_uint8(lhs_slice).unwrap(),
        deserialize_fhe_uint8(rhs_slice).unwrap(),
        operation,
        err_msg,
    )
}

#[no_mangle]
pub unsafe extern "C" fn op_uint16(
    lhs: ByteSliceView,
    rhs: ByteSliceView,
    operation: Op,
    err_msg: Option<&mut UnmanagedVector>,
) -> UnmanagedVector {

    let lhs_slice = lhs.read().unwrap();
    let rhs_slice = rhs.read().unwrap();

    common_op(
        deserialize_fhe_uint16(lhs_slice).unwrap(),
        deserialize_fhe_uint16(rhs_slice).unwrap(),
        operation,
        err_msg,
    )
}

#[no_mangle]
pub unsafe extern "C" fn op_uint32(
    lhs: ByteSliceView,
    rhs: ByteSliceView,
    operation: Op,
    err_msg: Option<&mut UnmanagedVector>,
) -> UnmanagedVector {

    let lhs_slice = lhs.read().unwrap();
    let rhs_slice = rhs.read().unwrap();

    common_op(
        deserialize_fhe_uint32(lhs_slice).unwrap(),
        deserialize_fhe_uint32(rhs_slice).unwrap(),
        operation,
        err_msg,
    )
}

fn common_op<
    T: Add<Output = T>
        + Sub<Output = T>
        + Mul<Output = T>
        + FheOrd<Output = T>
        + FheEq
        + Serialize
        + UnwindSafe,
>(
    num1: T,
    num2: T,
    operation: Op,
    err_msg: Option<&mut UnmanagedVector>,
) -> UnmanagedVector {
    let server_key_guard = SERVER_KEY.lock().unwrap();

    let r: Result<Vec<u8>, RustError> = catch_unwind(|| {
        match *server_key_guard {
            true => {}
            false => panic!("Server key not set"), // Return an error or handle this case appropriately.
        };

        let result = match operation {
            Op::Add => num1 + num2,
            Op::Sub => num1 - num2,
            Op::Mul => num1 * num2,
            Op::Lt => num1.lt(num2),
            Op::Lte => num1.le(num2),
        };

        let r = bincode::serialize(&result).unwrap();

        r
    })
    .map_err(|err| {
        eprintln!("Panic in op_uint8: {:?}", err);
        RustError::generic_error("lol")
    });

    let result = handle_c_error_binary(r, err_msg);
    UnmanagedVector::new(Some(result))
}
