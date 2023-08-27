use crate::api::Op;
use crate::error::{handle_c_error_binary, RustError};
use crate::keys::SERVER_KEY;
use crate::memory::{ByteSliceView, UnmanagedVector};
use serde::Serialize;
use std::ops::{Add, Mul, Sub};
use std::panic::{catch_unwind, UnwindSafe};
use tfhe::prelude::FheOrd;
use tfhe::prelude::*;

use log::error;

use crate::serialization::{deserialize_fhe_uint16, deserialize_fhe_uint32, deserialize_fhe_uint8};

/// Performs the specified operation on two encrypted x-bit unsigned integers.
///
/// This function deserializes the inputs, performs the specified operation, and
/// returns the serialized result. The `err_msg` parameter can be used to pass
/// back error messages to the caller.
///
/// # Safety
///
/// This function is marked `unsafe` because it performs unchecked operations on
/// raw pointers passed from C code.
///
/// # Arguments
///
/// * `lhs` - The left-hand side operand.
/// * `rhs` - The right-hand side operand.
/// * `operation` - The operation to perform.
/// * `err_msg` - A mutable reference to an `UnmanagedVector` that can contain error messages.
///
/// # Returns
///
/// An `UnmanagedVector` containing the serialized result.
macro_rules! define_op_fn {
    ($func_name:ident, $deserialize_func:ident, $type:ty) => {
        #[no_mangle]
        #[export_name = stringify!($func_name)]
        pub unsafe extern "C" fn $func_name(
            lhs: ByteSliceView,
            rhs: ByteSliceView,
            operation: Op,
            err_msg: Option<&mut UnmanagedVector>,
        ) -> UnmanagedVector {
            let lhs_slice = lhs.read().unwrap();
            let rhs_slice = rhs.read().unwrap();

            common_op(
                $deserialize_func(lhs_slice, false).unwrap(),
                $deserialize_func(rhs_slice, false).unwrap(),
                operation,
                err_msg,
            )
        }
    };
}

// Use the macro to define the functions
define_op_fn!(op_uint8, deserialize_fhe_uint8, FheUint8);
define_op_fn!(op_uint16, deserialize_fhe_uint16, FheUint16);
define_op_fn!(op_uint32, deserialize_fhe_uint32, FheUint32);

/// A generic function that performs the given operation on two encrypted numbers.
///
/// This function is used internally by the other `op_` functions to
/// perform the actual arithmetic. It's generic over the type of the operands.
///
/// # Arguments
///
/// * `num1` - The first operand.
/// * `num2` - The second operand.
/// * `operation` - The operation to perform.
/// * `err_msg` - A mutable reference to an `UnmanagedVector` that can contain error messages.
///
/// # Returns
///
/// An `UnmanagedVector` containing the serialized result.
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
    // todo (eshel) verify that the key is loaded into zama lib
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

        bincode::serialize(&result).unwrap()
    })
    .map_err(|err| {
        error!("Panic in op_uint8: {:?}", err);
        RustError::generic_error("failed to perform operation on u8")
    });

    let result = handle_c_error_binary(r, err_msg);
    UnmanagedVector::new(Some(result))
}
