use crate::api::Op;
use crate::error::RustError;
use crate::keys::GlobalKeys;
use serde::Serialize;
use std::ops::{Add, Mul, Sub};
use tfhe::prelude::*;

use crate::serialization::{deserialize_fhe_uint16, deserialize_fhe_uint32, deserialize_fhe_uint8};

/// Performs the specified operation on two encrypted x-bit unsigned integers.
///
/// This function deserializes the inputs, performs the specified operation, and
/// returns the serialized result.
///
///
/// # Arguments
///
/// * `lhs` - The left-hand side operand.
/// * `rhs` - The right-hand side operand.
/// * `operation` - The operation to perform.
///
/// # Returns
///
/// A `Vec<u8>` containing the serialized result, or `RustError`
macro_rules! define_op_fn {
    ($func_name:ident, $deserialize_func:ident, $type:ty) => {
        #[export_name = stringify!($func_name)]
        pub fn $func_name(lhs: &[u8], rhs: &[u8], operation: Op) -> Result<Vec<u8>, RustError> {
            common_op(
                $deserialize_func(lhs, false).unwrap(),
                $deserialize_func(rhs, false).unwrap(),
                operation,
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
    T: Add<Output = T> + Sub<Output = T> + Mul<Output = T> + FheOrd<Output = T> + FheEq + Serialize,
>(
    num1: T,
    num2: T,
    operation: Op,
) -> Result<Vec<u8>, RustError> {
    if !GlobalKeys::is_server_key_set() {
        return Err(RustError::generic_error(
            "server key must be set for math operation",
        ));
    }
    GlobalKeys::refresh_server_key_for_thread();

    let result = match operation {
        Op::Add => num1 + num2,
        Op::Sub => num1 - num2,
        Op::Mul => num1 * num2,
        Op::Lt => num1.lt(num2),
        Op::Lte => num1.le(num2),
    };

    bincode::serialize(&result).map_err(|err| {
        log::debug!("failed to serialize result: {:?}", err);
        RustError::generic_error(format!(
            "failed to serialize result after operation: {:?}",
            operation
        ))
    })
}
