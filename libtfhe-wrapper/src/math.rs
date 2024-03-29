use crate::api::{Op, UnaryOp};
use crate::error::RustError;
use crate::keys::GlobalKeys;
use serde::Serialize;
use std::ops::{Add, BitAnd, BitOr, BitXor, Div, Mul, Not, Rem, Shl, Shr, Sub};
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
            match ($deserialize_func(lhs, false), $deserialize_func(rhs, false)) {
                (Err(e), _) => {
                    log::error!("failed deserializing lhs value: {:?}", e);
                    Err(RustError::generic_error(format!(
                        "failed deserializing lhs value: {:?}",
                        e
                    )))
                }
                (_, Err(e)) => {
                    log::error!("failed deserializing rhs value: {:?}", e);
                    Err(RustError::generic_error(format!(
                        "failed deserializing rhs value: {:?}",
                        e
                    )))
                }
                (Ok(l), Ok(r)) => common_op(l, r, operation),
            }
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
        + Div<Output = T>
        + BitAnd<Output = T>
        + BitOr<Output = T>
        + BitXor<Output = T>
        + Rem<Output = T>
        + FheOrd<Output = T>
        + FheEq<Output = T>
        + for<'a> FheMin<&'a T, Output = T>
        + for<'a> FheMax<&'a T, Output = T>
        + Shl<Output = T>
        + Shr<Output = T>
        + Serialize,
>(
    num1: T,
    num2: T,
    operation: Op,
) -> Result<Vec<u8>, RustError> {
    GlobalKeys::refresh_server_key_for_thread();

    let result = match operation {
        Op::Add => num1 + num2,
        Op::Sub => num1 - num2,
        Op::Mul => num1 * num2,
        Op::Lt => num1.lt(num2),
        Op::Lte => num1.le(num2),
        Op::Div => num1 / num2,
        Op::Gt => num1.gt(num2),
        Op::Gte => num1.ge(num2),
        Op::Rem => num1 % num2,
        Op::BitAnd => num1 & num2,
        Op::BitOr => num1 | num2,
        Op::BitXor => num1 ^ num2,
        Op::Eq => num1.eq(num2),
        Op::Ne => num1.ne(num2),
        Op::Min => num1.min(&num2),
        Op::Max => num1.max(&num2),
        Op::Shl => num1 << num2,
        Op::Shr => num1 >> num2,
    };

    bincode::serialize(&result).map_err(|err| {
        log::error!("failed serializing result: {:?}", err);
        RustError::generic_error(format!(
            "failed serializing result after operation: {:?}",
            operation
        ))
    })
}

/// Performs the specified operation on an encrypted x-bit unsigned integer.
///
/// This function deserializes the input, performs the specified operation, and
/// returns the serialized result.
///
///
/// # Arguments
///
/// * `lhs` - The operand.
/// * `operation` - The operation to perform.
///
/// # Returns
///
/// A `Vec<u8>` containing the serialized result, or `RustError`
macro_rules! define_unary_op_fn {
    ($func_name:ident, $deserialize_func:ident, $type:ty) => {
        #[export_name = stringify!($func_name)]
        pub fn $func_name(lhs: &[u8], operation: UnaryOp) -> Result<Vec<u8>, RustError> {
            unary_op($deserialize_func(lhs, false).unwrap(), operation)
        }
    };
}

// Use the macro to define the functions
define_unary_op_fn!(unary_op_uint8, deserialize_fhe_uint8, FheUint8);
define_unary_op_fn!(unary_op_uint16, deserialize_fhe_uint16, FheUint16);
define_unary_op_fn!(unary_op_uint32, deserialize_fhe_uint32, FheUint32);

/// A generic function that performs the given operation on a single encrypted number.
///
/// This function is used internally by the other `op_` functions to
/// perform the actual arithmetic. It's generic over the type of the operand.
///
/// # Arguments
///
/// * `num1` - The operand.
/// * `operation` - The operation to perform.
/// * `err_msg` - A mutable reference to an `UnmanagedVector` that can contain error messages.
///
/// # Returns
///
/// An `UnmanagedVector` containing the serialized result.
fn unary_op<T: Not<Output = T> + Serialize>(
    num1: T,
    operation: UnaryOp,
) -> Result<Vec<u8>, RustError> {
    GlobalKeys::refresh_server_key_for_thread();

    let result = match operation {
        UnaryOp::Not => !num1,
        // todo add remaining unary ops
    };

    bincode::serialize(&result).map_err(|err| {
        log::debug!("failed to serialize result: {:?}", err);
        RustError::generic_error(format!(
            "failed to serialize result after operation: {:?}",
            operation
        ))
    })
}
