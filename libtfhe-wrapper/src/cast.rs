use crate::error::RustError;
use crate::serialization::*;
use tfhe::{FheUint16, FheUint32, FheUint8};

// pub(crate) fn cast_impl<FromType, ToType>(val: &[u8]) -> Result<Vec<u8>, RustError> {
//     let mut from: FromType;
//     deserialize_fhe_uint_impl(&mut from, val, false).unwrap();
//     let out = ToType::cast_from(from);
//     bincode::serialize(&out).map_err(|err| {
//         log::debug!("failed to serialize result: {:?}", err);
//         RustError::generic_error(format!("failed to serialize result for cast"))
//     })
// }

/// A generic function that performs the given cast on an encrypted number.
///
/// # Template
/// * `ToType` - The type to convert to
///
/// # Arguments
///
/// * `val` - The value to be converted.
///
/// # Returns
///
macro_rules! define_cast_fn {
    ($func_name:ident, $deserialize_func:ident, $from_type:ty, $to_type:ty) => {
        #[export_name = stringify!($func_name)]
        pub(crate) fn $func_name(val: &[u8]) -> Result<Vec<u8>, RustError> {
            let i: $from_type = $deserialize_func(val, false).unwrap();
            let out = <$to_type>::cast_from(i);
            bincode::serialize(&out).map_err(|err| {
                log::debug!("failed to serialize result: {:?}", err);
                RustError::generic_error(format!("failed to serialize result for cast"))
            })
        }
    };
}

// Use the macro to define the functions
define_cast_fn!(
    cast_from_uint8_to_uint16,
    deserialize_fhe_uint8,
    FheUint8,
    FheUint16
);
define_cast_fn!(
    cast_from_uint8_to_uint32,
    deserialize_fhe_uint8,
    FheUint8,
    FheUint32
);
define_cast_fn!(
    cast_from_uint16_to_uint8,
    deserialize_fhe_uint8,
    FheUint8,
    FheUint8
);
define_cast_fn!(
    cast_from_uint16_to_uint32,
    deserialize_fhe_uint8,
    FheUint8,
    FheUint32
);
define_cast_fn!(
    cast_from_uint32_to_uint8,
    deserialize_fhe_uint8,
    FheUint8,
    FheUint8
);
define_cast_fn!(
    cast_from_uint32_to_uint16,
    deserialize_fhe_uint8,
    FheUint8,
    FheUint16
);
