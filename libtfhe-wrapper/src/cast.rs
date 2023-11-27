use crate::error::RustError;
use crate::serialization::*;
use tfhe::{FheUint16, FheUint32, FheUint8};

macro_rules! define_cast_fn {
    ($func_name:ident, $deserialize_func:ident, $from_type:ty, $to_type:ty) => {
        #[export_name = stringify!($func_name)]
        pub(crate) fn $func_name(val: &[u8]) -> Result<Vec<u8>, RustError> {
            match $deserialize_func(val, false) {
                Ok(v) => {
                    let out = <$to_type>::cast_from(v);
                    bincode::serialize(&out).map_err(|err| {
                        log::error!("failed serializing value: {:?}", err);
                        RustError::generic_error(format!("failed serializing result for cast"))
                    })
                }
                Err(e) => {
                    log::error!("failed deserializing value: {:?}", e);
                    Err(RustError::generic_error(format!(
                        "failed deserializing value: {:?}",
                        e
                    )))
                }
            }
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
