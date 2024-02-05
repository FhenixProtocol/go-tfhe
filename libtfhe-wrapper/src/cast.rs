#[macro_use]
use crate::error::RustError;
use crate::serialization::*;
// use tfhe::prelude::*;
use tfhe::{
    CompactFheUint128, CompactFheUint16, CompactFheUint256, CompactFheUint32, CompactFheUint64,
    CompactFheUint8, FheUint128, FheUint16, FheUint256, FheUint32, FheUint64, FheUint8,
};

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

// Defining cast from FheUint8
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
    cast_from_uint8_to_uint64,
    deserialize_fhe_uint8,
    FheUint8,
    FheUint64
);
define_cast_fn!(
    cast_from_uint8_to_uint128,
    deserialize_fhe_uint8,
    FheUint8,
    FheUint128
);
define_cast_fn!(
    cast_from_uint8_to_uint256,
    deserialize_fhe_uint8,
    FheUint8,
    FheUint256
);

// Defining cast from FheUint16
define_cast_fn!(
    cast_from_uint16_to_uint8,
    deserialize_fhe_uint16,
    FheUint16,
    FheUint8
);
define_cast_fn!(
    cast_from_uint16_to_uint32,
    deserialize_fhe_uint16,
    FheUint16,
    FheUint32
);
define_cast_fn!(
    cast_from_uint16_to_uint64,
    deserialize_fhe_uint16,
    FheUint16,
    FheUint64
);
define_cast_fn!(
    cast_from_uint16_to_uint128,
    deserialize_fhe_uint16,
    FheUint16,
    FheUint128
);
define_cast_fn!(
    cast_from_uint16_to_uint256,
    deserialize_fhe_uint16,
    FheUint16,
    FheUint256
);

// Defining cast from FheUint32
define_cast_fn!(
    cast_from_uint32_to_uint8,
    deserialize_fhe_uint32,
    FheUint32,
    FheUint8
);
define_cast_fn!(
    cast_from_uint32_to_uint16,
    deserialize_fhe_uint32,
    FheUint32,
    FheUint16
);
define_cast_fn!(
    cast_from_uint32_to_uint64,
    deserialize_fhe_uint32,
    FheUint32,
    FheUint64
);
define_cast_fn!(
    cast_from_uint32_to_uint128,
    deserialize_fhe_uint32,
    FheUint32,
    FheUint128
);
define_cast_fn!(
    cast_from_uint32_to_uint256,
    deserialize_fhe_uint32,
    FheUint32,
    FheUint256
);

// Defining cast from FheUint64
define_cast_fn!(
    cast_from_uint64_to_uint8,
    deserialize_fhe_uint64,
    FheUint64,
    FheUint8
);
define_cast_fn!(
    cast_from_uint64_to_uint16,
    deserialize_fhe_uint64,
    FheUint64,
    FheUint16
);
define_cast_fn!(
    cast_from_uint64_to_uint32,
    deserialize_fhe_uint64,
    FheUint64,
    FheUint32
);
define_cast_fn!(
    cast_from_uint64_to_uint128,
    deserialize_fhe_uint64,
    FheUint64,
    FheUint128
);
define_cast_fn!(
    cast_from_uint64_to_uint256,
    deserialize_fhe_uint64,
    FheUint64,
    FheUint256
);

// Defining cast from FheUint128
define_cast_fn!(
    cast_from_uint128_to_uint8,
    deserialize_fhe_uint128,
    FheUint128,
    FheUint8
);
define_cast_fn!(
    cast_from_uint128_to_uint16,
    deserialize_fhe_uint128,
    FheUint128,
    FheUint16
);
define_cast_fn!(
    cast_from_uint128_to_uint32,
    deserialize_fhe_uint128,
    FheUint128,
    FheUint32
);
define_cast_fn!(
    cast_from_uint128_to_uint64,
    deserialize_fhe_uint128,
    FheUint128,
    FheUint64
);
define_cast_fn!(
    cast_from_uint128_to_uint256,
    deserialize_fhe_uint128,
    FheUint128,
    FheUint256
);

define_cast_fn!(
    cast_from_uint256_to_uint8,
    deserialize_fhe_uint256,
    FheUint256,
    FheUint8
);

define_cast_fn!(
    cast_from_uint256_to_uint16,
    deserialize_fhe_uint256,
    FheUint256,
    FheUint16
);
define_cast_fn!(
    cast_from_uint256_to_uint32,
    deserialize_fhe_uint256,
    FheUint256,
    FheUint32
);
define_cast_fn!(
    cast_from_uint256_to_uint64,
    deserialize_fhe_uint256,
    FheUint256,
    FheUint64
);
define_cast_fn!(
    cast_from_uint256_to_uint128,
    deserialize_fhe_uint256,
    FheUint256,
    FheUint128
);
