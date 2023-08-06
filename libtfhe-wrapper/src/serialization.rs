use crate::memory::ByteSliceView;
use tfhe::{FheUint16, FheUint32, FheUint8};

pub(crate) fn deserialize_fhe_uint8(
    slice: ByteSliceView,
) -> Result<FheUint8, Box<bincode::ErrorKind>> {
    bincode::deserialize::<FheUint8>(slice.read().unwrap())
}

// Function for deserializing FheUint16
pub(crate) fn deserialize_fhe_uint16(
    slice: ByteSliceView,
) -> Result<FheUint16, Box<bincode::ErrorKind>> {
    bincode::deserialize::<FheUint16>(slice.read().unwrap())
}

// Function for deserializing FheUint32
pub(crate) fn deserialize_fhe_uint32(
    slice: ByteSliceView,
) -> Result<FheUint32, Box<bincode::ErrorKind>> {
    bincode::deserialize::<FheUint32>(slice.read().unwrap())
}
