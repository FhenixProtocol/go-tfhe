use crate::memory::ByteSliceView;
use tfhe::{FheUint16, FheUint32, FheUint8, CompactFheUint8, CompactFheUint16, CompactFheUint32};

// todo: fix all of this

pub(crate) unsafe fn deserialize_fhe_uint8(
    slice: ByteSliceView,
) -> Result<FheUint8, Box<bincode::ErrorKind>> {
    let x: CompactFheUint8 = bincode::deserialize::<CompactFheUint8>(slice.read().unwrap())?;
    Ok(x.expand())
}

// Function for deserializing FheUint16
pub(crate) fn deserialize_fhe_uint16(
    slice: ByteSliceView,
) -> Result<FheUint16, Box<bincode::ErrorKind>> {
    let x: CompactFheUint16 =bincode::deserialize::<CompactFheUint16>(slice.read().unwrap())?;
    Ok(x.expand())
}

// Function for deserializing FheUint32
pub(crate) fn deserialize_fhe_uint32(
    slice: ByteSliceView,
) -> Result<FheUint32, Box<bincode::ErrorKind>> {
    let x: CompactFheUint32 = bincode::deserialize::<CompactFheUint32>(slice.read().unwrap())?;
    Ok(x.expand())
}
