use crate::memory::ByteSliceView;
use tfhe::{FheUint16, FheUint32, FheUint8, CompactFheUint8, CompactFheUint16, CompactFheUint32};

// todo: fix all of this

pub(crate) fn deserialize_fhe_uint8(
    slice: &[u8],
) -> Result<FheUint8, Box<bincode::ErrorKind>> {
    let x: CompactFheUint8 = bincode::deserialize::<CompactFheUint8>(slice)?;
    Ok(x.expand())
}

// Function for deserializing FheUint16
pub(crate) fn deserialize_fhe_uint16(
    slice: &[u8],
) -> Result<FheUint16, Box<bincode::ErrorKind>> {
    let x: CompactFheUint16 =bincode::deserialize::<CompactFheUint16>(slice)?;
    Ok(x.expand())
}

// Function for deserializing FheUint32
pub(crate) fn deserialize_fhe_uint32(
    slice: &[u8],
) -> Result<FheUint32, Box<bincode::ErrorKind>> {
    let x: CompactFheUint32 = bincode::deserialize::<CompactFheUint32>(slice)?;
    Ok(x.expand())
}
