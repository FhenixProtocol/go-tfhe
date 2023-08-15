use crate::memory::ByteSliceView;
use tfhe::{FheUint16, FheUint32, FheUint8, CompactFheUint8List, CompactFheUint16List, CompactFheUint32List};

// todo: fix all of this

pub(crate) unsafe fn deserialize_fhe_uint8(
    slice: ByteSliceView,
) -> Result<FheUint8, Box<bincode::ErrorKind>> {
    let x: CompactFheUint8List = bincode::deserialize::<CompactFheUint8List>(slice.read().unwrap())?;
    let y = x.expand();
    // this sucks, obviously
    Ok(y[0].clone())
}

// Function for deserializing FheUint16
pub(crate) fn deserialize_fhe_uint16(
    slice: ByteSliceView,
) -> Result<FheUint16, Box<bincode::ErrorKind>> {
    let x: CompactFheUint16List =bincode::deserialize::<CompactFheUint16List>(slice.read().unwrap())?;
    let y = x.expand();
    // this sucks, obviously
    Ok(y[0].clone())
}

// Function for deserializing FheUint32
pub(crate) fn deserialize_fhe_uint32(
    slice: ByteSliceView,
) -> Result<FheUint32, Box<bincode::ErrorKind>> {
    let x: CompactFheUint32List = bincode::deserialize::<CompactFheUint32List>(slice.read().unwrap())?;
    let y = x.expand();
    // this sucks, obviously
    Ok(y[0].clone())
}
