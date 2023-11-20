use tfhe::{CompactFheUint16, CompactFheUint32, CompactFheUint8, FheUint16, FheUint32, FheUint8};

macro_rules! deserialize_fhe_uint {
    ($name:ident, $type:ty, $compact_type:ty) => {
        /// Deserializes a byte slice into the respective `FheUint` object.
        ///
        /// If the `compact` flag is set to true, the function first deserializes
        /// into a compact form of the `FheUint` and then expands it.
        /// Otherwise, it directly deserializes into the `FheUint` object.
        ///
        /// # Arguments
        ///
        /// * `slice` - The byte slice to be deserialized.
        /// * `compact` - A boolean flag indicating if the slice is in compact form.
        ///
        /// # Returns
        ///
        /// A `Result` with the deserialized `FheUint`, or a `Box<bincode::ErrorKind>` on error.
        pub(crate) fn $name(slice: &[u8], compact: bool) -> Result<$type, Box<bincode::ErrorKind>> {
            if compact {
                let x: $compact_type = bincode::deserialize(slice)?;
                Ok(x.expand())
            } else {
                let x: $type = bincode::deserialize(slice).map_err(|err| {
                    #[cfg(target_arch = "wasm32")]
                    crate::imports::console_log(
                        format!("failed deserializing: {:?}", err).as_str(),
                    );
                    err
                })?;
                Ok(x)
            }
        }
    };
}

// Use the macro to generate the functions
deserialize_fhe_uint!(deserialize_fhe_uint8, FheUint8, CompactFheUint8);
deserialize_fhe_uint!(deserialize_fhe_uint16, FheUint16, CompactFheUint16);
deserialize_fhe_uint!(deserialize_fhe_uint32, FheUint32, CompactFheUint32);

// leaving this here because debugging and modifying macros is a bitch
// so you can just uncomment this code and play with it

// pub(crate) fn deserialize_fhe_uint32(
//     slice: &[u8],
//     compact: bool,
// ) -> Result<FheUint32, Box<bincode::ErrorKind>> {
//     if compact {
//         let x: CompactFheUint32 = bincode::deserialize::<CompactFheUint32>(slice)?;
//         Ok(x.expand())
//     } else {
//         let x: FheUint32 = bincode::deserialize::<FheUint32>(slice)?;
//         Ok(x)
//     }
// }
