use tfhe::{
    CompactFheUint128, CompactFheUint16, CompactFheUint256, CompactFheUint32, CompactFheUint64,
    CompactFheUint8, FheUint128, FheUint16, FheUint256, FheUint32, FheUint64, FheUint8,
};

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
deserialize_fhe_uint!(deserialize_fhe_uint64, FheUint64, CompactFheUint64);
deserialize_fhe_uint!(deserialize_fhe_uint128, FheUint128, CompactFheUint128);
deserialize_fhe_uint!(deserialize_fhe_uint256, FheUint256, CompactFheUint256);
