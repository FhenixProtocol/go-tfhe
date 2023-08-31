// Using wasm_bindgen for WASM compilation
// #[wasm_bindgen]
use tfhe::{
    generate_keys, shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS, CompactPublicKey,
    ConfigBuilder,
};

pub enum FheUintType {
    Uint8 = 0,
    Uint16 = 1,
    Uint32 = 2,
}

#[derive(Debug)]
pub enum Op {
    Add = 0,
    Sub = 1,
    Mul = 2,
    Lt = 3,
    Lte = 4,
}

pub fn generate_full_keys(path_to_cks: String, path_to_sks: String, path_to_pks: String) -> u32 {
    //Result<bool, JsValue> {
    let config = ConfigBuilder::all_disabled()
        .enable_custom_integers(PARAM_MESSAGE_2_CARRY_2_KS_PBS, None)
        .build();
    tfhe::core_crypto::seeders::custom_seeder::set_custom_seeder("test2".to_string());

    let (cks, sks) = generate_keys(config);
    let pks = CompactPublicKey::try_new(&cks);

    // Your implementation here
    // Return Ok(true) or Err(JsValue::from_str("Error message"))
    0
}

pub fn version() -> u32 {
    return 2;
}

pub unsafe extern "C" fn math_operation(
    lhs: *mut u8,
    rhs: *mut u8,
    operation: u8,
    uint_type: u8,
) -> *mut c_void {
    // Your implementation here
    if let Some(public_key_slice) = key.read() {
        let r = deserialize_public_key_safe(public_key_slice);

        handle_c_error_default(r, err_msg)
    } else {
        log::debug!("Failed to read input public key");
        set_error(
            RustError::generic_error("failed to read public key"),
            err_msg,
        );
    }
}
//
// #[wasm_bindgen]
pub fn load_server_key_wasm(key: &[u8]) -> Result<(), JsValue> {
    // Your implementation here
    Ok(())
}
//
// #[wasm_bindgen]
pub fn load_client_key_wasm(key: &[u8]) -> Result<(), JsValue> {
    // Your implementation here
    Ok(())
}
//
// #[wasm_bindgen]
pub fn load_public_key_wasm(key: &[u8]) -> Result<(), JsValue> {
    // Your implementation here
    Ok(())
}
//
// #[wasm_bindgen]
pub fn get_public_key_wasm() -> Result<Vec<u8>, JsValue> {
    // Your implementation here
    Ok(vec![])
}
//
// #[wasm_bindgen]
pub fn expand_compressed_wasm(
    ciphertext: &[u8],
    int_type: FheUintType,
) -> Result<Vec<u8>, JsValue> {
    // Your implementation here
    Ok(vec![])
}
//
// #[wasm_bindgen]
pub fn encrypt_wasm(msg: u64, int_type: FheUintType) -> Result<Vec<u8>, JsValue> {
    // Your implementation here
    Ok(vec![])
}
//
// #[wasm_bindgen]
pub fn trivial_encrypt_wasm(msg: u64, int_type: FheUintType) -> Result<Vec<u8>, JsValue> {
    // Your implementation here
    Ok(vec![])
}

pub fn decrypt_wasm(ciphertext: &[u8], int_type: FheUintType) -> Result<u64, JsValue> {
    // Your implementation here
    Ok(0)
}
