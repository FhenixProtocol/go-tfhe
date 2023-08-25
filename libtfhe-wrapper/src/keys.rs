use lazy_static::lazy_static;
use std::sync::{Arc, Mutex};

use tfhe::{
    generate_keys, shortint::parameters::PARAM_SMALL_MESSAGE_2_CARRY_2_COMPACT_PK, ClientKey,
    CompactPublicKey, ConfigBuilder,
};

lazy_static! {
    pub static ref SERVER_KEY: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    pub static ref PUBLIC_KEY: Arc<Mutex<Option<CompactPublicKey>>> = Arc::new(Mutex::new(None));
    pub static ref CLIENT_KEY: Arc<Mutex<Option<ClientKey>>> = Arc::new(Mutex::new(None));
}

#[no_mangle]
pub unsafe extern "C" fn generate_full_keys(
    path_to_cks: *const std::ffi::c_char,
    path_to_sks: *const std::ffi::c_char,
    path_to_pks: *const std::ffi::c_char,
) -> bool {
    let config = ConfigBuilder::all_disabled()
        .enable_custom_integers(PARAM_SMALL_MESSAGE_2_CARRY_2_COMPACT_PK, None)
        .build();
    let (c_str_cks, c_str_sks, c_str_pks) = unsafe {
        (
            std::ffi::CStr::from_ptr(path_to_cks),
            std::ffi::CStr::from_ptr(path_to_sks),
            std::ffi::CStr::from_ptr(path_to_pks),
        )
    };

    let cks_path_str = match c_str_cks.to_str() {
        Err(_) => return false,
        Ok(s) => s,
    };

    let sks_path_str = match c_str_sks.to_str() {
        Err(_) => return false,
        Ok(s) => s,
    };

    let pks_path_str = match c_str_pks.to_str() {
        Err(_) => return false,
        Ok(s) => s,
    };

    // Client-side
    let (cks, sks) = generate_keys(config);
    let pks: CompactPublicKey = CompactPublicKey::new(&cks);

    let serialized_secret_key = bincode::serialize(&cks).unwrap();
    let serialized_server_key = bincode::serialize(&sks).unwrap();
    let serialized_public_key = bincode::serialize(&pks).unwrap();

    if let Err(e) = std::fs::write(cks_path_str, serialized_secret_key) {
        println!(
            "Failed to write cks to path: {:?}. Error: {:?}",
            cks_path_str, e
        );
        return false;
    };

    if let Err(e) = std::fs::write(sks_path_str, serialized_server_key) {
        println!(
            "Failed to write sks to path: {:?}. Error: {:?}",
            sks_path_str, e
        );
        return false;
    };

    if let Err(e) = std::fs::write(pks_path_str, serialized_public_key) {
        println!(
            "Failed to write pks to path: {:?}. Error: {:?}",
            pks_path_str, e
        );
        return false;
    };

    true
}
