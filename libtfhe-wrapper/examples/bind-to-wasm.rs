use std::ffi::c_char;
use tfhe_wrapper::api::version;

// #[no_mangle]
// pub unsafe extern "C" fn generate_fhe_keys() -> u32 {
//     generate_full_keys(
//         "./keys/cks".to_string(),
//         "./keys/sks".to_string(),
//         "./keys/pks".to_string()
//     );
//
//     0
// }

#[no_mangle]
pub unsafe extern "C" fn get_version() -> u32 {
    version()
}

fn main() {
    // unsafe { generate_fhe_keys() }
}