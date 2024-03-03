use crate::logger;

#[no_mangle]
pub unsafe extern "C" fn init_logger() {
    match logger::init_logger() {
        Ok(_) => (),
        Err(e) => eprintln!("Failed to initialize logger: {:?}", e),
    }
}
