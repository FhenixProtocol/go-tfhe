// #[(cfg(all(target_arch = "wasm32", feautre = "wasm32")))]
extern "C" {
    pub fn wavm_halt_and_set_finished() -> !;
    pub fn wavm_console_log(message_ptr: *const u8, message_len: usize);

}

//#[(cfg(all(target_arch = "wasm32", feautre = "wasm32")))]
pub fn console_log(message: &str) {
    let message_bytes = message.as_bytes();
    unsafe {
        wavm_console_log(message_bytes.as_ptr(), message_bytes.len());
    }
}
