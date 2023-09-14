extern "C" {
    // fn consoleLog(message_ptr: *const u8, message_len: usize);
    pub fn wavm_halt_and_set_finished() -> !;
}

pub fn console_log(_message: &str) {
    // let message_bytes = message.as_bytes();
    // unsafe {
    // consoleLog(message_bytes.as_ptr(), message_bytes.len());
    // }
}
