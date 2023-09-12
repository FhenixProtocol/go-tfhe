extern "C" {
    fn consoleLog(message_ptr: *const u8, message_len: usize);
}

pub fn console_log(message: &str) {
    let message_bytes = message.as_bytes();
    unsafe {
        consoleLog(message_bytes.as_ptr(), message_bytes.len());
    }
}
