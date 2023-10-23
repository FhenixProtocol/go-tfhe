use once_cell::sync::OnceCell;

use crate::error::RustError;
use tfhe::{ClientKey, CompactPublicKey, ServerKey};
// use std::sync::{Arc, Mutex};
use std::collections::HashSet;
use std::{thread, thread::ThreadId};
use std::sync::Mutex;
pub struct InitGuard {
    key: Option<ServerKey>,
    init_threads: HashSet<ThreadId>,
}

impl InitGuard {
    pub fn new() -> Self {
        Self {
            key: None,
            init_threads: HashSet::new(),
        }
    }

    pub fn is_key_set(&self) -> bool {
        self.key.is_some()
    }

    pub fn set_key(&mut self, key: ServerKey) {
        self.key = Some(key);
    }

    pub fn ensure_init(&mut self) {
        match &self.key {
            None => panic!("Public Key not set"),
            Some(key) => match self.init_threads.insert(thread::current().id()) {
                false => {}, // thread already set key in zama lib
                true => tfhe::set_server_key(key.clone()),
            }
        }
    }
}

pub struct GlobalKeys {}

impl GlobalKeys {
    pub fn get_public_key() -> Option<&'static CompactPublicKey> {
        PUBLIC_KEY.get()
    }
    pub fn get_client_key() -> Option<&'static ClientKey> {
        CLIENT_KEY.get()
    }

    // pub fn is_server_key_set() -> bool {
    //     SERVER_KEY.get().unwrap_or(&InitGuard::new()).is_key_set()
    // }

    pub fn set_public_key(key: CompactPublicKey) -> Result<(), CompactPublicKey> {
        PUBLIC_KEY.set(key)
    }

    pub fn set_client_key(key: ClientKey) -> Result<(), ClientKey> {
        CLIENT_KEY.set(key)
    }

    pub fn is_server_key_set() -> bool {
        if let Some(mutex) = SERVER_KEY.get() {
            mutex.lock().unwrap().is_key_set()
        } else {
            false
        }
    }

    pub fn set_server_key(key: ServerKey) -> Result<(), bool> {
        let mutex = SERVER_KEY.get_or_init(|| Mutex::new(InitGuard::new()));
        let mut guard = mutex.lock().unwrap();
        if guard.is_key_set() {
            return Err(false);
        }
        guard.set_key(key);
        Ok(())
    }

    // pub fn set_server_key(key: ServerKey) -> Result<(), bool> {
    //     if SERVER_KEY.get().is_none() {
    //         return Err(false);
    //     }
    //     SERVER_KEY.get_mut().unwrap().set_key(key);
    //     Ok(())
    // }
}

pub static SERVER_KEY: OnceCell<Mutex<InitGuard>>  = OnceCell::new();
pub static PUBLIC_KEY: OnceCell<CompactPublicKey> = OnceCell::new();
pub static CLIENT_KEY: OnceCell<ClientKey> = OnceCell::new();

pub fn deserialize_client_key_safe(key: &[u8]) -> Result<(), RustError> {
    let maybe_key_deserialized = bincode::deserialize::<ClientKey>(key).map_err(|err| {
        log::debug!("failed to deserialize client key: {:?}", err);
        RustError::generic_error("Failed to deserialize client key")
    })?;

    GlobalKeys::set_client_key(maybe_key_deserialized).map_err(|err| {
        log::debug!("Failed to set client key: {:?}", err);
        RustError::generic_error("Failed to set client key")
    })?;

    Ok(())
}

pub fn deserialize_public_key_safe(key: &[u8]) -> Result<(), RustError> {
    let maybe_key_deserialized = bincode::deserialize::<CompactPublicKey>(key).map_err(|err| {
        log::debug!("failed to deserialize public key: {:?}", err);
        RustError::generic_error("Failed to deserialize public key")
    })?;

    GlobalKeys::set_public_key(maybe_key_deserialized).map_err(|err| {
        log::debug!("Failed to set public key: {:?}", err);
        RustError::generic_error("Failed to set public key")
    })?;

    Ok(())
}

pub fn load_server_key_safe(key: &[u8]) -> Result<(), RustError> {
    let server_key = bincode::deserialize::<ServerKey>(key).map_err(|err| {
        log::debug!("Failed to set server key: {:?}", err);
        RustError::generic_error("failed to set server key: bad input")
    })?;

    tfhe::set_server_key(server_key.clone());

    GlobalKeys::set_server_key(server_key).map_err(|_| {
        log::debug!("Failed to set server key");
        RustError::generic_error("failed to set server key: set failed")
    })
}
