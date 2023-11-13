use once_cell::sync::OnceCell;

use crate::error::RustError;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS as KEYGEN_PARAMS;
use tfhe::{ClientKey, CompactPublicKey, ConfigBuilder, ServerKey};
// use std::sync::{Arc, Mutex};
use std::collections::HashSet;
use std::sync::Mutex;
use std::{thread, thread::ThreadId};
pub struct InitGuard {
    key: Option<ServerKey>,
    init_threads: HashSet<ThreadId>,
}

impl Default for InitGuard {
    fn default() -> Self {
        Self::new()
    }
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
            None => panic!("Server Key not set"),
            Some(key) => match self.init_threads.insert(thread::current().id()) {
                false => {} // thread already set key in zama lib
                true => tfhe::set_server_key(key.clone()),
            },
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

    pub fn set_public_key(key: CompactPublicKey) -> Result<(), RustError> {
        if PUBLIC_KEY.get().is_some() {
            println!("already loaded public key");
            return Ok(());
            // return Err(RustError::generic_error(
            //     "Cannot set public key multiple times",
            // ));
        }
        PUBLIC_KEY
            .set(key)
            .map_err(|_key| RustError::generic_error("failed to set public key"))
    }

    pub fn set_client_key(key: ClientKey) -> Result<(), RustError> {
        if CLIENT_KEY.get().is_some() {
            println!("already loaded client key");
            return Ok(());
            // return Err(RustError::generic_error(
            //     "Cannot set client key multiple times",
            // ));
        }
        CLIENT_KEY
            .set(key)
            .map_err(|_key| RustError::generic_error("failed to set client key"))
    }

    pub fn is_server_key_set() -> bool {
        if let Some(mutex) = SERVER_KEY.get() {
            mutex.lock().unwrap().is_key_set()
        } else {
            false
        }
    }

    pub fn refresh_server_key_for_thread() {
        let mutex = SERVER_KEY.get_or_init(|| Mutex::new(InitGuard::new()));
        let mut guard = mutex.lock().unwrap();
        guard.ensure_init();
    }

    pub fn set_server_key(key: ServerKey) -> Result<(), bool> {
        let mutex = SERVER_KEY.get_or_init(|| Mutex::new(InitGuard::new()));
        let mut guard = mutex.lock().unwrap();
        if !guard.is_key_set() {
            guard.set_key(key);
        }
        guard.ensure_init();
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

pub static SERVER_KEY: OnceCell<Mutex<InitGuard>> = OnceCell::new();
pub static PUBLIC_KEY: OnceCell<CompactPublicKey> = OnceCell::new();
pub static CLIENT_KEY: OnceCell<ClientKey> = OnceCell::new();

pub fn deserialize_client_key_safe(key: &[u8]) -> Result<(), RustError> {
    let maybe_key_deserialized = bincode::deserialize::<ClientKey>(key).map_err(|err| {
        log::debug!("failed to deserialize client key: {:?}", err);
        RustError::generic_error("Failed to deserialize client key")
    })?;

    GlobalKeys::set_client_key(maybe_key_deserialized)?;

    Ok(())
}

pub fn deserialize_public_key_safe(key: &[u8]) -> Result<(), RustError> {
    let maybe_key_deserialized = bincode::deserialize::<CompactPublicKey>(key).map_err(|err| {
        log::debug!("failed to deserialize public key: {:?}", err);
        RustError::generic_error("Failed to deserialize public key")
    })?;

    GlobalKeys::set_public_key(maybe_key_deserialized)?;

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

pub fn generate_keys_safe() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let config = ConfigBuilder::all_disabled()
        .enable_custom_integers(KEYGEN_PARAMS, None)
        .build();

    // Client-side
    let (cks, sks) = tfhe::generate_keys(config);
    let pks: CompactPublicKey = CompactPublicKey::new(&cks);

    let serialized_secret_key = bincode::serialize(&cks).unwrap();
    let serialized_server_key = bincode::serialize(&sks).unwrap();
    let serialized_public_key = bincode::serialize(&pks).unwrap();

    (
        serialized_secret_key,
        serialized_server_key,
        serialized_public_key,
    )
}
