use once_cell::sync::OnceCell;

use crate::error::RustError;
use tfhe::{ClientKey, CompactPublicKey, ServerKey};

pub struct GlobalKeys {}

impl GlobalKeys {
    pub fn get_public_key() -> Option<&'static CompactPublicKey> {
        PUBLIC_KEY.get()
    }
    pub fn get_client_key() -> Option<&'static ClientKey> {
        CLIENT_KEY.get()
    }

    pub fn is_server_key_set() -> &'static bool {
        SERVER_KEY.get().unwrap_or(&false)
    }

    pub fn set_public_key(key: CompactPublicKey) -> Result<(), CompactPublicKey> {
        PUBLIC_KEY.set(key)
    }

    pub fn set_client_key(key: ClientKey) -> Result<(), ClientKey> {
        CLIENT_KEY.set(key)
    }

    pub fn set_server_key(key: bool) -> Result<(), bool> {
        SERVER_KEY.set(key)
    }
}

pub static SERVER_KEY: OnceCell<bool> = OnceCell::with_value(false);
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

    tfhe::set_server_key(server_key);

    GlobalKeys::set_server_key(true).map_err(|_| {
        log::debug!("Failed to set server key");
        RustError::generic_error("failed to set server key: set failed")
    })
}
