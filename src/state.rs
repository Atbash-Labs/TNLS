use ed25519_compact::{PublicKey, SecretKey};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{CanonicalAddr, Storage};
use cosmwasm_storage::{singleton, singleton_read, ReadonlySingleton, Singleton};

pub static CONFIG_KEY: &[u8] = b"config";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct State {
    pub encryption_key: KeyPair,
    pub signing_key: KeyPair,
    pub owner: CanonicalAddr,
}

/// A key pair, stored with base64 encoded Strings because
/// [u8;64] is not serializeable (implementations from Serde go up to 32 bytes)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Hash)]
pub struct KeyPair {
    /// Public key part of the key pair
    pub pk: String,
    /// Secret key part of the key pair
    pub sk: String,
}

pub fn config_write<S: Storage>(storage: &mut S) -> Singleton<S, State> {
    singleton(storage, CONFIG_KEY)
}

pub fn config_read<S: Storage>(storage: &S) -> ReadonlySingleton<S, State> {
    singleton_read(storage, CONFIG_KEY)
}
