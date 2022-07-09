use std::any::type_name;

use cosmwasm_std::{CanonicalAddr, ReadonlyStorage, StdError, StdResult, Storage};
use cosmwasm_storage::{singleton, singleton_read, ReadonlySingleton, Singleton};
use secret_toolkit::{
    incubator::{CashMap, ReadOnlyCashMap},
    serialization::{Bincode2, Json, Serde},
    utils::types::Contract,
};

use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// storage key for config
pub static CONFIG_KEY: &[u8] = b"config";
/// storage key for this contract's address
pub static MY_ADDRESS_KEY: &[u8] = b"myaddr";
/// storage key for the contract instantiator
pub static CREATOR_KEY: &[u8] = b"creator";
/// storage key for prng seed
pub static PRNG_SEED_KEY: &[u8] = b"prngseed";
/// storage key for task IDs
pub static TASK_KEY: &[u8] = b"tasks";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct State {
    /// admin adress
    pub admin: CanonicalAddr,
    /// count of tx
    pub tx_cnt: u64,
    /// contract status
    pub status: u8,
    /// private gateway encryption key pair
    pub encryption_key: KeyPair,
    /// private gateway signing key pair
    pub signing_key: KeyPair,
}

/// A key pair, stored with base64 encoded Strings because
/// [u8;64] is not serializeable (implementations from Serde go up to 32 bytes)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct KeyPair {
    /// Public key part of the key pair
    pub pk: Vec<u8>,
    /// Secret key part of the key pair
    pub sk: Vec<u8>,
}

pub fn config_write<S: Storage>(storage: &mut S) -> Singleton<S, State> {
    singleton(storage, CONFIG_KEY)
}

pub fn config_read<S: Storage>(storage: &S) -> ReadonlySingleton<S, State> {
    singleton_read(storage, CONFIG_KEY)
}

pub fn load_signing_key<S: Storage>(storage: &S) -> StdResult<Vec<u8>> {
    let sk = config_read(storage).load()?.signing_key.sk;
    Ok(sk)
}

// Cashmap is convenient, but may not be the best solution if we need to maintain an ordered list
pub fn map2caller<S: Storage>(id: u128, caller: String, storage: &mut S) -> StdResult<()> {
    let mut hashmap: CashMap<String, _> = CashMap::init(TASK_KEY, storage);
    hashmap.insert(&id.to_le_bytes(), caller)?;
    Ok(())
}

/// Returns StdResult<()> resulting from saving an item to storage
///
/// # Arguments
///
/// * `storage` - a mutable reference to the storage this item should go to
/// * `key` - a byte slice representing the key to access the stored item
/// * `value` - a reference to the item to store
pub fn save<T: Serialize, S: Storage>(storage: &mut S, key: &[u8], value: &T) -> StdResult<()> {
    storage.set(key, &Bincode2::serialize(value)?);
    Ok(())
}

/// Removes an item from storage
///
/// # Arguments
///
/// * `storage` - a mutable reference to the storage this item is in
/// * `key` - a byte slice representing the key that accesses the stored item
pub fn remove<S: Storage>(storage: &mut S, key: &[u8]) {
    storage.remove(key);
}

/// Returns StdResult<T> from retrieving the item with the specified key.  Returns a
/// StdError::NotFound if there is no item with that key
///
/// # Arguments
///
/// * `storage` - a reference to the storage this item is in
/// * `key` - a byte slice representing the key that accesses the stored item
pub fn load<T: DeserializeOwned, S: ReadonlyStorage>(storage: &S, key: &[u8]) -> StdResult<T> {
    Bincode2::deserialize(
        &storage
            .get(key)
            .ok_or_else(|| StdError::not_found(type_name::<T>()))?,
    )
}

/// Returns StdResult<Option<T>> from retrieving the item with the specified key.
/// Returns Ok(None) if there is no item with that key
///
/// # Arguments
///
/// * `storage` - a reference to the storage this item is in
/// * `key` - a byte slice representing the key that accesses the stored item
pub fn may_load<T: DeserializeOwned, S: ReadonlyStorage>(
    storage: &S,
    key: &[u8],
) -> StdResult<Option<T>> {
    match storage.get(key) {
        Some(value) => Bincode2::deserialize(&value).map(Some),
        None => Ok(None),
    }
}
