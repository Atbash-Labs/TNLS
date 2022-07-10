#![allow(unused_imports)]

use cosmwasm_std::{CanonicalAddr, ReadonlyStorage, StdError, StdResult, Storage};
use cosmwasm_storage::{singleton, singleton_read, ReadonlySingleton, Singleton};
use secret_toolkit::{
    incubator::{CashMap, ReadOnlyCashMap},
    serialization::{Bincode2, Json, Serde},
    utils::types::Contract,
};

use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Storage key for this contract's configuration.
pub static CONFIG_KEY: &[u8] = b"config";
/// Storage key for this contract's address.
pub static MY_ADDRESS_KEY: &[u8] = b"myaddr";
/// Storage key for the contract instantiator.
pub static CREATOR_KEY: &[u8] = b"creator";
/// Storage key for prng seed.
pub static PRNG_SEED_KEY: &[u8] = b"prngseed";
/// Storage key for task IDs.
pub static TASK_KEY: &[u8] = b"tasks";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct State {
    /// Admin adress.
    pub admin: CanonicalAddr,
    /// Count of tx.
    pub tx_cnt: u64,
    /// Contract status.
    pub status: u8,
    /// Private gateway encryption key pair.
    pub encryption_key: KeyPair,
    /// Private gateway signing key pair.
    pub signing_key: KeyPair,
}

/// A key pair of `Vec<u8>`
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct KeyPair {
    /// Public key part of the key pair.
    pub pk: Vec<u8>,
    /// Secret key part of the key pair.
    pub sk: Vec<u8>,
}

/// Access storage for this contract's configuration.
pub fn config<S: Storage>(storage: &mut S) -> Singleton<S, State> {
    singleton(storage, CONFIG_KEY)
}
/// Access read-only storage for this contract's configuration.
pub fn config_read<S: Storage>(storage: &S) -> ReadonlySingleton<S, State> {
    singleton_read(storage, CONFIG_KEY)
}

/// Access PRNG seed storage.
// Is this really necessary?
pub fn prng<S: Storage>(storage: &mut S) -> Singleton<S, Vec<u8>> {
    singleton(storage, PRNG_SEED_KEY)
}
/// Access read-only PRNG seed storage.
pub fn prng_read<S: Storage>(storage: &S) -> ReadonlySingleton<S, Vec<u8>> {
    singleton_read(storage, PRNG_SEED_KEY)
}

/// Access storage for this contract's address.
pub fn my_address<S: Storage>(storage: &mut S) -> Singleton<S, CanonicalAddr> {
    singleton(storage, MY_ADDRESS_KEY)
}
/// Access read-only storage for this contract's address.
pub fn my_address_read<S: Storage>(storage: &mut S) -> Singleton<S, CanonicalAddr> {
    singleton(storage, MY_ADDRESS_KEY)
}

/// Access storage for the contract creator's address.
pub fn creator_address<S: Storage>(storage: &mut S) -> Singleton<S, CanonicalAddr> {
    singleton(storage, MY_ADDRESS_KEY)
}
/// Access read-only storage for the contract creator's address.
pub fn creator_address_read<S: Storage>(storage: &mut S) -> Singleton<S, CanonicalAddr> {
    singleton(storage, MY_ADDRESS_KEY)
}

// convenience functions
pub fn load_signing_key<S: Storage>(storage: &S) -> StdResult<Vec<u8>> {
    let sk = config_read(storage).load()?.signing_key.sk;
    Ok(sk)
}

// Cashmap is convenient, but may not be the best solution if we need to maintain an ordered list
pub fn map2caller<S: Storage>(storage: &mut S) -> CashMap<String, S> {
    let mut hashmap: CashMap<String, S> = CashMap::init(TASK_KEY, storage);
    hashmap
}
