use cosmwasm_std::{Binary, HumanAddr};
use secret_toolkit::storage::{Item, Keymap};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub static CONFIG: Item<State> = Item::new(b"config");

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct State {
    pub gateway_address: HumanAddr,
    pub gateway_hash: String,
    pub gateway_key: Binary,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Input {
    // user ethereum address
    pub address: String,
    // user name
    pub name: Option<String>,
    pub detail_1: u32,
    pub detail_2: u32,
    pub detail_3: u32,
    pub detail_4: u32,
    pub detail_5: u32,
}
