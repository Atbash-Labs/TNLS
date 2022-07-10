use cosmwasm_std::{Binary, Empty, HumanAddr};
use secret_toolkit::utils::types::Contract;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Inputs {
    pub task_id: u128,               // exact size TBD
    pub input_values: Binary,         // TBD
    pub handle: Binary,               // TBD
    pub contract: Contract,          // destination contract
    pub signature: Binary,           // signature of hash of unencrypted input value
    pub creator: Sender,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Sender {
    pub address: String,
    pub verifying_key: Binary,
}
