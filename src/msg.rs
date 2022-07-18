use cosmwasm_std::{Binary, HumanAddr};
use secret_toolkit::utils::HandleCallback;

use crate::types::{PostExecutionMsg, PreExecutionMsg};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InitMsg {
    /// entropy used for prng seed
    pub entropy: String,
    /// optional admin address, env.message.sender if missing
    pub admin: Option<HumanAddr>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
    Input { inputs: PreExecutionMsg },
    Output { outputs: PostExecutionMsg },
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ContractStatus {
    Normal,
    StopInputs,
    StopAll,
}

impl ContractStatus {
    /// Returns u8 representation of the ContractStatus
    pub fn to_u8(&self) -> u8 {
        match self {
            ContractStatus::Normal => 0,
            ContractStatus::StopInputs => 1,
            ContractStatus::StopAll => 2,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct InputResponse {
    pub task_id: u64,
    pub creating_address: HumanAddr,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct OutputResponse {
    pub task_id: u64,
    pub calling_contract: HumanAddr,
    pub output: Binary,
    pub signature: Binary,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    // Is there any need for queries?
    GetPublicKey {},
}

// We define a custom struct for each query response
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct PublicKeyResponse {
    pub key: Binary,
}

// Here we need to know the message structures for the specific HandleMsgs we want to call
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub enum CounterHandleMsg {
    Reset { count: i32 },
}

impl HandleCallback for CounterHandleMsg {
    const BLOCK_SIZE: usize = 256;
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct PrivContractHandleMsg {
    pub input_values: String,
    pub handle: String,
    pub signature: Binary,
}

impl HandleCallback for PrivContractHandleMsg {
    const BLOCK_SIZE: usize = 256;
}
