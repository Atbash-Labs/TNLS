use cosmwasm_std::{Binary, HumanAddr};
use secret_toolkit::utils::HandleCallback;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InitMsg {
    pub gateway_address: HumanAddr,
    pub gateway_hash: String,
    pub gateway_key: Binary,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
    Input { input: PrivContractHandleMsg },
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    Success,
    Failure,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct InputResponse {
    pub status: ResponseStatus,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    Query {},
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct PrivContractHandleMsg {
    /// JSON formatted string of decrypted user inputs.
    pub input_values: String,
    /// Handle function to be called in the destination contract.
    pub handle: String,
    // TODO add this into the gateway code
    pub task_id: u64,
    /// sha256(input_values)
    pub input_hash: Binary,
    /// Signature of sha256(input_values), signed by the private gateway.
    pub signature: Binary,
}

/// Message received from destination private contract
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct PostExecutionMsg {
    /// JSON string formatted outputs
    pub result: String,
    pub task_id: u64,
    /// SHA256 hash of decrypted inputs for verification
    pub input_hash: Binary,
}

impl HandleCallback for PostExecutionMsg {
    const BLOCK_SIZE: usize = 256;
}

// We define a custom struct for each query response
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct TestResponse {
    pub message: String,
}
