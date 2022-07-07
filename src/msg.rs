use crate::types::*;
use schemars::JsonSchema;
use secret_toolkit::utils::HandleCallback;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InitMsg {
    // Should we include a supplied entropy seed?
    pub entropy: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
    Input { interchain_message: PublicPrivate },
    Output { interchain_message: PrivatePublic },
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    Success,
    Failure,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleAnswer {
    Input { status: ResponseStatus },
    Output { status: ResponseStatus },
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
pub enum QueryAnswer {
    GetPublicKey { key: String },
}

// Here we need to know the message structures for the specific HandleMsgs we want to call
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub enum CounterHandleMsg {
    Reset { count: i32 },
}

impl HandleCallback for CounterHandleMsg {
    const BLOCK_SIZE: usize = 256;
}
