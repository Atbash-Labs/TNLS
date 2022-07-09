use cosmwasm_std::{Binary, Empty, HumanAddr};
use secret_toolkit::utils::types::Contract;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Inputs {
    pub task_id: u128,               // exact size TBD
    pub input_values: Empty,         // TBD
    pub handle: Empty,               // TBD
    pub contract_address: HumanAddr, // destination contract address
    pub contract_hash: String,       // destination contract code hash
    pub signature: Binary,           // signature of hash of unencrypted input value
    pub creating_address: Sender, // unsure if this is a person or a contract. is it the calling contract?
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct PublicPrivate {
    pub message_creator: Sender,
    pub source_network: String,
    pub routing_info: RoutingInfo,
    pub routing_info_signature: Binary,
    pub payload: Payload,
    pub payload_signature: Binary,
    pub signature_of_entire_packet: Binary,
    pub task_id: u128,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct PrivatePublic {
    pub source_network: String,
    pub routing_info: RoutingInfo,
    pub routing_info_signature: Binary,
    pub payload: Payload,
    pub payload_signature: Binary,
    pub signature_of_entire_packet: Binary,
    pub task_id: u128,
    pub task_id_signature: Binary,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Sender {
    pub verifying_key: Binary,
    pub address: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct RoutingInfo {
    pub sender: HumanAddr,
    pub destination: Contract,
    // consider using more primitive types because incoming messages may not be written in Rust
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub enum Data {
    Scenario1 { integer: u8 },
    Scenario2 { string: String },
    ScenarioN { etc: usize },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
/// Encryption of (Data, Routing info, User address)
pub struct Payload {
    pub data: Data,
    pub routing_info: RoutingInfo,
    pub user_address: String,
}
