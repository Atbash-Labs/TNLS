use cosmwasm_std::{Binary, HumanAddr};
use schemars::JsonSchema;
use secret_toolkit::{crypto::secp256k1, utils::types::Contract};
use serde::{Deserialize, Serialize};

pub type Base64 = Binary;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct PublicPrivate {
    pub message_creator: Sender,
    pub source_network: String,
    pub routing_info: RoutingInfo,
    pub routing_info_signature: Base64,
    pub payload: Payload,
    pub payload_signature: Base64,
    pub signature_of_entire_packet: Base64,
    pub task_id: u128,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct PrivatePublic {
    pub source_network: String,
    pub routing_info: RoutingInfo,
    pub routing_info_signature: Base64,
    pub payload: Payload,
    pub payload_signature: Base64,
    pub signature_of_entire_packet: Base64,
    pub task_id: u128,
    pub task_id_signature: Base64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Sender {
    pub verifying_key: Base64,
    pub address: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct RoutingInfo {
    pub sender: HumanAddr,
    pub destination: Contract,
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
