use cosmwasm_std::{
    from_binary, Api, Binary, Extern, HumanAddr, Querier, StdError, StdResult, Storage,
};
use secret_toolkit::utils::{types::Contract, HandleCallback};

use crate::types::*;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use secp256k1::{ecdh::SharedSecret, PublicKey, SecretKey};

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
pub enum ResponseStatus {
    Success,
    Failure,
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
    pub status: ResponseStatus
}

// #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
// #[serde(rename_all = "snake_case")]
// pub struct OutputResponse {
//     pub status: ResponseStatus
// }

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// Returns the gateway's public encryption key.
    GetPublicKey {},
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct PublicKeyResponse {
    pub key: Binary,
}

/// Message received from the relayer.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct PreExecutionMsg {
    /// Task ID coming from the relayer.
    pub task_id: u64,
    /// Handle to be called at destination contract.
    pub handle: String,
    /// Destination contract address and code hash.
    pub routing_info: Contract,
    /// Encryption of (data, routing info, and user address/verifying key).
    pub payload: Binary,
    /// Unique random bytes used to encrypt payload
    pub nonce: Binary,
    /// Hash of encrypted input values.
    pub payload_hash: Binary,
    /// Signature of hash of encrypted input values.
    pub payload_signature: Binary,
    /// User verification key / public chain address.
    pub sender_info: Sender,
}

impl PreExecutionMsg {
    pub fn verify<S: Storage, A: Api, Q: Querier>(&self, deps: &Extern<S, A, Q>) -> StdResult<()> {
        deps.api
            .secp256k1_verify(
                self.payload_hash.as_slice(),
                self.payload_signature.as_slice(),
                self.sender_info.public_key.as_slice(),
            )
            .map_err(|err| StdError::generic_err(err.to_string()))?;
        Ok(())
    }
    pub fn decrypt_payload(&self, sk: Binary) -> StdResult<Payload> {
        let my_secret = SecretKey::from_slice(sk.as_slice())
            .map_err(|err| StdError::generic_err(err.to_string()))?;
        let their_public = PublicKey::from_slice(self.sender_info.public_key.as_slice())
            .map_err(|err| StdError::generic_err(err.to_string()))?;
        let shared_key = SharedSecret::new(&their_public, &my_secret);
        let cipher = ChaCha20Poly1305::new_from_slice(shared_key.as_ref())
            .map_err(|_err| StdError::generic_err("could not create cipher".to_string()))?; // TODO change msg back to err.to_string()
        let nonce = Nonce::from_slice(self.nonce.as_slice()); // TODO get nonce as part of the input message
        let plaintext = cipher
            .decrypt(nonce, self.payload.as_slice())
            .map(Binary)
            .map_err(|_err| StdError::generic_err("could not decrypt".to_string()))?;
        let payload: Payload = from_binary(&plaintext)?;
        Ok(payload)
    }
}

/// Message sent to destination private contract with decrypted inputs
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct PrivContractHandleMsg {
    /// JSON formatted string of decrypted user inputs.
    pub input_values: String,
    /// Handle function to be called in the destination contract.
    pub handle: String,
    /// sha256(input_values)
    pub input_hash: [u8;32],
    /// Signature of sha256(input_values), signed by the private gateway.
    pub signature: Binary,
}

impl HandleCallback for PrivContractHandleMsg {
    const BLOCK_SIZE: usize = 256;
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

/// Message sent to the relayer.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct BroadcastMsg {
    /// JSON encoded string of results from the private contract.
    pub result: String,
    /// Encryption of (data, routing info, and user info).
    pub payload: Binary,
    /// Task ID coming from the gateway.
    pub task_id: u64,
    /// SHA256 hash of (result, packet, task_id)
    pub output_hash: Binary,
    /// `output_hash` signed with Private Gateway key
    pub signature: Binary,
}

impl HandleCallback for BroadcastMsg {
    const BLOCK_SIZE: usize = 256;
}