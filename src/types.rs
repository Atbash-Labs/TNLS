use cosmwasm_std::{
    from_binary, Api, Binary, Extern, HumanAddr, Querier, StdError, StdResult, Storage,
};
use secret_toolkit::utils::types::Contract;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use secp256k1::{ecdh::SharedSecret, PublicKey, SecretKey};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Sender {
    // user public chain address
    pub address: HumanAddr,
    // user verification key
    pub public_key: Binary,
}

/// A packet containing user message data.
/// It is encrypted with a shared secret of the user's private key and the Private Gateway's public key.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Payload {
    // input values, json formatted string
    pub data: String,
    // destination address on private network
    pub routing_info: Contract,
    // user verification key / public chain address
    pub sender: Sender,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct PreExecutionMsg {
    /// Task ID coming from the relayer.
    pub task_id: u64,
    /// Handle to be called at destination contract.
    pub handle: String,
    /// Destination contract address and code hash.
    pub routing_info: Contract,
    /// Encryption of (data, routing info, and user address/verifying key). Includes additional data (AD).
    pub payload: Binary,
    /// Hash of unencrypted input values.
    pub payload_hash: Binary,
    /// Signature of hash of unencrypted input values.
    pub payload_signature: Binary,
    /// User verification key / public chain address.
    pub sender: Sender,
}

impl PreExecutionMsg {
    pub fn verify<S: Storage, A: Api, Q: Querier>(&self, deps: &Extern<S, A, Q>) -> StdResult<()> {
        deps.api
            .secp256k1_verify(
                self.payload_hash.as_slice(),
                self.payload_signature.as_slice(),
                self.sender.public_key.as_slice(),
            )
            .map_err(|err| StdError::generic_err(err.to_string()))?;
        Ok(())
    }
    pub fn decrypt_payload(&self, sk: Binary) -> StdResult<Payload> {
        let my_secret = SecretKey::from_slice(sk.as_slice())
            .map_err(|err| StdError::generic_err(err.to_string()))?;
        let their_public = PublicKey::from_slice(self.sender.public_key.as_slice())
            .map_err(|err| StdError::generic_err(err.to_string()))?;
        let shared_key = SharedSecret::new(&their_public, &my_secret);
        let cipher = ChaCha20Poly1305::new_from_slice(shared_key.as_ref())
            .map_err(|err| StdError::generic_err(err.to_string()))?;
        let nonce = Nonce::from_slice(b"unique nonce"); // can we get the nonce from the ETH transaction?
        let plaintext = cipher
            .decrypt(nonce, self.payload.as_slice())
            .map(Binary)
            .map_err(|err| StdError::generic_err(err.to_string()))?;
        let payload: Payload = from_binary(&plaintext)?;
        Ok(payload)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct PostExecutionMsg {
    pub result: Binary,
    pub task_id: u64,
    pub parameters: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct BroadcastMsg {
    // result, packet, task ID
    pub output: (String, Binary, u64),
    // output signed with Private Gateway key
    pub signature: Binary,
}
