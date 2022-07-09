//! Master Private Gateway
//! description...

use cosmwasm_std::{
    debug_print, log, to_binary, Api, Binary, Empty, Env, Extern, HandleResponse, HandleResult,
    InitResponse, InitResult, Querier, QueryResult, StdResult, Storage,
};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};
use secret_toolkit::{
    crypto::secp256k1::{PrivateKey, PublicKey, Signature},
    crypto::{sha_256, Prng},
    incubator::{CashMap, ReadOnlyCashMap},
    utils::{pad_handle_result, pad_query_result, HandleCallback},
};

use crate::{
    msg::{
        ContractStatus, CounterHandleMsg, HandleAnswer, HandleMsg, InitMsg, QueryAnswer, QueryMsg,
        ResponseStatus::Success,
    },
    state::{
        config_read, config_write, load, load_signing_key, may_load, save, State, CONFIG_KEY,
        CREATOR_KEY, MY_ADDRESS_KEY, PRNG_SEED_KEY, TASK_KEY,
    },
    types::*,
};

use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_compact::*;

/// pad handle responses and log attributes to blocks of 256 bytes to prevent leaking info based on
/// response size
pub const BLOCK_SIZE: usize = 256;

#[cfg(not(feature = "library"))]
pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: InitMsg,
) -> InitResult {
    // Save the address of the contract's creator
    let creator_raw = deps.api.canonical_address(&env.message.sender)?;
    save(&mut deps.storage, CREATOR_KEY, &creator_raw)?;

    // Save this contract's address
    save(
        &mut deps.storage,
        MY_ADDRESS_KEY,
        &deps.api.canonical_address(&env.contract.address)?,
    )?;

    // Set admin address if provided, or else use creator address
    let admin_raw = msg
        .admin
        .map(|a| deps.api.canonical_address(&a))
        .transpose()?
        .unwrap_or(creator_raw);

    // Create and save pseudo-random-number-generator seed from user provided entropy string
    let prng_seed: Vec<u8> = sha_256(base64::encode(msg.entropy.clone()).as_bytes()).to_vec();

    // Generate ed25519 key pair for encryption
    let encryption_key_pair = ed25519_compact::KeyPair::from_slice(&prng_seed).unwrap();

    // Generate secp256k1 key pair for signing messages
    let mut rng = Prng::new(&prng_seed, msg.entropy.as_bytes()); // is this the best way to generate randomness?
    let secret_key = PrivateKey::parse(&rng.rand_bytes())?;
    let public_key = secret_key.pubkey();

    // Save both key pairs
    let state = State {
        admin: admin_raw.clone(),
        tx_cnt: 0,
        status: ContractStatus::Normal.to_u8(),
        encryption_key: crate::state::KeyPair {
            pk: encryption_key_pair.pk.to_vec(),
            sk: encryption_key_pair.sk.to_vec(),
        },
        signing_key: crate::state::KeyPair {
            pk: public_key.serialize().to_vec(),
            sk: secret_key.serialize().to_vec(),
        },
    };

    save(&mut deps.storage, CONFIG_KEY, &state)?;
    save(&mut deps.storage, PRNG_SEED_KEY, &prng_seed)?;

    debug_print!("Contract was initialized by {}", env.message.sender);

    Ok(InitResponse {
        messages: vec![],
        log: vec![
            log("encryption_public_key", "pubkey1"), // need to implement display formatting
            log("signing_public_key", "pubkey2"),    // need to implement display formatting
        ],
    })
}

#[cfg(not(feature = "library"))]
pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) -> HandleResult {
    let response = match msg {
        HandleMsg::Input { inputs } => pre_execution(deps, env, inputs),
        HandleMsg::Output { outputs } => post_execution(deps, env, outputs),
    };
    pad_handle_result(response, BLOCK_SIZE)
}

fn pre_execution<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: Inputs,
) -> HandleResult {
    let message = &[1u8; 32]; // hash of the unencrypted input values
    let signature = msg.signature;
    let public_key = msg.creating_address.verifying_key; // TODO how to get verifying key?
                                                         // verify that signature is correct

    // The signature and public key are in "Cosmos" format:
    // signature: Serialized "compact" signature (64 bytes).
    // public key: Serialized according to SEC 2
    deps.api
        .secp256k1_verify(message, signature.as_slice(), public_key.as_slice());

    // load key and sign
    let private_key = load_signing_key(&deps.storage)?;
    let task_id_signature = SecretKey::from_slice(private_key.as_slice())
        .unwrap()
        .sign(msg.task_id.to_le_bytes(), None); // write the error case, make some noise

    // example message construction (consider having a secondary contract that can upgrade to add new message types)
    let reset_msg = CounterHandleMsg::Reset { count: 200 };

    let cosmos_msg = reset_msg.to_cosmos_msg(msg.contract_hash, msg.contract_address, None)?;

    Ok(HandleResponse {
        messages: vec![cosmos_msg],
        log: vec![log("task_ID", &msg.task_id)],
        data: Some(to_binary(&HandleAnswer::Input { status: Success })?),
    })
}

fn post_execution<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: Empty,
) -> HandleResult {
    // verify that calling contract is correct one for Task ID (check map)
    // sign and broadcast pair(?) of outputs + Task ID + inputs
    let output = "output";
    let task_id: u64 = 1;
    let private_key = load_signing_key(&deps.storage)?;
    let signature = SecretKey::from_slice(private_key.as_slice()) //I believe this is a simple transformation of types
        .unwrap()
        .sign(b"message", None); // write the error case, make some noise

    Ok(HandleResponse {
        messages: vec![],
        log: vec![
            log("task_ID", task_id),
            log("outputs", output),
            log("signature", &base64::encode(&signature)),
        ],
        data: Some(to_binary(&HandleAnswer::Output { status: Success })?), // could look into returning outputs here instead of in logs
    })
}

#[cfg(not(feature = "library"))]
pub fn query<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    msg: QueryMsg,
) -> StdResult<Binary> {
    let response = match msg {
        QueryMsg::GetPublicKey {} => query_public_key(&deps),
    };
    pad_query_result(response, BLOCK_SIZE)
}

fn query_public_key<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>) -> QueryResult {
    let state = config_read(&deps.storage).load()?;
    to_binary(&QueryAnswer::GetPublicKey {
        key: state.signing_key.pk,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use cosmwasm_std::{coins, from_binary, StdError};

    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies(20, &[]);

        let msg = InitMsg {
            admin: None,
            entropy: "secret".to_string(),
        };
        let env = mock_env("creator", &coins(1000, "earth"));

        // TODO assert that keys were generated

        // we can just call .unwrap() to assert this was a success
        let res = init(&mut deps, env, msg).unwrap();
        assert_eq!(0, res.messages.len());
    }

    #[test]
    fn increment() {
        todo!()
    }
}
