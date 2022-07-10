#![allow(unused_imports)]
use cosmwasm_std::{
    debug_print, log, to_binary, Api, Empty, Env, Extern, HandleResponse, HandleResult,
    InitResponse, InitResult, Querier, QueryResult, Storage,
};
use secret_toolkit::{
    crypto::secp256k1::{PrivateKey, PublicKey, Signature},
    crypto::{sha_256, Prng},
    utils::{pad_handle_result, pad_query_result, HandleCallback},
};

use crate::{
    msg::{
        ContractStatus, CounterHandleMsg, HandleMsg, InitMsg, InputResponse, OutputResponse,
        PublicKeyResponse, QueryMsg, ResponseStatus::Success,
    },
    state::{
        config, config_read, creator_address, creator_address_read, load_signing_key, map2caller,
        my_address, my_address_read, prng, prng_read, State,
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
////////////////////////////////////// Init ///////////////////////////////////////
/// Returns InitResult
///
/// Initializes the contract
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `msg` - InitMsg passed in with the instantiation message
pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: InitMsg,
) -> InitResult {
    // Save this contract's address
    let my_address_raw = &deps.api.canonical_address(&env.contract.address)?;
    my_address(&mut deps.storage).save(my_address_raw)?;

    // Save the address of the contract's creator
    let creator_raw = deps.api.canonical_address(&env.message.sender)?;
    creator_address(&mut deps.storage).save(&creator_raw)?;

    // Set admin address if provided, or else use creator address
    let admin_raw = msg
        .admin
        .map(|a| deps.api.canonical_address(&a))
        .transpose()?
        .unwrap_or(creator_raw);

    // Create and save pseudo-random-number-generator seed from user provided entropy string
    let prng_seed: Vec<u8> = sha_256(base64::encode(msg.entropy.clone()).as_bytes()).to_vec();

    // Generate ed25519 key pair for encryption
    let encryption_key_pair = ed25519_compact::KeyPair::from_slice(&[0; 64]).unwrap();

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
            pk: public_key.serialize_compressed().to_vec(),
            sk: secret_key.serialize().to_vec(),
        },
    };

    config(&mut deps.storage).save(&state)?;
    prng(&mut deps.storage).save(&prng_seed)?;

    Ok(InitResponse {
        messages: vec![],
        log: vec![
            log("encryption_public_key", "pubkey1"), // need to implement display formatting
            log("signing_public_key", "pubkey2"),    // need to implement display formatting
        ],
    })
}

#[cfg(not(feature = "library"))]
///////////////////////////////////// Handle //////////////////////////////////////
/// Returns HandleResult
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `msg` - HandleMsg passed in with the execute message
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
    // map task ID to calling contract
    let task_id = msg.task_id;
    let caller = msg.creator.address.to_string();
    map2caller(&mut deps.storage).insert(&task_id.to_le_bytes(), caller)?;

    // verify that signature is correct
    let message = &[1u8; 32]; // hash of the unencrypted input values
    let signature = msg.signature;
    let public_key = msg.creator.verifying_key; // TODO how to get verifying key?

    // The signature and public key are in "Cosmos" format:
    // signature: Serialized "compact" signature (64 bytes).
    // public key: Serialized according to SEC 2
    deps.api
        .secp256k1_verify(message, signature.as_slice(), public_key.as_slice());

    // decrypt input values

    // load key and sign(task ID + input values)
    let private_key = load_signing_key(&deps.storage)?;
    let task_id_signature = SecretKey::from_slice(private_key.as_slice())
        .unwrap()
        .sign(msg.task_id.to_le_bytes(), None); // write the error case, make some noise

    // example message construction (consider having a secondary contract that can upgrade to add new message types)
    let reset_msg = CounterHandleMsg::Reset { count: 200 };

    let cosmos_msg = reset_msg.to_cosmos_msg(msg.contract.hash, msg.contract.address, None)?;

    Ok(HandleResponse {
        messages: vec![cosmos_msg],
        log: vec![log("task_ID", &msg.task_id)],
        data: Some(to_binary(&InputResponse {
            status: Success,
            task_id: task_id,
            creating_address: msg.creator.address,
        })?),
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
    let task_id: u128 = 1;
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
        data: Some(to_binary(&OutputResponse {
            status: Success,
            task_id: task_id,
            creating_address: String::new(),
        })?), // could look into returning outputs here instead of in logs
    })
}

#[cfg(not(feature = "library"))]
/////////////////////////////////////// Query /////////////////////////////////////
/// Returns QueryResult
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `msg` - QueryMsg passed in with the query call
pub fn query<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>, msg: QueryMsg) -> QueryResult {
    let response = match msg {
        QueryMsg::GetPublicKey {} => query_public_key(&deps),
    };
    pad_query_result(response, BLOCK_SIZE)
}

fn query_public_key<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>) -> QueryResult {
    let state: State = config_read(&deps.storage).load()?;
    to_binary(&PublicKeyResponse {
        key: state.signing_key.pk,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use cosmwasm_std::{coins, from_binary, Binary, HumanAddr};

    use chacha20poly1305::aead::{Aead, NewAead};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    use secret_toolkit::utils::types::Contract;

    #[test]
    fn chacha20poly1305() {
        let key = Key::from_slice(b"an example very very secret key."); // 32-bytes
        let cipher = ChaCha20Poly1305::new(key);

        let nonce = Nonce::from_slice(b"unique nonce"); // 12-bytes; unique per message

        let ciphertext = cipher
            .encrypt(nonce, b"plaintext message".as_ref())
            .expect("encryption failure!"); // NOTE: handle this error to avoid panics!
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .expect("decryption failure!"); // NOTE: handle this error to avoid panics!

        assert_eq!(&plaintext, b"plaintext message");
    }

    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env("creator", &coins(1000, "earth"));
        let msg = InitMsg {
            admin: None,
            entropy: "secret".to_string(),
        };

        // we can just call .unwrap() to assert this was a success
        let res = init(&mut deps, env, msg).unwrap();
        assert_eq!(0, res.messages.len());

        // it worked, let's query the state
        let msg = QueryMsg::GetPublicKey {};
        let res = query(&deps, msg);
        assert!(res.is_ok(), "query failed: {}", res.err().unwrap());
        let value: PublicKeyResponse = from_binary(&res.unwrap()).unwrap();
        assert!(value.key.len() == 33 as usize);
    }

    #[ignore]
    #[test]
    fn pre_execution() {
        // initialize
        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env("creator", &coins(1000, "earth"));
        let msg = InitMsg {
            admin: None,
            entropy: "secret".to_string(),
        };

        // mock inputs
        let unencrypted_inputs: Binary;
        let verifying_key = secret_toolkit::crypto::secp256k1::PublicKey::parse(b"seed").unwrap();

        let task_id = 1;
        let input_values = Binary(vec![]);
        let handle = Binary(vec![]);
        let contract = Contract {
            address: HumanAddr("human address".to_string()),
            hash: "contract hash".to_string(),
        };
        let signature = Binary([0u8; 32].to_vec());
        let creator = Sender {
            address: "sender address".to_string(),
            verifying_key: Binary(verifying_key.serialize_compressed().to_vec()),
        };

        let inputs = Inputs {
            task_id,
            input_values,
            handle,
            contract,
            signature,
            creator,
        };

        let msg = HandleMsg::Input { inputs: inputs };
        let res = super::handle(&mut deps, env, msg);
        assert!(res.is_ok(), "query failed: {}", res.err().unwrap());
        let value: InputResponse = from_binary(&res.unwrap().data.unwrap()).unwrap();
        assert!(value.task_id == 1)
    }

    #[ignore]
    #[test]
    fn post_execution() {
        todo!()
    }
}
