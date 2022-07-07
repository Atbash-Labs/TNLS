use crate::{
    msg::{
        CounterHandleMsg, HandleAnswer, HandleMsg, InitMsg, QueryAnswer, QueryMsg,
        ResponseStatus::Success,
    },
    state::{config_read, config_write, State},
    types::*,
};
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use cosmwasm_std::{
    debug_print, log, to_binary, Api, Binary, Env, Extern, HandleResponse, HandleResult,
    InitResponse, InitResult, Querier, QueryResult, StdResult, Storage,
};
use ed25519_compact::*;
use secp256k1::{rand::thread_rng, Secp256k1};
use secret_toolkit::{
    crypto::secp256k1::*,
    crypto::sha_256,
    serialization::Base64,
    utils::{pad_handle_result, pad_query_result, HandleCallback},
};

/// pad handle responses and log attributes to blocks of 256 bytes to prevent leaking info based on
/// response size
pub const BLOCK_SIZE: usize = 256;

pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: InitMsg,
) -> InitResult {
    // Should we include a supplied entropy seed?
    let encryption_key_pair =
        ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::generate()); // should use a different method for seed to reduce dependencies

    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut thread_rng());

    let state = State {
        encryption_key: crate::state::KeyPair {
            pk: base64::encode(encryption_key_pair.pk.as_ref()),
            sk: base64::encode(encryption_key_pair.sk.as_ref()),
        },
        signing_key: crate::state::KeyPair {
            pk: base64::encode(&public_key.serialize()),
            sk: base64::encode(&secret_key.serialize_secret()),
        },
        owner: deps.api.canonical_address(&env.message.sender)?,
    };

    config_write(&mut deps.storage).save(&state)?;

    debug_print!("Contract was initialized by {}", env.message.sender);

    Ok(InitResponse {
        messages: vec![],
        log: vec![
            log("encryption_public_key", &state.encryption_key.pk),
            log("signing_public_key", &state.signing_key.pk),
        ],
    })
}

pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) -> HandleResult {
    let response = match msg {
        HandleMsg::Input { interchain_message } => pre_execution(deps, env, interchain_message),
        HandleMsg::Output { interchain_message } => post_execution(deps, env, interchain_message),
    };
    pad_handle_result(response, BLOCK_SIZE)
}

fn pre_execution<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: PublicPrivate,
) -> HandleResult {
    // I think this message is supposed to be the "packet" or a hash of the packet
    let message = &[1u8; 32];
    let signature = msg.signature_of_entire_packet;
    let public_key = msg.message_creator.verifying_key;
    // verify that signature is correct
    deps.api
        .secp256k1_verify(message, signature.as_slice(), public_key.as_slice());

    let destination_contract = msg.routing_info.destination;

    // load key and sign
    let private_key = &base64::decode(&config_read(&deps.storage).load()?.signing_key.sk).unwrap();
    let task_id_signature = SecretKey::from_slice(private_key.as_slice())
        .unwrap()
        .sign(msg.task_id.to_le_bytes(), None); // write the error case, make some noise

    // example message construction (consider having a secondary contract that can upgrade to add new message types)
    let reset_msg = CounterHandleMsg::Reset { count: 200 };

    let cosmos_msg = reset_msg.to_cosmos_msg(
        destination_contract.hash,
        destination_contract.address,
        None,
    )?;

    Ok(HandleResponse {
        messages: vec![cosmos_msg],
        log: vec![log("task_ID", &msg.task_id)],
        data: Some(to_binary(&HandleAnswer::Input { status: Success })?),
    })
}

fn post_execution<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: PrivatePublic,
) -> HandleResult {
    // verify that calling contract (which contract exactly) is correct one for Task ID
    // sign and broadcast pair(?) of outputs + Task ID + inputs
    let output = "output";
    let task_id = msg.task_id;
    let private_key = &base64::decode(&config_read(&deps.storage).load()?.signing_key.sk).unwrap();
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
