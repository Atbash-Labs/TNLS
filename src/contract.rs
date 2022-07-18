use cosmwasm_std::{
    log, to_binary, Api, Binary, Env, Extern, HandleResponse, HandleResult, InitResponse,
    InitResult, Querier, QueryResult, StdError, Storage,
};
use secret_toolkit::{
    crypto::secp256k1::{PrivateKey, PublicKey},
    crypto::{sha_256, Prng},
    utils::{pad_handle_result, pad_query_result, HandleCallback},
};

use crate::{
    msg::{
        ContractStatus, HandleMsg, InitMsg, InputResponse, OutputResponse, PrivContractHandleMsg,
        PublicKeyResponse, QueryMsg,
    },
    state::{
        config, config_read, creator_address, map2caller, map2caller_read, my_address, prng,
        KeyPair, State,
    },
    types::*,
};

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

    // Create pseudo-random-number-generator seed from user provided entropy string
    let prng_seed: Vec<u8> = sha_256(base64::encode(msg.entropy).as_bytes()).to_vec();

    // Generate secp256k1 key pair for encryption
    let (secret, public, new_prng_seed) = generate_keypair(&env, prng_seed, None)?;
    let encryption_keys = KeyPair {
        sk: Binary(secret.serialize().to_vec()), // private key is 32 bytes,
        pk: Binary(public.serialize_compressed().to_vec()), // public key is 33 bytes
    };

    // Generate secp256k1 key pair for signing messages
    let (secret, public, new_prng_seed) = generate_keypair(&env, new_prng_seed, None)?;
    let signing_keys = KeyPair {
        sk: Binary(secret.serialize().to_vec()), // private key is 32 bytes,
        pk: Binary(public.serialize_compressed().to_vec()), // public key is 33 bytes
    };

    // Save both key pairs
    let state = State {
        admin: admin_raw,
        tx_cnt: 0,
        status: ContractStatus::Normal.to_u8(),
        encryption_keys: encryption_keys.clone(),
        signing_keys: signing_keys.clone(),
    };

    config(&mut deps.storage).save(&state)?;
    prng(&mut deps.storage).save(&new_prng_seed)?;

    Ok(InitResponse {
        messages: vec![],
        log: vec![
            log("encryption_pubkey", &encryption_keys.pk),
            log("signing_pubkey", &signing_keys.pk),
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
    _env: Env,
    msg: PreExecutionMsg,
) -> HandleResult {
    // map task ID to sender
    map2caller(&mut deps.storage)
        .insert(&msg.task_id.to_le_bytes(), msg.routing_info.address.clone())?;

    // verify that signature is correct
    msg.verify(deps)?;

    // load config
    let config = config_read(&deps.storage).load()?;

    // decrypt payload
    let payload = msg.decrypt_payload(config.encryption_keys.sk)?;
    let input_values = payload.data;

    // verify the internal verification key (inside the packet?) matches the user address
    if payload.sender != msg.sender {
        return Err(StdError::generic_err("verification key mismatch"));
    }
    // verify the routing info matches the internally stored routing info
    if msg.routing_info != payload.routing_info {
        return Err(StdError::generic_err("routing info mismatch"));
    }

    // TODO find a way to construct the handle message
    let handle = msg.handle;

    // load key and sign(task ID + input values)
    let mut signing_key_bytes = [0u8; 32];
    signing_key_bytes.copy_from_slice(config.signing_keys.sk.as_slice());

    let signature = PrivateKey::parse(&signing_key_bytes)?
        .sign(&msg.task_id.to_le_bytes(), deps.api)
        .serialize();
    let signature = to_binary(&signature.to_vec())?;

    // in it's current form, every message sent from this private gateway has the same message structure
    let contract_msg = PrivContractHandleMsg {
        input_values,
        handle,
        signature,
    };

    let cosmos_msg =
        contract_msg.to_cosmos_msg(msg.routing_info.hash, msg.routing_info.address, None)?;

    Ok(HandleResponse {
        messages: vec![cosmos_msg],
        log: vec![
            log("task_ID", &msg.task_id),
            log("status", "sent to secret contract"),
        ],
        data: Some(to_binary(&InputResponse {
            task_id: msg.task_id,
            creating_address: msg.sender.address,
        })?),
    })
}

fn post_execution<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: PostExecutionMsg,
) -> HandleResult {
    // verify that calling contract is correct one for Task ID (check map)
    let calling_contract = env.message.sender;
    if calling_contract
        != map2caller_read(&deps.storage)
            .load(&msg.task_id.to_le_bytes())?
            .address
    {
        return Err(StdError::generic_err(
            "calling contract does not match task ID",
        ));
    }

    // sign and broadcast pair of outputs + Task ID + inputs
    let output = msg.result;
    let task_id = msg.task_id;

    // load config
    let config = config_read(&deps.storage).load()?;

    // load this gateway's signing key
    let private_key = config.signing_keys.sk;

    let mut signing_key_bytes = [0u8; 32];
    signing_key_bytes.copy_from_slice(private_key.as_slice());

    let signature = PrivateKey::parse(&signing_key_bytes)?
        .sign(output.as_slice(), deps.api)
        .serialize();

    let signature = to_binary(&signature.to_vec())?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![log("task_ID", task_id), log("status", "success")],
        data: Some(to_binary(&OutputResponse {
            task_id,
            calling_contract,
            output,
            signature,
        })?),
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
        QueryMsg::GetPublicKey {} => query_public_key(deps),
    };
    pad_query_result(response, BLOCK_SIZE)
}

fn query_public_key<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>) -> QueryResult {
    let state: State = config_read(&deps.storage).load()?;
    to_binary(&PublicKeyResponse {
        key: state.signing_keys.pk,
    })
}

/////////////////////////////////////// Helpers /////////////////////////////////////

/// Returns (PublicKey, StaticSecret, Vec<u8>)
///
/// generates a public and privite key pair and generates a new PRNG_SEED with or without user entropy.
///
/// # Arguments
///
/// * `env` - contract's environment to be used for randomization
/// * `prng_seed` - required prng seed for randomization
/// * `user_entropy` - optional random string input by the user
pub fn generate_keypair(
    env: &Env,
    prng_seed: Vec<u8>,
    user_entropy: Option<String>,
) -> Result<(PrivateKey, PublicKey, Vec<u8>), StdError> {
    // generate new rng seed
    let new_prng_bytes: [u8; 32] = match user_entropy {
        Some(s) => new_entropy(env, prng_seed.as_ref(), s.as_bytes()),
        None => new_entropy(env, prng_seed.as_ref(), prng_seed.as_ref()),
    };

    // generate and return key pair
    let mut rng = Prng::new(prng_seed.as_ref(), new_prng_bytes.as_ref());
    let sk = PrivateKey::parse(&rng.rand_bytes())?;
    let pk = sk.pubkey();

    Ok((sk, pk, new_prng_bytes.to_vec()))
}

/// Returns [u8;32]
///
/// generates new entropy from block data, does not save it to the contract.
///
/// # Arguments
///
/// * `env` - Env of contract's environment
/// * `seed` - (user generated) seed for rng
/// * `entropy` - Entropy seed saved in the contract
pub fn new_entropy(env: &Env, seed: &[u8], entropy: &[u8]) -> [u8; 32] {
    // 16 here represents the lengths in bytes of the block height and time.
    let entropy_len = 16 + env.message.sender.len() + entropy.len();
    let mut rng_entropy = Vec::with_capacity(entropy_len);
    rng_entropy.extend_from_slice(&env.block.height.to_be_bytes());
    rng_entropy.extend_from_slice(&env.block.time.to_be_bytes());
    rng_entropy.extend_from_slice(env.message.sender.0.as_bytes());
    rng_entropy.extend_from_slice(entropy);

    let mut rng = Prng::new(seed, &rng_entropy);

    rng.rand_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use cosmwasm_std::{coins, from_binary, Binary};

    use chacha20poly1305::aead::{Aead, NewAead};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

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
            entropy: "secret".to_owned(),
        };

        // we can just call .unwrap() to assert this was a success
        let res = init(&mut deps, env, msg).unwrap();
        assert_eq!(2, res.log.len());

        // it worked, let's query the state
        let msg = QueryMsg::GetPublicKey {};
        let res = query(&deps, msg);
        assert!(res.is_ok(), "query failed: {}", res.err().unwrap());
        let value: PublicKeyResponse = from_binary(&res.unwrap()).unwrap();
        assert_eq!(value.key.as_slice().len(), 33);
    }

    #[test]
    fn pre_execution() {
        // initialize
        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env("creator", &coins(1000, "earth"));
        let msg = InitMsg {
            admin: None,
            entropy: "secret".to_string(),
        };
        let res = init(&mut deps, env.clone(), msg).unwrap();
        let pubkey = Binary::from_base64(&res.log[0].value).unwrap();
        assert_eq!(pubkey.len(), 33);

        // todo!();

        // mock inputs
        // let inputs = PreExecutionMsg {
        //     task_id,
        //     handle,
        //     routing_info,
        //     payload,
        //     payload_hash,
        //     payload_signature,
        //     sender,
        // };
        // let msg = HandleMsg::Input { inputs: inputs };
        // let res = super::handle(&mut deps, env.clone(), msg);
        // assert!(res.is_ok(), "query failed: {}", res.err().unwrap());
        // let value: InputResponse = from_binary(&res.unwrap().data.unwrap()).unwrap();
        // assert!(value.task_id == 1)
    }

    #[ignore]
    #[test]
    fn post_execution() {
        todo!()
    }
}
