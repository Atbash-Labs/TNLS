use cosmwasm_std::{
    debug_print, log, to_binary, Api, Binary, Env, Extern, HandleResponse, HandleResult, HumanAddr,
    InitResponse, InitResult, Querier, QueryResult, StdError, StdResult, Storage,
};
use secret_toolkit::utils::{pad_handle_result, pad_query_result, HandleCallback};

use crate::{
    msg::{
        HandleMsg, InitMsg, InputResponse, PostExecutionMsg, PrivContractHandleMsg, QueryMsg,
        ResponseStatus::Failure, ResponseStatus::Success, TestResponse,
    },
    state::{balances, balances_read, config, config_read, Balance, State},
};

use serde::{Deserialize, Serialize};

/// pad handle responses and log attributes to blocks of 256 bytes to prevent leaking info based on
/// response size
pub const BLOCK_SIZE: usize = 256;

pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: InitMsg,
) -> InitResult {
    let state = State {
        gateway_address: msg.gateway_address,
        gateway_hash: msg.gateway_hash,
        gateway_key: msg.gateway_key,
    };

    config(&mut deps.storage).save(&state)?;

    debug_print!("Contract was initialized by {}", env.message.sender);

    Ok(InitResponse::default())
}

pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) -> HandleResult {
    let response = match msg {
        HandleMsg::Input { input } => try_handle(deps, env, input),
    };
    pad_handle_result(response, BLOCK_SIZE)
}

// acts like a gateway message handle filter
pub fn try_handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: PrivContractHandleMsg,
) -> HandleResult {
    // verify signature with stored gateway public key
    let gateway_key = config_read(&deps.storage).load()?.gateway_key;
    deps.api
        .secp256k1_verify(
            msg.input_hash.as_slice(),
            msg.signature.as_slice(),
            gateway_key.as_slice(),
        )
        .map_err(|err| StdError::generic_err(err.to_string()))?;

    // determine which function to call based on the included handle
    let handle = msg.handle.as_str();
    match handle {
        "store_input" => try_store_input(deps, env, msg.input_values, msg.task_id, msg.input_hash),
        "compare" => try_compare(deps, env, msg.input_values, msg.task_id, msg.input_hash),
        _ => Ok(HandleResponse {
            messages: vec![],
            log: vec![],
            data: Some(to_binary(&InputResponse { status: Failure })?),
        }),
    }
}

pub fn try_store_input<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    _env: Env,
    input_values: String,
    task_id: u64,
    input_hash: Binary,
) -> HandleResult {
    let config = config_read(&deps.storage).load()?;

    let balance: Balance = serde_json_wasm::from_str(&input_values).unwrap();
    let raw_owner = deps.api.canonical_address(&balance.owner)?;
    balances(&mut deps.storage).save(raw_owner.as_slice(), &balance.amount)?;

    let callback_msg = PostExecutionMsg {
        result: String::new(),
        task_id,
        input_hash,
    }
    .to_cosmos_msg(config.gateway_hash, config.gateway_address, None)?;

    debug_print("stored balance successfully");
    Ok(HandleResponse {
        messages: vec![callback_msg],
        log: vec![],
        data: Some(to_binary(&InputResponse { status: Success })?),
    })
}

#[derive(Serialize, Deserialize)]
pub struct Comparison {
    pub address_a: HumanAddr,
    pub address_b: HumanAddr,
}

pub fn try_compare<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    _env: Env,
    input_values: String,
    task_id: u64,
    input_hash: Binary,
) -> HandleResult {
    let config = config_read(&deps.storage).load()?;

    let comparison: Comparison = serde_json_wasm::from_str(&input_values).unwrap();

    let raw_address_a = deps.api.canonical_address(&comparison.address_a)?;
    let raw_address_b = deps.api.canonical_address(&comparison.address_b)?;

    let balance_a = balances_read(&deps.storage).load(raw_address_a.as_slice())?;
    let balance_b = balances_read(&deps.storage).load(raw_address_b.as_slice())?;

    let result = if balance_a > balance_b {
        comparison.address_a
    } else {
        comparison.address_b
    };

    let callback_msg = PostExecutionMsg {
        result: result.to_string(),
        task_id,
        input_hash,
    }
    .to_cosmos_msg(config.gateway_hash, config.gateway_address, None)?;

    debug_print("compared balances successfully");
    Ok(HandleResponse {
        messages: vec![callback_msg],
        log: vec![],
        data: Some(to_binary(&InputResponse { status: Success })?),
    })
}

pub fn query<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>, msg: QueryMsg) -> QueryResult {
    let response = match msg {
        QueryMsg::Query {} => query_input(deps),
    };
    pad_query_result(response, BLOCK_SIZE)
}

fn query_input<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>) -> QueryResult {
    let message = "congratulations".to_string();
    to_binary(&TestResponse { message })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use cosmwasm_std::{coins, from_binary, HumanAddr, StdError};

    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env("creator", &coins(1000, "earth"));
        let msg = InitMsg {
            gateway_address: HumanAddr("fake address".to_string()),
            gateway_hash: "fake code hash".to_string(),
            gateway_key: Binary(b"fake key".to_vec()),
        };

        // we can just call .unwrap() to assert this was a success
        let res = init(&mut deps, env, msg).unwrap();
        assert_eq!(0, res.messages.len());

        // it worked, let's query
        let res = query(&deps, QueryMsg::Query {});
        assert!(res.is_ok(), "query failed: {}", res.err().unwrap());
        let value: TestResponse = from_binary(&res.unwrap()).unwrap();
        assert_eq!("congratulations", value.message);
    }

    #[ignore]
    #[test]
    fn store_input() {
        todo!()
    }

    #[ignore]
    #[test]
    fn compare() {
        todo!()
    }
}
