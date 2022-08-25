use std::cmp::max;

use cosmwasm_std::{
    log, to_binary, Api, Binary, Env, Extern, HandleResponse, HandleResult, InitResponse,
    InitResult, Querier, QueryResult, StdError, Storage,
};
use secret_toolkit::utils::{pad_handle_result, pad_query_result, HandleCallback};

use crate::{
    msg::{GatewayMsg, HandleMsg, InitMsg, QueryMsg, RicherResponse},
    state::{Input, Millionaire, State, CONFIG, MILLIONAIRES},
};

use serde::{Deserialize, Serialize};
use tnls::msg::{InputResponse, PostExecutionMsg, PrivContractHandleMsg, ResponseStatus::Success};

/// pad handle responses and log attributes to blocks of 256 bytes to prevent leaking info based on
/// response size
pub const BLOCK_SIZE: usize = 256;

pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    _env: Env,
    msg: InitMsg,
) -> InitResult {
    let state = State {
        gateway_address: msg.gateway_address,
        gateway_hash: msg.gateway_hash,
        gateway_key: msg.gateway_key,
    };

    // config(&mut deps.storage).save(&state)?;
    CONFIG.save(&mut deps.storage, &state)?;

    Ok(InitResponse::default())
}

pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) -> HandleResult {
    let response = match msg {
        HandleMsg::Input { message } => try_handle(deps, env, message),
    };
    pad_handle_result(response, BLOCK_SIZE)
}

pub fn query<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>, msg: QueryMsg) -> QueryResult {
    let response = match msg {
        QueryMsg::Query {} => todo!(),
    };
    pad_query_result(response, BLOCK_SIZE)
}

// acts like a gateway message handle filter
fn try_handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: PrivContractHandleMsg,
) -> HandleResult {
    // verify signature with stored gateway public key
    let gateway_key = CONFIG.load(&deps.storage)?.gateway_key;
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
        "submit_player" => {
            try_store_input(deps, env, msg.input_values, msg.task_id, msg.input_hash)
        }
        "compare" => try_compare(deps, env, msg.input_values, msg.task_id, msg.input_hash),
        _ => Err(StdError::generic_err("invalid handle".to_string())),
    }
}

fn try_store_input<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    _env: Env,
    input_values: String,
    task_id: u64,
    input_hash: Binary,
) -> HandleResult {
    let config = CONFIG.load(&deps.storage)?;

    let input: Input = serde_json_wasm::from_str(&input_values)
        .map_err(|err| StdError::generic_err(err.to_string()))?;

    let player = Millionaire::new(input.name, input.worth, input.other);

    MILLIONAIRES.insert(&mut deps.storage, &input.address, player)?;

    let result = serde_json_wasm::to_string(&InputResponse { status: Success })
        .map_err(|err| StdError::generic_err(err.to_string()))?;

    let callback_msg = GatewayMsg::Output {
        outputs: PostExecutionMsg {
            result,
            task_id,
            input_hash,
        },
    }
    .to_cosmos_msg(config.gateway_hash, config.gateway_address, None)?;

    Ok(HandleResponse {
        messages: vec![callback_msg],
        log: vec![log("status", "private computation complete")],
        data: None,
    })
}

#[derive(Serialize, Deserialize)]
pub struct Comparison {
    pub address_a: String,
    pub address_b: String,
}

pub fn try_compare<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    _env: Env,
    input_values: String,
    task_id: u64,
    input_hash: Binary,
) -> HandleResult {
    let config = CONFIG.load(&deps.storage)?;

    let comparison: Comparison = serde_json_wasm::from_str(&input_values).unwrap();

    let address_a = &comparison.address_a;
    let address_b = &comparison.address_b;

    let player1 = MILLIONAIRES.get(&deps.storage, address_a).unwrap();
    let player2 = MILLIONAIRES.get(&deps.storage, address_b).unwrap();

    let resp: RicherResponse;

    if player1 == player2 {
        resp = RicherResponse {
            richer: "It's a tie!".to_string(),
        };
    } else {
        let richer = max(player1, player2);
        resp = RicherResponse {
            richer: richer.name,
        };
    };

    let result =
        serde_json_wasm::to_string(&resp).map_err(|err| StdError::generic_err(err.to_string()))?;

    let callback_msg = PostExecutionMsg {
        result: result.to_string(),
        task_id,
        input_hash,
    }
    .to_cosmos_msg(config.gateway_hash, config.gateway_address, None)?;

    Ok(HandleResponse {
        messages: vec![callback_msg],
        log: vec![log("status", "private computation complete")],
        data: None,
    })
}

// fn query_input<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>) -> QueryResult {
//     let message = "congratulations".to_string();
//     to_binary(&TestResponse { message })
// }

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
        // let res = query(&deps, QueryMsg::Query {});
        // assert!(res.is_ok(), "query failed: {}", res.err().unwrap());
        // let value: TestResponse = from_binary(&res.unwrap()).unwrap();
        // assert_eq!("congratulations", value.message);
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
