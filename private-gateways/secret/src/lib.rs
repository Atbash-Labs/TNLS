/// Master Private Gateway
///
/// * bullet point
/// * bullet point
///
/// ## Usage
///
/// ```rust,ignore
/// use tnls_gateway::*;
///
/// // A destination contract address
/// let contract = Contract {
///     address,
///     hash,
/// };
///
/// let inputs = "something";
///
/// // Generates a new gateway message from inputs
/// let message = TnlsMessage::new(contract, inputs);
/// ```
///
/// ## Cargo Features
///
/// * `library`: disable all init/handle/query exports
pub mod contract;
pub mod msg;
pub mod state;
pub mod types;

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::contract;
    use cosmwasm_std::{
        do_handle, do_init, do_query, ExternalApi, ExternalQuerier, ExternalStorage,
    };

    #[no_mangle]
    extern "C" fn init(env_ptr: u32, msg_ptr: u32) -> u32 {
        do_init(
            &contract::init::<ExternalStorage, ExternalApi, ExternalQuerier>,
            env_ptr,
            msg_ptr,
        )
    }

    #[no_mangle]
    extern "C" fn handle(env_ptr: u32, msg_ptr: u32) -> u32 {
        do_handle(
            &contract::handle::<ExternalStorage, ExternalApi, ExternalQuerier>,
            env_ptr,
            msg_ptr,
        )
    }

    #[no_mangle]
    extern "C" fn query(msg_ptr: u32) -> u32 {
        do_query(
            &contract::query::<ExternalStorage, ExternalApi, ExternalQuerier>,
            msg_ptr,
        )
    }

    // Other C externs like cosmwasm_vm_version_1, allocate, deallocate are available
    // automatically because we `use cosmwasm_std`.
}
