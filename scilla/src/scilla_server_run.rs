use std::str;

use anyhow::{Result, anyhow};
use evm::ExitSucceed;
use evm_ds::{
    evm::backend::Backend,
    protos::{evm_proto as EvmProto, evm_proto::ExitReasonCps},
};
use jsonrpc_core::Params;
use primitive_types::{H160, H256, U256};
use serde_json::{from_value, json, Value};
use sha2::{Digest, Sha256};
use tracing::*;

use crate::{
    backend_collector::BackendCollector,
    call_scilla_server::{call_scilla_server, ensure_setup_correct},
    scilla_tcp_server::ScillaServer,
    types::*,
};

// These are the directories inside the docker container which scilla will look for.
// These shouldn't really change ever, unless the docker container changes.
pub const SCILLA_SERVER_SOCK_PATH: &str = "/tmp/scilla-server.sock";
pub const SCILLA_SERVER_LIB_PATH: &str = "/scilla/0/src/stdlib/";
pub const SCILLA_SERVER_INIT_PATH: &str = "/tmp/scilla_init/init.json";
pub const SCILLA_SERVER_INPUT_PATH: &str = "/tmp/scilla_input/input.scilla";
pub const SCILLA_SERVER_MESSAGE_PATH: &str = "/tmp/scilla_input/message.scilla";

/// The scheme to calculate scilla contract addresses is different from the EVM as
/// the nonce and hash scheme differ
pub fn calculate_contract_address_scilla(from_addr: H160, account_nonce: u64) -> H160 {
    let mut hasher = Sha256::new();
    hasher.update(from_addr.as_bytes());
    hasher.update((account_nonce - 1).to_be_bytes());
    let hashed = hasher.finalize();

    H160::from_slice(&hashed[(hashed.len() - 20)..])
}

/// Entry point for calling the scilla server. The backend is passed in so that the state can be queried
/// and the function will return the state changes as an EvmResult.
/// Note that the function will block the thread while it waits for the scilla server to respond.
/// The execution in this scilla library is only related to contract creation and contract calls.
/// Transfers are handled by the EVM.
pub fn run_scilla_impl_direct<B: Backend>(
    args: EvmProto::EvmCallArgs,
    backend: &B,
) -> EvmProto::EvmResult {
    let block_num = backend.block_number();
    let from_addr = backend.origin();

    debug!(
        "**** run_scilla_impl_direct called with args: {:?} from: {:?}, block_num: {:?}",
        args, from_addr, block_num
    );

    let backend_collector = BackendCollector::new(backend);
    let mut tcp_scilla_server =
        ScillaServer::new(backend_collector, args.caller, args.address, H256::zero());

    let is_contract_creation = tcp_scilla_server
        .inner
        .backend
        .get_code(args.address)
        .is_empty();

    let code = str::from_utf8(&args.code)
        .expect("unable to convert scilla code to a string")
        .to_string();

    let has_data = !args.data.is_empty();

    // Note: contract creation needs init data
    let return_value = if is_contract_creation && has_data {
        handle_contract_creation(&mut tcp_scilla_server, &code, args.data, args.gas_limit, args.apparent_value)
    } else if !is_contract_creation && has_data {
        handle_contract_call(&mut tcp_scilla_server, &code, args.data, args.gas_limit, args.apparent_value)
    } else {
        // todo: contract call without data - is this a valid case?
        panic!("Scilla invokation not a contract creation or call. This is invalid.");
    };

    let mut state_deltas = tcp_scilla_server.inner.backend.get_result();

    state_deltas.exit_reason = ExitReasonCps::Succeed(ExitSucceed::Stopped);
    state_deltas.return_value = return_value;
    state_deltas.tx_trace = args.tx_trace.clone();
    state_deltas
        .tx_trace
        .lock()
        .unwrap()
        .scilla_events
        .extend(tcp_scilla_server.inner.backend.events);

    debug!("Scilla state deltas: {:?}", state_deltas);

    state_deltas
}

pub fn check_contract<B: evm::backend::Backend>(
    _contract: &[u8],
    gas_limit: u64,
    _init: &Value,
    tcp_scilla_server: &mut ScillaServer<B>,
) -> Result<CheckOutput> {
    let args = vec![
        "-init".to_owned(),
        SCILLA_SERVER_INIT_PATH.to_string(), // ending init.json
        "-libdir".to_owned(),
        SCILLA_SERVER_LIB_PATH.to_string(),
        SCILLA_SERVER_INPUT_PATH.to_string(), // ending input.scilla
        "-gaslimit".to_owned(),
        gas_limit.to_string(),
        "-contractinfo".to_owned(),
        "-jsonerrors".to_owned(),
    ];
    let args = serde_json::to_value(args)?;
    let params: Value = [("argv".to_owned(), args)].into_iter().collect();
    let params: Params = from_value(params).unwrap();

    let response = call_scilla_server("check", params, tcp_scilla_server)?;

    let response: CheckOutput = serde_json::from_value(response.result.unwrap().clone()).unwrap();

    Ok(response)
}

pub fn invoke_contract<B: evm::backend::Backend>(
    gas_limit: u64,
    balance: U256, // todo: this
    tcp_scilla_server: &mut ScillaServer<B>,
) -> Result<InvokeOutput> {
    let args = vec![
        "-init".to_owned(),
        SCILLA_SERVER_INIT_PATH.to_string(),
        "-ipcaddress".to_owned(),
        SCILLA_SERVER_SOCK_PATH.to_owned(),
        "-imessage".to_owned(),
        SCILLA_SERVER_MESSAGE_PATH.to_string(),
        "-i".to_owned(),
        SCILLA_SERVER_INPUT_PATH.to_string(),
        "-gaslimit".to_owned(),
        gas_limit.to_string(),
        "-balance".to_owned(),
        balance.to_string(),
        "-libdir".to_owned(),
        SCILLA_SERVER_LIB_PATH.to_string(),
        "-jsonerrors".to_owned(),
        "-pplit".to_owned(),
        "true".to_owned(),
    ];

    let args = serde_json::to_value(args)?;
    let params: Value = [("argv".to_owned(), args)].into_iter().collect();
    let params: Params = from_value(params).unwrap();

    let response = call_scilla_server("run", params, tcp_scilla_server)?;

    let response: InvokeOutput = serde_json::from_value(response.result.unwrap().clone()).unwrap();

    Ok(response)
}
pub fn create_contract<B: evm::backend::Backend>(
    gas_limit: u64,
    balance: U256, // todo: this
    tcp_scilla_server: &mut ScillaServer<B>,
) -> Result<InvokeOutput> {
    let args = vec![
        "-i".to_owned(),
        SCILLA_SERVER_INPUT_PATH.to_string(),
        "-init".to_owned(),
        SCILLA_SERVER_INIT_PATH.to_string(), // ending init.json
        "-ipcaddress".to_owned(),
        SCILLA_SERVER_SOCK_PATH.to_owned(),
        "-gaslimit".to_owned(),
        gas_limit.to_string(),
        "-balance".to_owned(),
        balance.to_string(), // todo: this
        "-libdir".to_owned(),
        SCILLA_SERVER_LIB_PATH.to_string(),
        "-jsonerrors".to_owned(),
    ];

    let args = serde_json::to_value(args)?;
    let params: Value = [("argv".to_owned(), args)].into_iter().collect();
    let params: Params = from_value(params).unwrap();

    let response = call_scilla_server("run", params, tcp_scilla_server)?;

    debug!("Create Response before parsing: {:?}", response);

    let response: InvokeOutput = serde_json::from_value(response.result.unwrap()).unwrap();

    // todo: check this is ok?
    debug!("Create Response: {:?}", response);

    Ok(response)
}

fn handle_contract_creation<B: Backend>(tcp_scilla_server: &mut ScillaServer<B>, code: &str, init_data: Vec<u8>, gas_limit: u64, balance: U256) -> Vec<u8> {
    debug!("contract creation!");

    let contract_address = tcp_scilla_server.inner.contract_addr;
    let block_num = tcp_scilla_server.inner.backend.get_block_number();

    let mut init_data: Value = serde_json::from_slice(init_data.as_slice()).unwrap();
    init_data.as_array_mut().unwrap().push(
        json!({"vname": "_creation_block", "type": "BNum", "value": block_num.to_string()}),
    );
    let contract_address_hex = format!("{contract_address:?}");
    init_data.as_array_mut().unwrap().push(
        json!({"vname": "_this_address", "type": "ByStr20", "value": contract_address_hex}),
    );

    // Save the init data to the contract storage for future reference
    tcp_scilla_server
        .inner
        .backend
        .update_account_storage_scilla(
            contract_address,
            "init_data",
            init_data.to_string().as_bytes(),
        );

    // Write down to the files the init data and make sure the libs are in order
    ensure_setup_correct(Some(init_data.clone()), Some(code.clone().into()), None);

    // Create account with the contract as the code
    tcp_scilla_server.inner.backend.create_account(
        contract_address,
        code.as_bytes().to_vec(),
        true,
    );

    let check_output = check_contract(
        code.as_bytes(),
        gas_limit,
        &init_data,
        tcp_scilla_server,
    ).unwrap();

    debug!("Check output response: {:?}", check_output);

    let addr_no_prefix = format!("{contract_address:x}");

    for field in check_output.contract_info.fields {
        let depth_key = format!("{}\x16_depth\x16{}\x16", addr_no_prefix, field.name);

        tcp_scilla_server
            .inner
            .backend
            .update_account_storage_scilla(
                contract_address,
                &depth_key,
                field.depth.to_string().as_bytes(),
            );
        let type_key = format!("{}\x16_type\x16{}\x16", addr_no_prefix, field.name);
        tcp_scilla_server
            .inner
            .backend
            .update_account_storage_scilla(
                contract_address,
                &type_key,
                field.ty.as_bytes(),
            );

        debug!("check output field: {:?} {:?} {:?}", field, depth_key, type_key);
    }

    let version_key = format!("{addr_no_prefix}\x16_version\x16");
    tcp_scilla_server
        .inner
        .backend
        .update_account_storage_scilla(
            contract_address,
            &version_key,
            check_output.contract_info.scilla_major_version.as_bytes(),
        );
    let addr_key = format!("{addr_no_prefix}\x16_addr\x16");
    tcp_scilla_server
        .inner
        .backend
        .update_account_storage_scilla(
            contract_address,
            &addr_key,
            contract_address.as_bytes(),
        );

    create_contract(
        gas_limit,
        balance,
        tcp_scilla_server,
    ).unwrap();

    // todo: think about return values and how neccessary they are for scilla.
    code.to_string().into_bytes()
}

fn handle_contract_call<B: Backend>(tcp_scilla_server: &mut ScillaServer<B>, code: &str, data: Vec<u8>, gas_limit: u64, balance: U256) -> Vec<u8> {
    trace!("contract call!");

    let from_addr = tcp_scilla_server.inner.caller;
    let contract_addr = tcp_scilla_server.inner.contract_addr;

    let msg = serde_json::from_slice::<Value>(&data)
        .expect("unable to convert scilla data to a Value during contract call");

    trace!("msg before population: {:?}", msg);

    let mut msg = msg.clone();
    msg.as_object_mut()
        .unwrap()
        .insert("_sender".to_owned(), format!("{from_addr:#x}").into());
    msg.as_object_mut()
        .unwrap()
        .insert("_origin".to_owned(), format!("{from_addr:#x}").into());
    msg.as_object_mut()
        .unwrap()
        .insert("_amount".to_owned(), balance.to_string().into());

    trace!("msg after population: {:?}", msg);

    let origin_addr_hex = format!("{from_addr:#x}");
    trace!("origin addr: {:?}", origin_addr_hex);

    // todo: do we use balance, amount, or value as nomenclature?
    // This is a loop in which contract to contract calls are handled by pushing the next
    // call onto the stack.
    let mut messages = vec![(true, from_addr, contract_addr, msg, balance)];
    while let Some((
                       recipient_is_contract,
                       from_addr,
                       to_addr,
                       message,
                       _amount, // unused...
                   )) = messages.pop()
    {
        trace!("Updating scilla backend context to from_addr {:?} and to_addr {:?}", from_addr, to_addr);
        tcp_scilla_server.inner.caller = from_addr;
        tcp_scilla_server.inner.contract_addr = to_addr;

        // Todo: get this in a cleaner way...
        let code = tcp_scilla_server.inner.backend.get_code(to_addr);
        let init_data = tcp_scilla_server
            .inner
            .backend
            .get_account_storage_scilla(to_addr, "init_data");

        if code.is_empty() {
            warn!("Skipping non-existent contract");
            continue;
        }

        if init_data.is_empty() {
            warn!("Skipping non-existent init data!");
            continue;
        }

        let init_data = serde_json::from_slice::<Value>(&init_data)
            .expect("unable to convert scilla data to a Value during contract call");

        debug!("{from_addr:?} invokes {} on {to_addr:?}", message["_tag"]);

        if !recipient_is_contract {
            warn!("Need to implement transfer!");
            continue;
        }

        // Make sure the setup is correct for files to be read
        ensure_setup_correct(Some(init_data.clone()), Some(code.clone()), Some(message));

        // TODO: Differentiate between exceptions from contract and errors from Scilla itself.
        let result = invoke_contract(
            gas_limit,
            balance,
            tcp_scilla_server,
        );

        match result {
            Ok(invoked) => {
                debug!("invoke contract invoke: {:?}", invoked);

                // The events are collected by the backend and then added to the tx_trace
                for event in invoked.events {
                    tcp_scilla_server.inner.backend.add_event(event);
                }

                if invoked.accepted {
                    //transfer(&mut db.lock().unwrap(), from_addr, to_addr, amount)?;
                    todo!("Need to handle contract to contract transfer!");
                }

                for message in invoked.messages.unwrap() {
                    let recipient_addr = message.recipient;

                    // Check the recipient is a contract
                    let recipient_contract = tcp_scilla_server
                        .inner
                        .backend
                        .get_code(recipient_addr);
                    let addr_hex = format!("{to_addr:#x}");

                    let input_message = json!({
                            "_sender": addr_hex,
                            "_origin": origin_addr_hex,
                            "_amount": message.amount,
                            "_tag": message.tag,
                            "params": message.params,
                        });

                    trace!("Pushing on input message/call: {:?}", input_message);

                    messages.push((
                        !recipient_contract.is_empty(),
                        to_addr, // Note, the 'from' became the 'to'
                        recipient_addr,
                        input_message,
                        message.amount.parse().unwrap(),
                    ));
                }
            }
            Err(err) => {
                warn!("scilla invoke contract error: {:?}", err);
            }
        }
    }

    // return value is empty
    vec![]
}

pub fn reconstruct_kv_pairs<B: Backend>(backend: &B, address: H160) -> Vec<(String, Vec<u8>)> {
    let mut collector = BackendCollector::new(backend);
    collector.reconstruct_kv_pairs(address)
}
