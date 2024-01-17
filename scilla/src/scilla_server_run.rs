use std::{fs::File, io::{Write}, mem, path::{Path, PathBuf}, str};

use anyhow::{Result};
use evm::ExitSucceed;
use evm_ds::{
    evm::backend::{Backend},
    protos::{
        evm_proto as EvmProto,
        evm_proto::{ExitReasonCps},
    },
};

use jsonrpc_core::{
    Params,
};
use primitive_types::{H160, H256, U256};

use serde_json::{from_value, json, Value};
use sha2::{Digest, Sha256};
use tracing::{*};

use crate::{
    backend_collector::BackendCollector,
    call_scilla_server::{call_scilla_server, CheckOutput, ensure_setup_correct},
    scilla_tcp_server::ScillaServer,
};
use crate::call_scilla_server::JsonRpcResponse;

/// The scheme to calculate scilla contract addresses is different from the EVM.
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
pub fn run_scilla_impl_direct<B: Backend + std::marker::Sync>(
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
    let mut tcp_scilla_server = ScillaServer::new(backend_collector, args.address, H256::zero(), block_num);

    // These are the directories inside the docker container which scilla will look for
    let lib_directory_str = "/scilla/0/src/stdlib/";
    let init_directory_str = "/tmp/scilla_init/init.json";
    let input_directory_str = "/tmp/scilla_input/input.scilla";
    let message_directory_str = "/tmp/scilla_input/message.scilla";

    let is_contract_creation = tcp_scilla_server
        .inner
        .backend
        .get_code(args.address)
        .is_empty();
    let code = str::from_utf8(&args.code)
        .expect("unable to convert scilla code to a string")
        .to_string();
    let init_data = args.data;
    let mut return_value = vec![];
    let has_data = !init_data.is_empty();

    match (is_contract_creation, has_data) {
        // Transfer
        (false, false) => {
            debug!("Execute transfer. nothing to do.");
        }
        // Contract creation
        (true, true) => {
            debug!("contract creation!");

            let _account_nonce: u64 = 1; // todo: this
            let contract_address = args.address;

            let mut init_data: Value = serde_json::from_slice(init_data.as_slice()).unwrap();
            init_data.as_array_mut().unwrap().push(
                json!({"vname": "_creation_block", "type": "BNum", "value": block_num.to_string()}),
            );
            let contract_address_hex = format!("{contract_address:?}");
            init_data.as_array_mut().unwrap().push(
                json!({"vname": "_this_address", "type": "ByStr20", "value": contract_address_hex}),
            );

            // Save the init data to the contract
            tcp_scilla_server
                .inner
                .backend
                .update_account_storage_scilla(
                    contract_address,
                    "init_data",
                    init_data.to_string().as_bytes(),
                );

            // Write down to the files the init data and make sure the libs are in order
            ensure_setup_correct(
                Some(init_data.clone()),
                Some(code.clone().into()),
                None,
            );

            // Create account here
            tcp_scilla_server.inner.backend.create_account(
                contract_address,
                code.as_bytes().to_vec(),
                true,
            );

            let check_output = check_contract(
                code.as_bytes(),
                args.gas_limit,
                &init_data,
                init_directory_str,
                lib_directory_str,
                input_directory_str,
                &mut tcp_scilla_server,
            )
            .unwrap();

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

                debug!(
                    "check output field: {:?} {:?} {:?}",
                    field, depth_key, type_key
                );
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
                code.as_bytes(),
                args.gas_limit,
                args.apparent_value,
                &init_data,
                init_directory_str,
                lib_directory_str,
                input_directory_str,
                &mut tcp_scilla_server,
            )
            .unwrap();

            return_value = code.into_bytes();
        }

        // Contract call
        (false, true) => {
            debug!("contract call! Lets gooooo");

            //let mut msg = serde_json::from_str::<Value>(args.data)?;
            let msg = serde_json::from_slice::<Value>(&init_data)
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
                .insert("_amount".to_owned(), args.apparent_value.to_string().into());

            let origin_addr_hex = format!("{from_addr:#x}");
            trace!("origin addr: {:?}", origin_addr_hex);

            let mut messages = vec![(true, args.caller, args.address, msg, args.apparent_value)];
            while let Some((
                recipient_is_contract,
                from_addr,
                to_addr,
                message,
                _amount, // unused...
            )) = messages.pop()
            {
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
                ensure_setup_correct(
                    Some(init_data.clone()),
                    Some(code.clone()),
                    Some(message),
                );

                // TODO: Differentiate between exceptions from contract and errors from Scilla itself.
                let result = invoke_contract(
                    &code,
                    args.gas_limit,
                    args.apparent_value,
                    &init_data,
                    init_directory_str,
                    lib_directory_str,
                    input_directory_str,
                    message_directory_str,
                    &mut tcp_scilla_server,
                );

                match result {
                    Ok(result) => {
                        let result = result.result.unwrap();
                        debug!("invoke contract resultX: {:?}", result);

                        let is_accepted = result.get("_accepted").cloned().unwrap_or(json!(false));
                        let events = result.get("events").cloned().unwrap_or(json!([]));
                        let gas_remaining = result.get("gas_remaining").cloned().unwrap_or(json!(["0"]));
                        let messages = result.get("messages").cloned().unwrap_or(json!([[]]));
                        let scilla_major_version = result.get("scilla_major_version").cloned().unwrap_or(json!("0"));
                        let states = result.get("states").cloned().unwrap_or(json!([]));

                        trace!("is_accepted: {:?}", is_accepted);
                        trace!("events: {:?}", events);
                        trace!("gas_remaining: {:?}", gas_remaining);
                        trace!("messages: {:?}", messages);
                        trace!("scilla_major_version: {:?}", scilla_major_version);
                        trace!("states: {:?}", states);

                        for event in events.as_array().unwrap().clone() {
                            tcp_scilla_server.inner.backend.add_event(event);
                        }
                    },
                    Err(err) => {
                        warn!("invoke contract error: {:?}", err);
                    },
                }

                /*
                if output.accepted {
                    transfer(&mut db.lock().unwrap(), from_addr, to_addr, amount)?;
                }

                for message in output.messages {
                    let recipient_addr = message.recipient;
                    let recipient = db
                        .lock()
                        .unwrap()
                        .get_account(recipient_addr)?
                        .map(Account::from_proto)
                        .transpose()?
                        .unwrap_or_default();
                    let addr_hex = format!("{to_addr:#x}");
                    let input_message = json!({
                                    "_sender": addr_hex,
                                    "_origin": origin_addr_hex,
                                    "_amount": message.amount,
                                    "_tag": message.tag,
                                    "params": message.params,
                                });
                    messages.push((
                        recipient.contract.is_some(),
                        to_addr,
                        recipient_addr,
                        input_message,
                        message.amount.parse()?,
                    ));
                }
                 */
            }
        }
        (true, false) => {
            warn!("contract creation without init data!");
            //return Err(anyhow!("contract creation without init data"));
        }
    }

    let mut state_deltas = tcp_scilla_server.inner.backend.get_result();

    state_deltas.exit_reason = ExitReasonCps::Succeed(ExitSucceed::Stopped);
    state_deltas.return_value = return_value;
    state_deltas.tx_trace = args.tx_trace.clone();
    state_deltas.tx_trace.lock().unwrap().scilla_events.extend(tcp_scilla_server.inner.backend.events);

    debug!("Scilla state deltas: {:?}", state_deltas);

    state_deltas
}

pub fn check_contract<B: evm::backend::Backend>(
    _contract: &[u8],
    gas_limit: u64,
    _init: &Value,
    init_path: &str,
    lib_path: &str,
    input_path: &str,
    tcp_scilla_server: &mut ScillaServer<B>,
) -> Result<CheckOutput> {
    let args = vec![
        "-init".to_owned(),
        init_path.to_string(), // ending init.json
        "-libdir".to_owned(),
        lib_path.to_string(),
        input_path.to_string(), // ending input.scilla
        "-gaslimit".to_owned(),
        gas_limit.to_string(),
        "-contractinfo".to_owned(),
        "-jsonerrors".to_owned(),
    ];
    let args = serde_json::to_value(args)?;
    let params: Value = [("argv".to_owned(), args)].into_iter().collect();
    let params: Params = from_value(params).unwrap();

    let response = call_scilla_server("check", params, tcp_scilla_server)?;

    let response: CheckOutput =
        serde_json::from_value(response.result.unwrap().clone()).unwrap();

    Ok(response)
}

pub fn invoke_contract<B: evm::backend::Backend>(
    _contract: &[u8],
    gas_limit: u64,
    balance: U256, // todo: this
    _init: &Value,
    init_path: &str, // Note: same as message path
    lib_path: &str,
    input_path: &str,
    message_path: &str,
    tcp_scilla_server: &mut ScillaServer<B>,
) -> Result<JsonRpcResponse> {
    let args = vec![
        "-init".to_owned(),
        init_path.to_string(),
        "-ipcaddress".to_owned(),
        "/tmp/scilla-server.sock".to_owned(), // todo: this.
        "-imessage".to_owned(),
        message_path.to_string(),
        "-i".to_owned(),
        input_path.to_string(),
        "-gaslimit".to_owned(),
        gas_limit.to_string(),
        "-balance".to_owned(),
        balance.to_string(),
        "-libdir".to_owned(),
        lib_path.to_string(),
        "-jsonerrors".to_owned(),
        "-pplit".to_owned(),
        "true".to_owned(),
    ];

    let args = serde_json::to_value(args)?;
    let params: Value = [("argv".to_owned(), args)].into_iter().collect();
    let params: Params = from_value(params).unwrap();

    let response = call_scilla_server("run", params, tcp_scilla_server)?;

    Ok(response)
}
pub fn create_contract<B: evm::backend::Backend>(
    _contract: &[u8],
    gas_limit: u64,
    balance: U256, // todo: this
    _init: &Value,
    init_path: &str,
    lib_path: &str,
    input_path: &str,
    tcp_scilla_server: &mut ScillaServer<B>,
) -> Result<()> {
    let args = vec![
        "-i".to_owned(),
        input_path.to_string(),
        "-init".to_owned(),
        init_path.to_string(), // ending init.json
        "-ipcaddress".to_owned(),
        "/tmp/scilla-server.sock".to_owned(), // todo: this.
        "-gaslimit".to_owned(),
        gas_limit.to_string(),
        "-balance".to_owned(),
        balance.to_string(), // todo: this
        "-libdir".to_owned(),
        lib_path.to_string(),
        "-jsonerrors".to_owned(),
    ];

    let args = serde_json::to_value(args)?;
    let params: Value = [("argv".to_owned(), args)].into_iter().collect();
    let params: Params = from_value(params).unwrap();

    let response = call_scilla_server("run", params, tcp_scilla_server)?;

    debug!("Create Response: {:?}", response);

    Ok(())
}

pub fn reconstruct_kv_pairs<B: Backend> (
    backend: &B,
    address: H160,
) -> Vec<(String, Vec<u8>)> {
    let mut collector = BackendCollector::new(backend);
    collector.reconstruct_kv_pairs(address)
}
