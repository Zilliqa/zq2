use tracing::*;
use crate::backend_collector::BackendCollector;
use crate::call_scilla_server::call_scilla_server;
use crate::call_scilla_server::JsonRpcResponse;
use evm::{
    ExitSucceed,};
    //backend::{Apply, Backend}};

use evm_ds::{
    evm::backend::{Backend, Basic},
    protos::evm_proto::{Apply, EvmResult, Storage},
};
use crate::call_scilla_server::CheckOutput;

use std::collections::HashMap;
use crate::scilla_tcp_server::ScillaServer;
use futures::{future, FutureExt};
use std::io::Read;
use jsonrpc_core::IoHandler;
use jsonrpc_client_transports::{transports::duplex, RawClient, RpcChannel, RpcError};
use jsonrpc_core::{
    futures,
    futures_util::{SinkExt, StreamExt},
    Params,
};
use primitive_types::{H256, H160, U256};
use sha2::{Digest, Sha256};
use std::str;
use std::io::Write;
use tokio::io::AsyncWriteExt;
use tokio::io::AsyncReadExt;

use std::path::Path;
use evm_ds::protos::evm_proto as EvmProto;
use evm_ds::protos::evm_proto::{ExitReasonCps };
use anyhow::{anyhow, Result};
use serde_json::{json, Value, from_value};
use std::path::PathBuf;
use std::fs::File;
use std::net::TcpStream;

use std::sync::{Arc, Mutex};
use evm_ds::tracing_logging::LoggingEventListener;
use serde_json::from_str;
use serde::{Serialize, Deserialize};

use tokio::io::sink;
//use tokio::net::TcpStream;
use std::process;
use tokio::sync::oneshot;
use tokio::select;

use tokio::time::{sleep, Duration};
use tokio::runtime::{Runtime, Handle};
use tracing::field::debug;

pub fn calculate_contract_address_scilla(from_addr: H160, account_nonce: u64) -> H160 {
    debug!("calculate_contract_address_scilla called");
    let mut hasher = Sha256::new();
    hasher.update(from_addr.as_bytes());
    hasher.update((account_nonce - 1).to_be_bytes());
    let hashed = hasher.finalize();
    let contract_address = H160::from_slice(&hashed[(hashed.len() - 20)..]);
    contract_address
}

pub fn run_scilla_impl_direct<B: Backend + std::marker::Sync>(
    args: EvmProto::EvmCallArgs,
    backend: &B,
) -> EvmProto::EvmResult {

    let block_num = backend.block_number();
    let from_addr = backend.origin();

    debug!("**** run_scilla_impl_direct called with args: {:?} from: {:?}, block_num: {:?}", args, from_addr, block_num);

    let mut backend_collector = BackendCollector::new(backend);
    let mut tcp_scilla_server = ScillaServer::new(backend_collector);

    // These are the directories inside the docker container which scilla will look for
    let lib_directory_str = "/scilla/0/src/stdlib/";
    let init_directory_str = "/tmp/scilla_init/init.json";
    let input_directory_str = "/tmp/scilla_input/input.scilla";
    let message_directory_str = "/tmp/scilla_input/message.scilla";

    // These are the directories on the local machine which we will write to
    let init_directory = PathBuf::from("/Users/nhutton/repos/zq2/scilla_init/");
    let input_directory = PathBuf::from("/Users/nhutton/repos/zq2/scilla_input/");

    //let account = tcp_scilla_server.inner.backend.get_account(args.address);
    let is_contract_creation = tcp_scilla_server.inner.backend.get_code(args.address).is_empty();
    let code = str::from_utf8(&args.code).expect("unable to convert scilla code to a string").to_string();
    let init_data = args.data;
    let mut return_value = vec![];
    let has_data = !init_data.is_empty();

    match (is_contract_creation, has_data) {
        // Transfer
        (false, false) => {
            debug!("Execute transfer. nothing to do.");
            //Ok(())
            //let mut from = db
            //.lock()
            //.unwrap()
            //.get_account(from_addr)?
            //.map(Account::from_proto)
            //.transpose()?
            //.unwrap_or_default();
            //from.nonce = txn.nonce;
            //from.balance -= txn.cumulative_gas as u128 * txn.gas_price;
            //db.lock()
            //.unwrap()
            //.save_account(from_addr, from.to_proto()?)?;
//
            //transfer(&mut db.lock().unwrap(), from_addr, txn.to_addr, txn.amount)?;
        }
        // Contract creation
        (true, true) => {
            debug!("contract creation!");
            let account_nonce: u64 = 1; // todo: this

            // todo: make this a free function for contract creation calculation
            /*
            let mut hasher = Sha256::new();
            hasher.update(from_addr.as_bytes());
            hasher.update((account_nonce - 1).to_be_bytes());
            let hashed = hasher.finalize();
            let contract_address = H160::from_slice(&hashed[(hashed.len() - 20)..]); */

            let contract_address = args.address;

            let mut init_data: Value = serde_json::from_slice(init_data.as_slice()).unwrap();
            init_data.as_array_mut().unwrap().push(json!({"vname": "_creation_block", "type": "BNum", "value": block_num.to_string()}));
            let contract_address_hex = format!("{contract_address:?}");
            init_data.as_array_mut().unwrap().push(json!({"vname": "_this_address", "type": "ByStr20", "value": contract_address_hex}));

            debug!("Creating contract: {contract_address:?}");
            debug!("xx Init data is: {:?}", init_data);

            // Save the init data to the contract
            tcp_scilla_server.inner.backend.update_account_storage_scilla(contract_address, "init_data", init_data.to_string().as_bytes());

            let testme = tcp_scilla_server.inner.backend.get_account_storage_scilla(contract_address, "init_data");

            debug!("Serialized init data is: {:?}", init_data.to_string());

            let testme = serde_json::from_slice::<Value>(&testme).expect("unable to convert scilla data to a Value during contract call");
            debug!("Deserialized init data is: {:?}", testme);
            debug!("pause");

            // Write down to the files the init data and make sure the libs are in order
            // todo: make sure the old files are cleared
            ensure_setup_correct(Some(init_data.clone()), &init_directory, Some(code.clone().into()), &input_directory, None);

            // todo: write to backend the contract addr, code, init state

            // Create account here
            tcp_scilla_server.inner.backend.create_account(contract_address, code.as_bytes().to_vec(), true);
            // No init state 2 here

            //db.lock()
            //    .unwrap()
            //    .put_contract_code(contract_address, code.as_bytes())?;
            //db.lock()
            //    .unwrap()
            //    .put_init_state_2(contract_address, &serde_json::to_vec(&init_data)?)?;

            //let mut state_root = H256::from_slice(&Keccak256::digest(rlp::NULL_RLP));

            let check_output =
                check_contract(code.as_bytes(), args.gas_limit, &init_data, init_directory_str, lib_directory_str, input_directory_str, & mut tcp_scilla_server
                ).unwrap();

            debug!("Check output response: {:?}", check_output);

            let addr_no_prefix = format!("{contract_address:x}");

            for field in check_output.contract_info.fields {
                let depth_key =
                    format!("{}\x16_depth\x16{}\x16", addr_no_prefix, field.name);

                tcp_scilla_server.inner.backend.update_account_storage_scilla(contract_address, &depth_key, field.depth.to_string().as_bytes());
               // state_root = db.lock().unwrap().put_contract_state(
               //     state_root,
               //     &depth_key,
               //     field.depth.to_string().as_bytes(),
               // )?;
                let type_key =
                    format!("{}\x16_type\x16{}\x16", addr_no_prefix, field.name);
                tcp_scilla_server.inner.backend.update_account_storage_scilla(contract_address, &type_key, field.ty.as_bytes());
                //state_root = db.lock().unwrap().put_contract_state(
                //    state_root,
                //    &type_key,
                //    field.ty.as_bytes(),
                //)?;

                debug!("check output field: {:?} {:?} {:?}", field, depth_key, type_key);
            }

            let version_key = format!("{addr_no_prefix}\x16_version\x16");
            tcp_scilla_server.inner.backend.update_account_storage_scilla(contract_address, &version_key, check_output.contract_info.scilla_major_version.as_bytes());
            //state_root = db.lock().unwrap().put_contract_state(
            //    state_root,
            //    &version_key,
            //    check_output.contract_info.scilla_major_version.as_bytes(),
            //)?;
            let addr_key = format!("{addr_no_prefix}\x16_addr\x16");
            tcp_scilla_server.inner.backend.update_account_storage_scilla(contract_address, &addr_key, contract_address.as_bytes());
            //state_root = db.lock().unwrap().put_contract_state(
            //    state_root,
            //    &addr_key,
            //    contract_address.as_bytes(),
            //)?;

            //ipc_server.set_current_contract_addr(
            //    contract_address,
            //    state_root,
            //    block_num,
            //);


            create_contract(
                code.as_bytes(),
                args.gas_limit,
                args.apparent_value,
                &init_data,
                init_directory_str, lib_directory_str, input_directory_str, &mut tcp_scilla_server

            ).unwrap();


            /* let state_root = ipc_server.reset_current_contract_addr(); */


            //let contract_account = Account {
            //    version: 1,
            //    balance: 0,
            //    nonce: 0,
            //    contract: Some(Contract {
            //        code_hash: code_hash(code, &init_data)?,
            //        state_root,
            //    }),
            //};

            /*
            db.lock()
                .unwrap()
                .save_account(contract_address, contract_account.to_proto()?)?;

            let creator_account = db
                .lock()
                .unwrap()
                .get_account(from_addr)?
                .ok_or_else(|| anyhow!("account does not exist: {from_addr:?}"))?;

            let mut creator_account = Account::from_proto(creator_account)?;
            creator_account.nonce += 1;
            creator_account.balance -= args.cumulative_gas as u128 * args.gas_price;
            db.lock()
                .unwrap()
                .save_account(from_addr, creator_account.to_proto()?)?;
            */
            //Ok(())

            return_value = code.into_bytes();
        }

        // Contract call
        (false, true) => {
            debug!("contract call! Lets gooooo");

            //let caller_account = db
            //    .lock()
            //    .unwrap()
            //    .get_account(from_addr)?
            //    .ok_or_else(|| anyhow!("account does not exist: {from_addr:?}"))?;

            //let mut caller_account = Account::from_proto(caller_account)?;
            //caller_account.nonce += 1;
            //caller_account.balance -= txn.cumulative_gas as u128 * txn.gas_price;
            //db.lock()
            //    .unwrap()
            //    .save_account(from_addr, caller_account.to_proto()?)?;

            //let addr = txn.to_addr;

            //let success = serde_json::from_str::<Value>(&txn.receipt)?
            //    .as_object()
            //    .and_then(|obj| obj.get("success"))
            //    .and_then(|b| b.as_bool())
            //    .expect("TODO");
            //if !success {
            //    debug!("Skipping failed transaction");
            //    continue;
            //}

            //let mut msg = serde_json::from_str::<Value>(args.data)?;
            let mut msg = serde_json::from_slice::<Value>(&init_data).expect("unable to convert scilla data to a Value during contract call");

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

            //let origin_addr_hex = format!("{from_addr:#x}");
            let origin_addr_hex = format!("{from_addr:#x}");
            trace!("origin addr: {:?}", origin_addr_hex);

            let mut messages = vec![(true, args.caller, args.address, msg, args.apparent_value)];
            while let Some((
                               recipient_is_contract,
                               from_addr,
                               to_addr,
                               message,
                               amount, // unused...
                           )) = messages.pop()
            {
                // Todo: get this in a cleaner way...
                let code = tcp_scilla_server.inner.backend.get_code(to_addr);
                let init_data = tcp_scilla_server.inner.backend.get_account_storage_scilla(to_addr, "init_data");

                if code.is_empty() {
                    warn!("Skipping non-existent contract");
                    continue;
                }

                if init_data.is_empty() {
                    warn!("Skipping non-existent init data!");
                    continue;
                }

                let init_data = serde_json::from_slice::<Value>(&init_data).expect("unable to convert scilla data to a Value during contract call");

                debug!("{from_addr:?} invokes {} on {to_addr:?}", message["_tag"]);

                if !recipient_is_contract {
                    warn!("Need to implement transfer!");
                    continue;
                }

                // Make sure the setup is correct for files to be read
                ensure_setup_correct(Some(init_data.clone()), &init_directory, Some(code.clone()), &input_directory, Some(message));

                // TODO: Differentiate between exceptions from contract and errors from Scilla itself.
                invoke_contract(
                    &code,
                    args.gas_limit,
                    args.apparent_value,
                    &init_data,
                    init_directory_str,
                    lib_directory_str,
                    input_directory_str,
                    message_directory_str,
                    &mut tcp_scilla_server,
                    //message,
//                    &db,
//                    &ipc_server,
//                    &scilla,
//                    txn.gas_limit,
//                    block_num,
//                    to_addr,
//                    &message,
                );

                debug!("invoke contract done");

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
            //Ok(())
            //return Err(anyhow!("contract creation without init data"));
        }
    }

    //db.lock()
    //.unwrap()
    //.put_tx_body(txn.block, txn.id, txn.to_proto()?)?;
    //db.lock().unwrap().put_tx_epoch(
    //txn.id,
    //ProtoTxEpoch {
    //epochnum: txn.block,
    //},
    //)?;

    let mut state_deltas = tcp_scilla_server.inner.backend.get_result();

    state_deltas.exit_reason = ExitReasonCps::Succeed(ExitSucceed::Stopped);
    state_deltas.return_value = return_value;

    debug!("State deltas: {:?}", state_deltas);

    state_deltas
}

pub fn check_contract<B: evm::backend::Backend>(
    contract: &[u8],
    gas_limit: u64,
    init: &Value,
    init_path: &str,
    lib_path: &str,
    input_path: &str,
    tcp_scilla_server: &mut ScillaServer<B>,
) -> Result<CheckOutput> {
    //let dir = TempDir::new()?;
    //let (contract_path, init_path) = self.create_common_inputs(&dir, contract, init)?;

    let args = vec![
        "-init".to_owned(),
        //"/tmp/scilla_init/init.json".to_owned(), // ending init.json
        init_path.to_string(), // ending init.json
        "-libdir".to_owned(),
        //"/scilla/0/src/stdlib/".to_owned(),
        lib_path.to_string(),
        //"/tmp/scilla_input/input.scilla".to_owned(), // ending input.scilla
        input_path.to_string(), // ending input.scilla
        "-gaslimit".to_owned(),
        gas_limit.to_string(),
        "-contractinfo".to_owned(),
        "-jsonerrors".to_owned(),
    ];
    let args = serde_json::to_value(args)?;
    let params: Value = [("argv".to_owned(), args)].into_iter().collect();
    let params: Params = from_value(params).unwrap();

    let mut response = call_scilla_server("check", params, tcp_scilla_server)?;

    let response = response.replace("\"{", "{")
        .replace("}\"", "}");

    let mut deser: Result<JsonRpcResponse, serde_json::Error> = from_str(&response);
    debug!("Deser: {:?}", deser);

    let response: CheckOutput = serde_json::from_value(deser.unwrap().result.unwrap().clone()).unwrap();

    Ok(response)
}

pub fn invoke_contract<B: evm::backend::Backend> (
    contract: &[u8],
    gas_limit: u64,
    balance: U256, // todo: this
    init: &Value,
    init_path: &str, // Note: same as message path
    lib_path: &str,
    input_path: &str,
    message_path: &str,
    tcp_scilla_server: & mut ScillaServer<B>,
    //message: Value,
) -> Result<()> {
    //let dir = TempDir::new()?;

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

    let mut response = call_scilla_server("run", params, tcp_scilla_server)?;

    let response = response.replace("\"{", "{")
        .replace("}\"", "}");

    debug!("invoke contract response: {:?}", response);

    Ok(())
}
pub fn create_contract<B: evm::backend::Backend> (
    contract: &[u8],
    gas_limit: u64,
    balance: U256, // todo: this
    init: &Value,
    init_path: &str,
    lib_path: &str,
    input_path: &str,
    tcp_scilla_server: & mut ScillaServer<B>,
) -> Result<()> {
    //let dir = TempDir::new()?;

    let args = vec![
        "-i".to_owned(),
        //contract_path.to_str().unwrap().to_owned(),
        input_path.to_string(),
        "-init".to_owned(),
        init_path.to_string(), // ending init.json
        "-ipcaddress".to_owned(),
        "/tmp/scilla-server.sock".to_owned(), // todo: this.
        //"/tmp/scilla-socket/server.sock".to_owned(), // todo: this.
        "-gaslimit".to_owned(),
        gas_limit.to_string(),
        "-balance".to_owned(),
        //balance.to_string(),
        //"1000000".to_string(), // todo: this
        balance.to_string(), // todo: this
        "-libdir".to_owned(),
        //self.lib_dir.to_str().unwrap().to_owned(),
        lib_path.to_string(),
        "-jsonerrors".to_owned(),
    ];

    let args = serde_json::to_value(args)?;
    let params: Value = [("argv".to_owned(), args)].into_iter().collect();
    let params: Params = from_value(params).unwrap();

    let mut response = call_scilla_server("run", params, tcp_scilla_server)?;

    let response = response.replace("\"{", "{")
        .replace("}\"", "}");

    debug!("Create Response: {:?}", response);

    //let mut deser: Result<JsonRpcResponse, serde_json::Error> = from_str(&response);
    //debug!("Deser: {:?}", deser);

    //let response: CheckOutput = serde_json::from_value(deser.unwrap().result.unwrap().clone()).unwrap();

    //debug!("Create response: {response}");

    Ok(())
}
fn ensure_setup_correct(init_data: Option<serde_json::Value>, init_directory: &Path, input_data: Option<Vec<u8>>, input_directory: &Path, message: Option<Value>) {

    debug!("Ensure setup correct for scilla invocation: {:?} {:?}", init_data, input_data);

    match init_data {
        Some(init_data) => {
            let init_data = init_data.as_array().unwrap();
            let mut init_data = init_data.clone();

            let mut init_file = File::create(init_directory.join("init.json")).unwrap();
            //init_file.write_all(init_data).unwrap();
            init_file.write_all(serde_json::to_string(&init_data).unwrap().as_bytes()).unwrap();
        }
        None => { }
    }

    match input_data {
        Some(input_data) => {
            let mut input_file = File::create(input_directory.join("input.scilla")).unwrap();
            input_file.write_all(&input_data).unwrap();
        }
        None => { }
    }

    match message {
        Some(message) => {
            let mut message_file = File::create(input_directory.join("message.scilla")).unwrap();
            message_file.write_all(serde_json::to_string(&message).unwrap().as_bytes()).unwrap();
        }
        None => { }
    }
}
