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

    // These are the directories on the local machine which we will write to
    //let init_directory_local = "/Users/nhutton/repos/zq2/scilla_init/";
    //let input_directory_local = "/Users/nhutton/repos/zq2/scilla_input/";
    let init_directory = PathBuf::from("/Users/nhutton/repos/zq2/scilla_init/");
    let input_directory = PathBuf::from("/Users/nhutton/repos/zq2/scilla_input/");

    let code = str::from_utf8(&args.code).expect("unable to convert scilla code to a string").to_string();
    let init_data = args.data;

    match (code.is_empty(), init_data.is_empty()) {
        // Transfer
        (true, true) => {
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
        (false, false) => {
            debug!("contract creation!");
            let account_nonce: u64 = 1; // todo: this

            // todo: make this a free function for contract creation calculation
            let mut hasher = Sha256::new();
            hasher.update(from_addr.as_bytes());
            hasher.update((account_nonce - 1).to_be_bytes());
            let hashed = hasher.finalize();
            let contract_address = H160::from_slice(&hashed[(hashed.len() - 20)..]);

            debug!("Creating contract: {contract_address:?}");
            debug!("Init data is: {:?}", init_data);

            let mut init_data: Value = serde_json::from_slice(init_data.as_slice()).unwrap();
            init_data.as_array_mut().unwrap().push(json!({"vname": "_creation_block", "type": "BNum", "value": block_num.to_string()}));
            let contract_address_hex = format!("{contract_address:?}");
            init_data.as_array_mut().unwrap().push(json!({"vname": "_this_address", "type": "ByStr20", "value": contract_address_hex}));

            // Write down to the files the init data and make sure the libs are in order
            // todo: make sure the old files are cleared
            ensure_setup_correct(Some(init_data.clone()), &init_directory, Some(code.clone()), &input_directory);

            // todo: write to backend the contract addr, code, init state

            // Create account here
            //backend_collector.

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

            debug!("Check output: {:?}", check_output);

            let addr_no_prefix = format!("{contract_address:x}");

            debug!("here0");

            /*
            for field in check_output.contract_info.fields {
                let depth_key =
                    format!("{}\x16_depth\x16{}\x16", addr_no_prefix, field.name);
                state_root = db.lock().unwrap().put_contract_state(
                    state_root,
                    &depth_key,
                    field.depth.to_string().as_bytes(),
                )?;
                let type_key =
                    format!("{}\x16_type\x16{}\x16", addr_no_prefix, field.name);
                state_root = db.lock().unwrap().put_contract_state(
                    state_root,
                    &type_key,
                    field.ty.as_bytes(),
                )?;
            }
            */

            debug!("here1");

            /*
            let version_key = format!("{addr_no_prefix}\x16_version\x16");
            state_root = db.lock().unwrap().put_contract_state(
                state_root,
                &version_key,
                check_output.contract_info.scilla_major_version.as_bytes(),
            )?;
            debug!("here2");
            let addr_key = format!("{addr_no_prefix}\x16_addr\x16");
            state_root = db.lock().unwrap().put_contract_state(
                state_root,
                &addr_key,
                contract_address.as_bytes(),
            )?;
            debug!("here3");
            */

            /*
            ipc_server.set_current_contract_addr(
                contract_address,
                state_root,
                block_num,
            ); */

            debug!("here4create");

            create_contract(
                code.as_bytes(),
                args.gas_limit,
                //args.apparent_value,
                &init_data,
                init_directory_str, lib_directory_str, input_directory_str, &mut tcp_scilla_server

            ).unwrap();

            debug!("here5");

            /* let state_root = ipc_server.reset_current_contract_addr(); */

            debug!("here6");

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
        }

        // Contract call
        (false, true) => {
            debug!("contract call! Nothing to do");
            //Ok(())
        }
        (true, false) => {
            debug!("contract creation without init data");
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

    EvmProto::EvmResult {
        exit_reason : ExitReasonCps::Succeed(ExitSucceed::Stopped),
        return_value: vec![],
        apply: vec![],
        logs: vec![],
        tx_trace: Arc::new(Mutex::new(LoggingEventListener::new(false))),
        remaining_gas: 0,
        continuation_id: 0,
        trap_data: None,
    }
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
pub fn create_contract<B: evm::backend::Backend>(
    contract: &[u8],
    gas_limit: u64,
    //balance: u128, // todo: this
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
        "1000000".to_string(), // todo: this
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
fn ensure_setup_correct(init_data: Option<serde_json::Value>, init_directory: &Path, input_data: Option<String>, input_directory: &Path) {

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
            input_file.write_all(input_data.as_bytes()).unwrap();
        }
        None => { }
    }
}

//// todo: this.
//fn get_account_nonce() -> u64 {
//    1
//}

