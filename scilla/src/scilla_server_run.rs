use tracing::*;
use evm::{
    ExitSucceed,
    backend::{Apply, Backend}};

use jsonrpc_client_transports::{transports::duplex, RawClient, RpcChannel, RpcError};
use jsonrpc_core::{
    futures,
    futures_util::{SinkExt, StreamExt},
    Params,
};
use primitive_types::{H256, H160};
use sha2::{Digest, Sha256};
use std::str;
use std::io::Write;
use tokio::io::AsyncWriteExt;
use tokio::io::AsyncReadExt;

use std::path::Path;
use evm_ds::protos::evm_proto as EvmProto;
use evm_ds::protos::evm_proto::{ExitReasonCps };
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::fs::File;

use std::sync::{Arc, Mutex};
use evm_ds::tracing_logging::LoggingEventListener;
use serde_json::from_str;
use serde::{Serialize, Deserialize};

use tokio::io::sink;
use tokio::net::TcpStream;
use std::process;
use tokio::sync::oneshot;
use tokio::select;

use tokio::time::{sleep, Duration};

pub fn run_scilla_impl_direct<B: Backend>(
    args: EvmProto::EvmCallArgs,
    backend: &B,
) -> EvmProto::EvmResult {

    debug!("**** run_scilla_impl_direct called with args: {:?}", args);
    let block_num = backend.block_number();
    //let scilla = Scilla::new(PathBuf::from("/scilla/default/lib/scilla/stdlib/"))?;
    //let db = Db::new(persistence_directory)?;
    //let db = Arc::new(Mutex::new(db));
    //let ipc_server = state_ipc_server::Server::new(db.clone());

    //let from_addr = account_address(txn.sender_pub_key);
    let from_addr = backend.origin();

    let lib_directory = PathBuf::from("/scilla/0/src/stdlib/");
    let init_directory = PathBuf::from("/Users/nhutton/repos/zq2/scilla_init/");
    let input_directory = PathBuf::from("/Users/nhutton/repos/zq2/scilla_input/");
    // Convert code to string since scilla
    let code = str::from_utf8(&args.code).expect("unable to convert code to string").to_string();
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
            let mut hasher = Sha256::new();
            hasher.update(from_addr.as_bytes());
            hasher.update((get_account_nonce() - 1).to_be_bytes());
            let hashed = hasher.finalize();
            let contract_address = H160::from_slice(&hashed[(hashed.len() - 20)..]);
            debug!("Created contract: {contract_address:?}");
            debug!("Init data is: {:?}", init_data);

            //let mut init_data = init_data.clone();
            //let mut init_data: Value = serde_json::from_str(init_data);
            let mut init_data: Value = serde_json::from_slice(init_data.as_slice()).unwrap();
            init_data.as_array_mut().unwrap().push(json!({"vname": "_creation_block", "type": "BNum", "value": block_num.to_string()}));
            let contract_address_hex = format!("{contract_address:?}");
            init_data.as_array_mut().unwrap().push(json!({"vname": "_this_address", "type": "ByStr20", "value": contract_address_hex}));

            // Write down to the files the init data and make sure the libs are in order
            // todo: make sure the old files are cleared
            ensure_setup_correct(Some(init_data.clone()), &init_directory, Some(code.clone()), &input_directory);

            // todo: write to backend the contract addr, code, init state

            //db.lock()
            //    .unwrap()
            //    .put_contract_code(contract_address, code.as_bytes())?;
            //db.lock()
            //    .unwrap()
            //    .put_init_state_2(contract_address, &serde_json::to_vec(&init_data)?)?;

            //let mut state_root = H256::from_slice(&Keccak256::digest(rlp::NULL_RLP));

            let check_output =
                check_contract(code.as_bytes(), args.gas_limit, &init_data).unwrap();

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

pub fn check_contract(
    contract: &[u8],
    gas_limit: u64,
    init: &Value,
) -> Result<CheckOutput> {
    //let dir = TempDir::new()?;
    //let (contract_path, init_path) = self.create_common_inputs(&dir, contract, init)?;

    let args = vec![
        "-init".to_owned(),
        //init_path.to_str().unwrap().to_owned(),
        "/tmp/scilla_init/init.json".to_owned(),
        "-libdir".to_owned(),
        //self.lib_dir.to_str().unwrap().to_owned(),
        //"/tmp/scilla_libs/".to_owned(),
        "/scilla/0/src/stdlib/".to_owned(),
        //contract_path.to_str().unwrap().to_owned(),
        //"/scilla/0/input.scilla".to_owned(),
        "/tmp/scilla_input/input.scilla".to_owned(),
        "-gaslimit".to_owned(),
        gas_limit.to_string(),
        "-contractinfo".to_owned(),
        "-jsonerrors".to_owned(),
    ];
    let args = serde_json::to_value(args)?;
    let params = [("argv".to_owned(), args)].into_iter().collect();

    let mut response = call_scilla_server("check", params)?;

    let response = response.replace("\"{", "{")
        .replace("}\"", "}");

    let mut deser: Result<JsonRpcResponse, serde_json::Error> = from_str(&response);
    debug!("Deser: {:?}", deser);

    let response: CheckOutput = serde_json::from_value(deser.unwrap().result.unwrap().clone()).unwrap();

    Ok(response)
}
pub fn create_contract(
    contract: &[u8],
    gas_limit: u64,
    //balance: u128, // todo: this
    init: &Value,
) -> Result<()> {
    //let dir = TempDir::new()?;

    let args = vec![
        "-init".to_owned(),
        //init_path.to_str().unwrap().to_owned(),
        "/tmp/scilla_init/init.json".to_owned(),
        "-libdir".to_owned(),
        //self.lib_dir.to_str().unwrap().to_owned(),
        //"/tmp/scilla_libs/".to_owned(),
        "/scilla/0/src/stdlib/".to_owned(),
        //contract_path.to_str().unwrap().to_owned(),
        //"/scilla/0/input.scilla".to_owned(),
        "/tmp/scilla_input/input.scilla".to_owned(),
        "-gaslimit".to_owned(),
        gas_limit.to_string(),
        "-contractinfo".to_owned(),
        "-jsonerrors".to_owned(),
    ];

    let args = serde_json::to_value(args)?;
    let params = [("argv".to_owned(), args)].into_iter().collect();

    let mut response = call_scilla_server("run", params)?;

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
            //init_data.as_array_mut().unwrap().push(json!({"vname": "_creation_block", "type": "BNum", "value": "1"}));
            //let contract_address_hex = format!("{contract_address:?}");
            //init_data.as_array_mut().unwrap().push(json!({"vname": "_this_address", "type": "ByStr20", "value": contract_address_hex}));
            //let init_data = serde_json::to_string(&init_data).unwrap();
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

// todo: this.
fn get_account_nonce() -> u64 {
    1
}

struct TcpRawClient {
    pub client: TcpStream,
}

#[derive(Deserialize, Debug)]
pub struct CheckOutput {
    pub contract_info: ContractInfo,
}

#[derive(Deserialize, Debug)]
pub struct ContractInfo {
    pub scilla_major_version: String,
    pub fields: Vec<Param>,
}

#[derive(Deserialize, Debug)]
pub struct Param {
    #[serde(rename = "vname")]
    pub name: String,
    pub depth: u64,
    #[serde(rename = "type")]
    pub ty: String,
}


#[derive(Serialize, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: serde_json::Value,
    id: u32,
}

impl JsonRpcRequest {
    fn new(method: &str, params: serde_json::Value, id: u32) -> Self {
        JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
            id,
        }
    }
}
#[derive(Serialize, Deserialize, Debug)]
struct JsonRpcResponse {
    jsonrpc: String,
    result: Option<Value>,
    error: Option<JsonRpcError>,
    id: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct JsonRpcError {
    code: i32,
    message: String,
    data: Option<Value>,
}

pub fn call_scilla_server(method: &str, params: serde_json::Value) -> Result<String> {

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async move {
        let request = JsonRpcRequest::new(method, params, 1);
        let mut request_str = serde_json::to_string(&request)?;
        let request_str = request_str + "\n";

        debug!("Calling Scilla server with request: {:?}", request_str);

        let mut stream = TcpStream::connect("127.0.0.1:12345").await?;
        stream.write_all(request_str.as_bytes()).await?;

        let mut response = [0; 10000];
        let mut bytes_read = 0;

        loop {
            select! {
            _ = tokio::time::sleep(Duration::from_millis(5000)) => {
                return Err(anyhow!("Timeout trying to read response from Scilla server"));
            }
            bytes_r = stream.read(&mut response[bytes_read..]) => {
                bytes_read += bytes_r.unwrap();

                if bytes_read == 0 {
                    debug!("Scilla server closed connection {:?}", response);
                }

                if response[bytes_read-1] == '\n' as u8 {
                    let filtered = filter_this(response[0..bytes_read-1].to_vec());
                    return Ok(String::from_utf8(filtered)?);
                } else {
                    debug!("Scilla response so far: {:?}", response);
                }

                if bytes_read >= 10000 {
                    return Err(anyhow!("Response from Scilla server too large!"));
                }
            }
        }
        }
    })
}

fn filter_this(data: Vec<u8>) -> Vec<u8> {
    let mut filtered_data = Vec::new();
    let mut skip_next = false;

    for (i, &byte) in data.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }

        if byte == b'\\' && i + 1 < data.len() && data[i + 1] == b'"' {
            //skip_next = true; // Skip the next character, which is a quotation mark
            continue;
        }

        if byte == b'\\' && i + 1 < data.len() && data[i + 1] == b'n' {
            skip_next = true; // Skip the next character, which is a quotation mark
            continue;
        }
        filtered_data.push(byte);
    }
    filtered_data
}
