use tracing::*;
use evm::{
    ExitSucceed,
    backend::{Apply, Backend}};

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

fn get_runtime_handle() -> (Handle, Option<Runtime>) {
    match Handle::try_current() {
        Ok(h) => (h, None),
        Err(_) => {
            let rt = Runtime::new().unwrap();
            (rt.handle().clone(), Some(rt))
        }
    }
}

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

    let tcp_scilla_server = ScillaServer::new(backend);

    let lib_directory_str = "/scilla/0/src/stdlib/";
    let init_directory_str = "/tmp/scilla_init/init.json";
    let input_directory_str = "/tmp/scilla_input/input.scilla";

    let init_directory_local = "/Users/nhutton/repos/zq2/scilla_init/";
    let input_directory_local = "/Users/nhutton/repos/zq2/scilla_input/";

    //let lib_directory = PathBuf::from(lib_directory_str);
    let init_directory = PathBuf::from(init_directory_local);
    let input_directory = PathBuf::from(input_directory_local);
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
                check_contract(code.as_bytes(), args.gas_limit, &init_data, init_directory_str, lib_directory_str, input_directory_str, &tcp_scilla_server
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
                init_directory_str, lib_directory_str, input_directory_str, &tcp_scilla_server

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
    tcp_scilla_server: &ScillaServer<B>,
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
    let params = [("argv".to_owned(), args)].into_iter().collect();

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
    tcp_scilla_server: &ScillaServer<B>,
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
    let params = [("argv".to_owned(), args)].into_iter().collect();

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

pub fn call_scilla_server<B: evm::backend::Backend>(method: &str, params: serde_json::Value, tcp_scilla_server: &ScillaServer<B>) -> Result<String> {

    //let rt = tokio::runtime::Builder::new_current_thread()
    //    .enable_all()
    //    .build()?;

    //let rt = get_runtime_handle();

    //rt.0.

    //let result = rt.0.spawn(async move {
    //debug!("Calling the Scilla server proper");
    //Ok("adsf".to_string())
    let request = JsonRpcRequest::new(method, params, 1);
    let mut request_str = serde_json::to_string(&request)?;
    let request_str = request_str + "\n";

    debug!("Calling Scilla server with request: {:?}", request_str);

    let mut stream = TcpStream::connect("127.0.0.1:12345")?;
    let mut stream_backend = TcpStream::connect("127.0.0.1:12346")?;

    stream.write_all(request_str.as_bytes())?;

    stream.set_nonblocking(true)?;
    stream_backend.set_nonblocking(true)?;

    let mut response = [0; 10000];
    let mut response_backend = [0; 10000];
    let mut bytes_read = 0;
    let mut bytes_read_backend = 0;

    //let mut io = IoHandler::new();

    //io.add_method("updateStateValueB64",  |params| {
    //    debug!("updateStateValueB64 called with params: {:?}", params);
    //    future::ready(Ok(json!(true))).boxed()
    //    //move |params| inner.lock().unwrap().fetch_state_value_b64(params)
    //});

    //io.add_method("updateStateValue",  |params| {
    //    debug!("updateStateValue called with params: {:?}", params);
    //    future::ready(Ok(json!(true))).boxed()
    //    //move |params| inner.lock().unwrap().fetch_state_value_b64(params)
    //});

    //debug!("Calling the Scilla server proper");

    loop {
        let bytes_read_tcp = stream_backend.read(&mut response_backend[bytes_read..]);

        match bytes_read_tcp {
            Ok(bytes_read) => {
                if bytes_read > 0 {
                    debug!("Scilla backend response so far: {:?}", str::from_utf8(&response_backend));
                }

                bytes_read_backend += bytes_read;
            }
            Err(e) => {
                debug!("Scilla backend response so far: {:?}", str::from_utf8(&response_backend));
                debug!("Scilla backend error: {:?}", e);
            }
        }

        if bytes_read_backend > 0 {
            if response_backend[bytes_read_backend-1] == '\n' as u8 {
                //let filtered = filter_this(response_backend[0..bytes_read_backend-1].to_vec());
                //debug!("Scilla backend response: {:?}", String::from_utf8(filtered.clone())?);
                //let aa = io.handle_request_sync(&String::from_utf8(filtered)?);
                //debug!("Scilla backend responseRR: {:?}", aa);

                let not_filtered = response_backend[0..bytes_read_backend-1].to_vec();
                let aa = tcp_scilla_server._tcp_server.handle_request_sync(&String::from_utf8(not_filtered)?);
                debug!("Scilla backend responseRR: {:?}", aa);
                debug!("Scilla backend response: {:?}", aa);
                //return Ok(String::from_utf8(filtered)?);
            } else {
                debug!("Scilla response so farX: {:?}", String::from_utf8(response.to_vec())?);
            }
        }

        let bytes_r = stream.read(&mut response[bytes_read..]);

        match bytes_r {
            Ok(bytes_r) => {
                bytes_read += bytes_r;
            }
            Err(e) => {
                debug!("Scilla read error: {:?}", e);
            }
        }


        if bytes_read > 0 {
            debug!("Scilla response so farBk: {:?}", String::from_utf8(response.to_vec())?);
        }

        if bytes_read == 0 {
            // sleep 1 sec
            std::thread::sleep(std::time::Duration::from_secs(1));

            continue;
        }

        if response[bytes_read-1] == '\n' as u8 {
            let filtered = filter_this(response[0..bytes_read-1].to_vec());
            return Ok(String::from_utf8(filtered)?);
        } else {
            debug!("Scilla response so farYY: {:?}", String::from_utf8(response.to_vec())?);
        }

        if bytes_read >= 10000 {
            return Err(anyhow!("Response from Scilla server too large!"));
        }

        // sleep 1 sec
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
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
/*

pub struct Server {
    //inner: Arc<Mutex<Inner>>,
    _tcp_server: jsonrpc_tcp_server::Server,
}

//struct Inner {
//    db: Arc<Mutex<Db>>,
//    current_contract_addr: Option<(H160, H256, u64)>,
//}

impl Server {
    pub fn new() -> Server {
        //let inner = Inner {
        //    db,
        //    current_contract_addr: None,
        //};
        //let inner = Arc::new(Mutex::new(inner));

        let mut io = IoHandler::new();
        io.add_method("fetchStateValueB64", {
            let inner = Arc::clone(&inner);
            move |params| inner.lock().unwrap().fetch_state_value_b64(params)
        });
        io.add_method("fetchExternalStateValueB64", {
            let inner = Arc::clone(&inner);
            move |params| inner.lock().unwrap().fetch_external_state_value_b64(params)
        });
        io.add_method("updateStateValueB64", {
            let inner = Arc::clone(&inner);
            move |params| inner.lock().unwrap().update_state_value_b64(params)
        });
        io.add_method("fetchBlockchainInfo", {
            let inner = Arc::clone(&inner);
            move |params| inner.lock().unwrap().fetch_blockchain_info(params)
        });

        let _tcp_server = ServerBuilder::new(io)
            .request_separators(Separator::Byte(b'\n'), Separator::Byte(b'\n'))
            .start("/tmp/stateipc.sock")
            .unwrap();

        Server { _tcp_server }
    }

    pub fn set_current_contract_addr(&self, addr: H160, state_root: H256, block_number: u64) {
        self.inner.lock().unwrap().current_contract_addr = Some((addr, state_root, block_number));
    }

    pub fn reset_current_contract_addr(&self) -> H256 {
        let (_, state_root, _) = self
            .inner
            .lock()
            .unwrap()
            .current_contract_addr
            .take()
            .unwrap();
        state_root
    }
}

impl Inner {
    fn fetch_state_value_b64(
        &mut self,
        params: Params,
    ) -> BoxFuture<Result<Value, jsonrpc_core::Error>> {
        fn err(s: &'static str) -> BoxFuture<Result<Value, jsonrpc_core::Error>> {
            futures::future::ready(Err(jsonrpc_core::Error::invalid_params(s))).boxed()
        }

        let b64 = base64::engine::general_purpose::STANDARD;

        let Params::Map(params) = params else { return err("expected a map"); };
        let Some(query) = params.get("query") else { return err("expected query in map"); };
        let Some(query) = query.as_str().map(str::to_owned) else { return err("query was not a string"); };
        let Ok(query) = b64.decode(query) else { return err("query was not base64"); };
        let Ok(query) = ProtoScillaQuery::decode(query.as_slice()) else { return err("could not parse query"); };

        let result = self.fetch_state_value_inner(query).map_err(convert_err);

        let result = result.map(|value| {
            let arr = match value {
                Some(value) => vec![true.into(), b64.encode(value.encode_to_vec()).into()],
                None => vec![false.into(), String::new().into()],
            };
            Value::Array(arr)
        });

        future::ready(result).boxed()
    }

    fn fetch_state_value_inner(
        &mut self,
        query: ProtoScillaQuery,
    ) -> Result<Option<ProtoScillaVal>> {
        trace!("Fetch state value: {query:?}");

        if ["_addr", "_version", "_depth", "_type", "_hasmap"].contains(&query.name.as_str()) {
            return Err(anyhow!("reserved variable name: {}", query.name));
        }

        let Some((addr, _, _)) = self.current_contract_addr else { return Err(anyhow!("no current contract")); };

        let addr_hex = format!("{addr:x}");
        let mut key = format!("{}\x16{}\x16", addr_hex, query.name);
        for index in &query.indices {
            key.push_str(str::from_utf8(index)?);
            key.push('\x16');
        }

        let value = match query.indices.len().cmp(&(query.mapdepth as usize)) {
            std::cmp::Ordering::Greater => {
                return Err(anyhow!("indices is deeper than map depth"));
            }
            std::cmp::Ordering::Equal => {
                // Result will not be a map and can be just fetched into the store
                let bytes = self.db.lock().unwrap().get_contract_state_data(&key)?;

                let Some(bytes) = bytes else { return Ok(None); };

                ProtoScillaVal {
                    val_type: Some(ValType::Bval(bytes)),
                }
            }
            std::cmp::Ordering::Less => {
                // We're fetching a map value. We need to iterate through the DB lexicographically.
                let mut entries = HashMap::new();

                let existing_entries: Vec<_> = self
                    .db
                    .lock()
                    .unwrap()
                    .get_contract_state_data_with_prefix(&key)
                    .collect();
                if existing_entries.is_empty() && !query.indices.is_empty() {
                    return Ok(None);
                }
                for kv in existing_entries {
                    let (k, v) = kv?;
                    entries.insert(k, v);
                }

                let mut val = ProtoScillaVal {
                    val_type: Some(ValType::Mval(proto_scilla_val::Map { m: HashMap::new() })),
                };
                for (k, v) in entries {
                    let key_non_prefix = k
                        .strip_prefix(&key)
                        .ok_or_else(|| anyhow!("{key} is not a prefix of {k}"))?;
                    let indices: Vec<_> = key_non_prefix.split_terminator('\x16').collect();

                    let mut val_ref = &mut val;
                    for index in &indices {
                        let Some(ValType::Mval(proto_scilla_val::Map { ref mut m })) = val_ref.val_type else { unreachable!(); };
                        val_ref = m.entry((*index).to_owned()).or_insert(ProtoScillaVal {
                            val_type: Some(ValType::Mval(Default::default())),
                        });
                    }

                    if query.indices.len() + indices.len() < query.mapdepth as usize {
                        // Assert that we have a protobuf-encoded empty map.
                        let empty_map = ProtoScillaVal::decode(v.as_slice())?;
                        match empty_map.val_type {
                            Some(ValType::Mval(map)) if map.m.is_empty() => {}
                            _ => {
                                return Err(anyhow!("Expected protobuf encoded empty map since entry has fewer keys than mapdepth"));
                            }
                        }
                        *val_ref = ProtoScillaVal {
                            val_type: Some(ValType::Mval(Default::default())),
                        };
                    } else {
                        *val_ref = ProtoScillaVal {
                            val_type: Some(ValType::Bval(v)),
                        };
                    }
                }
                val
            }
        };

        Ok(Some(value))
    }

    fn fetch_external_state_value_b64(
        &mut self,
        params: Params,
    ) -> BoxFuture<Result<Value, jsonrpc_core::Error>> {
        fn err(s: &'static str) -> BoxFuture<Result<Value, jsonrpc_core::Error>> {
            futures::future::ready(Err(jsonrpc_core::Error::invalid_params(s))).boxed()
        }

        let b64 = base64::engine::general_purpose::STANDARD;

        let Params::Map(params) = params else { return err("expected a map"); };
        let Some(addr) = params.get("addr") else { return err("expected addr in map"); };
        let Some(addr) = addr.as_str().map(str::to_owned) else { return err("addr was not a string"); };
        let Ok(addr) = addr.parse::<H160>() else { return err("addr parsing failed"); };
        let Some(query) = params.get("query") else { return err("expected query in map"); };
        let Some(query) = query.as_str().map(str::to_owned) else { return err("query was not a string"); };
        let Ok(query) = b64.decode(query) else { return err("query was not base64"); };

        let result = self
            .fetch_external_state_value_inner(addr, query)
            .map_err(convert_err);

        let result = result.map(|vt| {
            let arr = match vt {
                Some((value, ty)) => vec![
                    true.into(),
                    b64.encode(value.encode_to_vec()).into(),
                    ty.into(),
                ],
                None => vec![false.into(), String::new().into(), String::new().into()],
            };
            Value::Array(arr)
        });

        future::ready(result).boxed()
    }

    fn fetch_external_state_value_inner(
        &mut self,
        addr: H160,
        query: Vec<u8>,
    ) -> Result<Option<(ProtoScillaVal, String)>> {
        let mut query = ProtoScillaQuery::decode(query.as_slice())?;

        trace!("Fetch external state value: {addr:?} - {query:?}");

        let Some(account) = self.db.lock().unwrap().get_account(addr)? else { return Ok(None); };
        let account = Account::from_proto(account)?;

        fn scilla_val(b: Vec<u8>) -> ProtoScillaVal {
            ProtoScillaVal {
                val_type: Some(ValType::Bval(b)),
            }
        }

        match query.name.as_str() {
            "_balance" => {
                let val = scilla_val(format!("\"{}\"", account.balance).into_bytes());
                return Ok(Some((val, "Uint128".to_owned())));
            }
            "_nonce" => {
                let val = scilla_val(format!("\"{}\"", account.nonce).into_bytes());
                return Ok(Some((val, "Uint64".to_owned())));
            }
            "_this_address" => {
                if account.contract.is_some() {
                    let val = scilla_val(format!("\"0x{:?}\"", addr).into_bytes());
                    return Ok(Some((val, "ByStr20".to_owned())));
                }
            }
            "_codehash" => {
                let code_hash = account.contract.map(|c| c.code_hash).unwrap_or_default();
                let val = scilla_val(format!("\"0x{:?}\"", code_hash).into_bytes());
                return Ok(Some((val, "ByStr32".to_owned())));
            }
            "_code" => {
                let code = self
                    .db
                    .lock()
                    .unwrap()
                    .get_contract_code(addr)?
                    .unwrap_or_default();
                let val = scilla_val(code);
                return Ok(Some((val, String::new())));
            }
            _ => {}
        }

        let addr_hex = format!("{addr:x}");

        let ty = if query.name == "_evm_storage" {
            Some("ByStr30".to_owned())
        } else {
            let ty_key = format!("{}\x16_type\x16{}\x16", addr_hex, query.name);
            self.get_state(&ty_key)?
                .map(String::from_utf8)
                .transpose()?
        };
        let Some(ty) = ty else { return Ok(None); };

        let depth_key = format!("{}\x16_depth\x16{}\x16", addr_hex, query.name);
        let depth = String::from_utf8(
            self.get_state(&depth_key)?
                .ok_or_else(|| anyhow!("no depth"))?,
        )?
            .parse()?;
        query.mapdepth = depth;

        let Some(contract) = account.contract else { return Err(anyhow!("state read from non-contract")); };

        let Some((old_addr, old_state_root, block_num)) = self.current_contract_addr else { return Err(anyhow!("no current contract")); };

        self.current_contract_addr = Some((addr, contract.state_root, block_num));
        let value = self.fetch_state_value_inner(query)?;
        self.current_contract_addr = Some((old_addr, old_state_root, block_num));

        Ok(value.map(|v| (v, ty)))
    }

    fn update_state_value_b64(
        &mut self,
        params: Params,
    ) -> BoxFuture<Result<Value, jsonrpc_core::Error>> {
        fn err(s: &'static str) -> BoxFuture<Result<Value, jsonrpc_core::Error>> {
            futures::future::ready(Err(jsonrpc_core::Error::invalid_params(s))).boxed()
        }

        let b64 = base64::engine::general_purpose::STANDARD;

        let Params::Map(params) = params else { return err("expected a map"); };
        let Some(query) = params.get("query") else { return err("expected query in map"); };
        let Some(query) = query.as_str().map(str::to_owned) else { return err("query was not a string"); };
        let Ok(query) = b64.decode(query) else { return err("query was not base64"); };
        let Some(value) = params.get("value") else { return err("expected value in map"); };
        let Some(value) = value.as_str().map(str::to_owned) else { return err("value was not a string"); };
        let Ok(value) = b64.decode(value) else { return err("value was not base64"); };

        let result = self
            .update_state_value_inner(query, value)
            .map_err(convert_err);

        future::ready(result).boxed()
    }

    fn update_state_value_inner(&mut self, query: Vec<u8>, value: Vec<u8>) -> Result<Value> {
        let query = ProtoScillaQuery::decode(query.as_slice())?;
        let value = ProtoScillaVal::decode(value.as_slice())?;

        trace!("Update state value: {query:?} -> {value:?}");

        if ["_addr", "_version", "_depth", "_type", "_hasmap"].contains(&query.name.as_str()) {
            return Err(anyhow!("reserved variable name: {}", query.name));
        }

        let Some((addr, _, _)) = self.current_contract_addr else { return Err(anyhow!("no current contract")); };

        let addr_hex = format!("{addr:x}");
        let mut key = format!("{}\x16{}\x16", addr_hex, query.name);

        if query.ignoreval {
            if query.indices.is_empty() {
                return Err(anyhow!("indices cannot be empty"));
            }
            for index in &query.indices[..(query.indices.len() - 1)] {
                let index = str::from_utf8(index)?;
                key.push_str(index);
                key.push('\x16');
            }
            let parent_key = key.clone();
            let index = str::from_utf8(query.indices.last().unwrap())?;
            key.push_str(index);
            key.push('\x16');

            self.delete_by_prefix(&key)?;

            if self.key_is_empty(&parent_key)? {
                let empty_map = ProtoScillaVal {
                    val_type: Some(ValType::Mval(Default::default())),
                };
                self.update_state(&parent_key, &empty_map.encode_to_vec(), false)?;
            }
        } else {
            for index in &query.indices {
                let index = str::from_utf8(index)?;
                key.push_str(index);
                key.push('\x16');
            }

            match query.indices.len().cmp(&(query.mapdepth as usize)) {
                std::cmp::Ordering::Greater => {
                    return Err(anyhow!("indices is deeper than map depth"));
                }
                std::cmp::Ordering::Equal => {
                    let val_type = value.val_type.ok_or_else(|| anyhow!("no val_type"))?;
                    let ValType::Bval(bytes) = val_type else { return Err(anyhow!("expected bytes for value, but got a map")); };
                    self.update_state(&key, &bytes, true)?;
                }
                std::cmp::Ordering::Less => {
                    self.delete_by_prefix(&key)?;

                    fn map_handler(
                        inner: &mut Inner,
                        key_acc: String,
                        value: &ProtoScillaVal,
                    ) -> Result<()> {
                        let val_type = value
                            .val_type
                            .as_ref()
                            .ok_or_else(|| anyhow!("no val_type"))?;
                        let ValType::Mval(val_type) = val_type else { return Err(anyhow!("expected map for value but got bytes")); };

                        if val_type.m.is_empty() {
                            // We have an empty map. Insert an entry for keyAcc in the store to indicate that the key itself exists.
                            inner.update_state(&key_acc, &value.encode_to_vec(), true)?;
                            return Ok(());
                        }

                        for (k, v) in &val_type.m {
                            let mut index = key_acc.clone();
                            index.push_str(k);
                            index.push('\x16');

                            let inner_val_type =
                                v.val_type.as_ref().ok_or_else(|| anyhow!("no val_type"))?;
                            match inner_val_type {
                                ValType::Mval(_) => {
                                    map_handler(inner, index, v)?;
                                }
                                ValType::Bval(bytes) => {
                                    inner.update_state(&index, bytes.as_slice(), true)?;
                                }
                            }
                        }

                        Ok(())
                    }

                    map_handler(self, key, &value)?;
                }
            }
        }

        Ok(Value::Null)
    }

    fn fetch_blockchain_info(
        &mut self,
        params: Params,
    ) -> BoxFuture<Result<Value, jsonrpc_core::Error>> {
        fn err(s: &'static str) -> BoxFuture<Result<Value, jsonrpc_core::Error>> {
            futures::future::ready(Err(jsonrpc_core::Error::invalid_params(s))).boxed()
        }

        let Params::Map(params) = params else { return err("expected a map"); };
        let Some(query_name) = params.get("query_name") else { return err("expected query_name in map"); };
        let Some(query_name) = query_name.as_str().map(str::to_owned) else { return err("query_name was not a string"); };
        let Some(query_args) = params.get("query_args") else { return err("expected query_args in map"); };
        let Some(query_args) = query_args.as_str().map(str::to_owned) else { return err("query_args was not a string"); };

        let result = self
            .fetch_blockchain_info_inner(query_name, query_args)
            .map_err(convert_err);

        let result = result.map(|s| Value::Array(vec![true.into(), s.into()]));

        future::ready(result).boxed()
    }

    fn fetch_blockchain_info_inner(
        &mut self,
        query_name: String,
        query_args: String,
    ) -> Result<String> {
        trace!("Fetch blockchain info: {query_name} - {query_args}");

        match query_name.as_str() {
            "BLOCKNUMBER" => {
                let Some((_, _, block_number)) = self.current_contract_addr else { return Err(anyhow!("no current contract")); };
                Ok(block_number.to_string())
            }
            "TIMESTAMP" => {
                let block_num: u64 = query_args.parse()?;
                let block = self
                    .db
                    .lock()
                    .unwrap()
                    .get_tx_block(block_num)?
                    .ok_or_else(|| anyhow!("invalid block"))?;
                let block = TxBlock::from_proto(block)?;
                Ok(block.timestamp.to_string())
            }
            "BLOCKHASH" => {
                let block_num: u64 = query_args.parse()?;
                let block = self
                    .db
                    .lock()
                    .unwrap()
                    .get_tx_block(block_num)?
                    .ok_or_else(|| anyhow!("invalid block"))?;
                let block = TxBlock::from_proto(block)?;
                let block_hash = format!("{:x}", block.block_hash);
                Ok(block_hash)
            }
            "CHAINID" => Ok(1.to_string()),
            _ => Ok(String::new()),
        }
    }

    fn get_state(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.db.lock().unwrap().get_contract_state_data(key)
    }

    fn key_is_empty(&self, key: &str) -> Result<bool> {
        let keys: Vec<_> = self
            .db
            .lock()
            .unwrap()
            .get_contract_state_data_with_prefix(key)
            .collect::<Result<_>>()?;

        Ok(keys.is_empty())
    }

    fn delete_by_prefix(&mut self, prefix: &str) -> Result<()> {
        let Some((addr, state_root, block_number)) = self.current_contract_addr else { return Err(anyhow!("no current contract")); };
        let state_root = self
            .db
            .lock()
            .unwrap()
            .delete_contract_state_with_prefix(state_root, prefix)?;
        self.current_contract_addr = Some((addr, state_root, block_number));

        Ok(())
    }

    fn update_state(&mut self, key: &str, value: &[u8], clean_empty: bool) -> Result<()> {
        if clean_empty {
            let indices: Vec<_> = key.split_terminator('\x16').collect();
            if indices.len() < 2 {
                return Err(anyhow!("not enough indices: {}", indices.len()));
            }

            let mut scan_key = format!("{}\x16{}\x16", indices[0], indices[1]);
            self.delete_state(&scan_key)?;

            if indices.len() > 2 {
                // Exclude the value key.
                for index in &indices[2..(indices.len() - 1)] {
                    scan_key.push_str(index);
                    scan_key.push('\x16');
                    self.delete_state(&scan_key)?;
                }
            }
        }

        self.put_state(key, value)?;

        Ok(())
    }

    fn put_state(&mut self, key: &str, value: &[u8]) -> Result<()> {
        let Some((addr, state_root, block_number)) = self.current_contract_addr else { return Err(anyhow!("no current contract")); };
        let state_root = self
            .db
            .lock()
            .unwrap()
            .put_contract_state(state_root, key, value)?;
        self.current_contract_addr = Some((addr, state_root, block_number));

        Ok(())
    }

    fn delete_state(&mut self, key: &str) -> Result<()> {
        let Some((addr, state_root, block_number)) = self.current_contract_addr else { return Err(anyhow!("no current contract")); };
        let state_root = self
            .db
            .lock()
            .unwrap()
            .delete_contract_state(state_root, key)?;
        self.current_contract_addr = Some((addr, state_root, block_number));

        Ok(())
    }
}

fn convert_err(err: impl Into<anyhow::Error>) -> jsonrpc_core::Error {
    let err: anyhow::Error = err.into();
    error!("{err:?}");
    jsonrpc_core::Error {
        code: jsonrpc_core::ErrorCode::InternalError,
        message: err.to_string(),
        data: None,
    }
}

 */
