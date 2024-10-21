//! Interface to the Scilla intepreter

use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddr},
    str,
    sync::{
        mpsc::{channel, Receiver, Sender},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use alloy::{hex::ToHexExt, primitives::Address};
use anyhow::{anyhow, Result};
use base64::Engine;
use bytes::{BufMut, Bytes, BytesMut};
use jsonrpsee::{
    core::{client::ClientT, params::ObjectParams, ClientError},
    http_client::HttpClientBuilder,
    server::ServerHandle,
    types::{error::CALL_EXECUTION_FAILED_CODE, ErrorObject},
    RpcModule,
};
use prost::Message as _;
use serde::{
    de::{self, Unexpected},
    Deserialize, Deserializer, Serialize,
};
use serde_json::Value;
use sha2::Sha256;
use sha3::{digest::DynDigest, Digest};
use tokio::runtime;
use tracing::trace;

use crate::{
    cfg::ScillaExtLibsPathInScilla,
    crypto::Hash,
    exec::{PendingState, StorageValue},
    scilla_proto::{self, ProtoScillaQuery, ProtoScillaVal, ValType},
    serde_util::{bool_as_str, num_as_str},
    state::{Code, ContractInit},
    time::SystemTime,
    transaction::{ScillaGas, ZilAmount},
};

#[derive(PartialEq, Debug)]
enum ScillaServerRequestType {
    Check,
    Run,
}

#[derive(Debug)]
struct ScillaServerRequestBuilder {
    request_type: ScillaServerRequestType,
    init: Option<String>,
    message: Option<String>,
    lib_dirs: Option<Vec<String>>,
    code: Option<String>,
    gas_limit: Option<String>,
    ipc_address: Option<String>,
    balance: Option<String>,
    is_library: bool,
    contract_info: bool,
    json_errors: bool,
    pplit: bool,
}

impl ScillaServerRequestBuilder {
    fn new(request_type: ScillaServerRequestType) -> Self {
        Self {
            request_type,
            init: None,
            lib_dirs: None,
            code: None,
            message: None,
            gas_limit: None,
            balance: None,
            ipc_address: None,
            is_library: false,
            contract_info: false,
            json_errors: false,
            pplit: false,
        }
    }

    fn init(mut self, init: String) -> Self {
        self.init = Some(init);
        self
    }

    fn message(mut self, msg: &Value) -> Result<Self> {
        self.message = Some(serde_json::to_string(&msg)?);
        Ok(self)
    }

    fn lib_dirs(mut self, lib_dirs: Vec<String>) -> Self {
        self.lib_dirs = Some(lib_dirs);
        self
    }

    fn code(mut self, code: String) -> Self {
        self.code = Some(code);
        self
    }

    fn ipc_address(mut self, ipc_address: String) -> Self {
        self.ipc_address = Some(ipc_address);
        self
    }

    fn gas_limit(mut self, gas_limit: ScillaGas) -> Self {
        self.gas_limit = Some(gas_limit.to_string());
        self
    }

    fn balance(mut self, balance: ZilAmount) -> Self {
        self.balance = Some(balance.to_string());
        self
    }

    fn pplit(mut self, pplit: bool) -> Self {
        self.pplit = pplit;
        self
    }

    #[allow(clippy::wrong_self_convention)]
    fn is_library(mut self, is_library: bool) -> Self {
        self.is_library = is_library;
        self
    }

    fn contract_info(mut self, contract_info: bool) -> Self {
        self.contract_info = contract_info;
        self
    }

    fn json_errors(mut self, json_errors: bool) -> Self {
        self.json_errors = json_errors;
        self
    }

    fn build(self) -> Result<(&'static str, ObjectParams)> {
        let mut args = vec![];

        if let Some(init) = self.init {
            args.extend(["-init".to_owned(), init]);
        }

        if let Some(lib_dirs) = self.lib_dirs {
            args.extend(["-libdir".to_owned(), lib_dirs.join(":")]);
        }

        if let Some(ipc_address) = self.ipc_address {
            args.extend(["-ipcaddress".to_owned(), ipc_address])
        }

        if let Some(balance) = self.balance {
            args.extend(["-balance".to_owned(), balance]);
        }

        if let Some(message) = self.message {
            args.extend(["-imessage".to_owned(), message]);
        }

        if let Some(code) = self.code {
            // Check request doesn't need `-i` for input code.
            if self.request_type == ScillaServerRequestType::Run {
                args.push("-i".to_owned());
            }
            args.push(code);
        }

        if let Some(gas_limit) = self.gas_limit {
            args.extend(vec!["-gaslimit".to_owned(), gas_limit.to_string()]);
        }

        if self.contract_info {
            args.push("-contractinfo".to_owned());
        }

        if self.json_errors {
            args.push("-jsonerrors".to_owned());
        }

        if self.is_library {
            args.push("-islibrary".to_owned());
            if self.request_type == ScillaServerRequestType::Run {
                // Check request doesn't need `true` if -islibrary is specified.
                args.push("true".to_owned());
            }
        }
        if self.pplit {
            args.extend(vec!["-pplit".to_owned(), "true".to_owned()]);
        }

        let request_type = match self.request_type {
            ScillaServerRequestType::Check => "check",
            ScillaServerRequestType::Run => "run",
        };

        let mut params = ObjectParams::new();
        params.insert("argv", args)?;

        Ok((request_type, params))
    }
}

/// The interface to the Scilla interpreter.
#[derive(Debug)]
pub struct Scilla {
    request_tx: Sender<(&'static str, ObjectParams)>,
    response_rx: Mutex<Receiver<Result<Value, ClientError>>>,
    state_server: Arc<Mutex<StateServer>>,
    local_address: String,
    scilla_stdlib_dir: String,
}

impl Scilla {
    /// Create a new Scilla interpreter. This involves spawning two threads:
    /// 1. The client thread, responsible for communicating with the server.
    /// 2. The state IPC thread, responsible for serving state requests from the running Scilla server.
    ///
    /// # Client thread
    ///
    /// This thread starts an event loop which waits for JSON-RPC requests, forwards them to the server and sends the
    /// response back. Communication with the main thread is performed via two MPSC channels (one for requests and one
    /// for responses).
    ///
    /// If the other half of either channel is dropped by the main thread, we terminate.
    ///
    /// # State IPC thread
    ///
    /// This runs a JSON-RPC server at a random port. The address of this server is communicated to the Scilla server
    /// in each request (in the `-ipcaddress` argument). The server is implemented by [StateServer].
    ///
    /// After creating the [StateServer], we wrap it in an `Arc<Mutex<T>>` and send a clone back to the main thread,
    /// to enable shared access to the server.
    pub fn new(address: String, local_address: String, scilla_stdlib_dir: String) -> Scilla {
        let (request_tx, request_rx) = channel();
        let (response_tx, response_rx) = channel();

        thread::spawn(move || {
            let runtime = runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let client = HttpClientBuilder::default()
                .request_timeout(Duration::from_secs(5))
                .build(format!("{address}/run"))
                .unwrap();

            loop {
                let Ok((method, params)) = request_rx.recv() else {
                    break;
                };
                let response = runtime.block_on(client.request(method, params));
                let Ok(()) = response_tx.send(response) else {
                    break;
                };
            }
        });

        let (tx, rx) = channel();
        thread::spawn(move || {
            let runtime = runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            runtime.block_on(async {
                let server = StateServer::new().await.unwrap();
                let handle = server.handle.clone();
                let server = Arc::new(Mutex::new(server));
                tx.send(Arc::clone(&server)).unwrap();
                handle.stopped().await
            });
        });
        let state_server = rx.recv().unwrap();

        Scilla {
            request_tx,
            response_rx: Mutex::new(response_rx),
            state_server,
            local_address,
            scilla_stdlib_dir,
        }
    }

    fn state_server_addr(&self) -> String {
        let local_addr = &self.local_address;
        let addr = self.state_server.lock().unwrap().addr;

        format!("{local_addr}:{}", addr.port())
    }

    pub fn check_contract(
        &self,
        code: &str,
        gas_limit: ScillaGas,
        init: &ContractInit,
        ext_libs_dir: &ScillaExtLibsPathInScilla,
    ) -> Result<Result<CheckOutput, ErrorResponse>> {
        let request = ScillaServerRequestBuilder::new(ScillaServerRequestType::Check)
            .init(init.to_string())
            .lib_dirs(vec![self.scilla_stdlib_dir.clone(), ext_libs_dir.0.clone()])
            .code(code.to_owned())
            .gas_limit(gas_limit)
            .contract_info(true)
            .json_errors(true)
            .is_library(init.is_library()?)
            .build()?;

        self.request_tx.send(request)?;
        let response = self.response_rx.lock().unwrap().recv()?;

        trace!(?response, "check response");

        let response: Value = match response {
            Ok(r) => r,
            Err(ClientError::Call(e)) => serde_json::from_str(e.message())?,
            Err(e) => {
                return Err(anyhow!("{e:?}"));
            }
        };

        // Sometimes Scilla returns a JSON object within a JSON string. Sometimes it doesn't...
        let response = if let Some(response) = response.as_str() {
            serde_json::from_str(response)?
        } else {
            response
        };

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum OutputOrError {
            Err(ErrorResponse),
            Output(CheckOutput),
        }

        match serde_json::from_value(response)? {
            OutputOrError::Err(e) => Ok(Err(e)),
            OutputOrError::Output(response) => Ok(Ok(response)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_contract(
        &self,
        state: PendingState,
        sender: Address,
        code: &str,
        gas_limit: ScillaGas,
        value: ZilAmount,
        init: &ContractInit,
        ext_libs_dir: &ScillaExtLibsPathInScilla,
    ) -> Result<(Result<CreateOutput, ErrorResponse>, PendingState)> {
        let request = ScillaServerRequestBuilder::new(ScillaServerRequestType::Run)
            .ipc_address(self.state_server_addr())
            .init(init.to_string())
            .lib_dirs(vec![self.scilla_stdlib_dir.clone(), ext_libs_dir.0.clone()])
            .code(code.to_owned())
            .gas_limit(gas_limit)
            .balance(value)
            .json_errors(true)
            .is_library(init.is_library()?)
            .build()?;

        let (response, state) =
            self.state_server
                .lock()
                .unwrap()
                .active_call(sender, state, || {
                    self.request_tx.send(request)?;
                    Ok(self.response_rx.lock().unwrap().recv()?)
                })?;

        trace!(?response, "create response");

        let response: Value = match response {
            Ok(r) => r,
            Err(ClientError::Call(e)) => serde_json::from_str(e.message())?,
            Err(e) => {
                return Err(anyhow!("{e:?}"));
            }
        };

        // Sometimes Scilla returns a JSON object within a JSON string. Sometimes it doesn't...
        let response = if let Some(response) = response.as_str() {
            serde_json::from_str(response)?
        } else {
            response
        };

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum OutputOrError {
            Err(ErrorResponse),
            Output(CreateOutput),
        }

        match serde_json::from_value(response)? {
            OutputOrError::Err(e) => Ok((Err(e), state)),
            OutputOrError::Output(response) => Ok((Ok(response), state)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn invoke_contract(
        &self,
        state: PendingState,
        contract: Address,
        code: &str,
        gas_limit: ScillaGas,
        contract_balance: ZilAmount,
        init: &ContractInit,
        msg: &Value,
        ext_libs_dir: &ScillaExtLibsPathInScilla,
    ) -> Result<(Result<InvokeOutput, ErrorResponse>, PendingState)> {
        let request = ScillaServerRequestBuilder::new(ScillaServerRequestType::Run)
            .init(init.to_string())
            .ipc_address(self.state_server_addr())
            .lib_dirs(vec![self.scilla_stdlib_dir.clone(), ext_libs_dir.0.clone()])
            .code(code.to_owned())
            .message(msg)?
            .balance(contract_balance)
            .gas_limit(gas_limit)
            .json_errors(true)
            .pplit(true)
            .build()?;

        let (response, state) =
            self.state_server
                .lock()
                .unwrap()
                .active_call(contract, state, || {
                    self.request_tx.send(request)?;
                    Ok(self.response_rx.lock().unwrap().recv()?)
                })?;

        let response: Value = match response {
            Ok(r) => r,
            Err(ClientError::Call(e)) => serde_json::from_str(e.message())?,
            Err(e) => {
                return Err(anyhow!("{e:?}"));
            }
        };

        trace!("Invoke response: {response}");

        // Sometimes Scilla returns a JSON object within a JSON string. Sometimes it doesn't...
        let response = if let Some(response) = response.as_str() {
            serde_json::from_str(response)?
        } else {
            serde_json::from_value(response)?
        };

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum OutputOrError {
            Err(ErrorResponse),
            Output(InvokeOutput),
        }

        match serde_json::from_value(response)? {
            OutputOrError::Err(e) => Ok((Err(e), state)),
            OutputOrError::Output(response) => Ok((Ok(response), state)),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CheckOutput {
    #[serde(with = "num_as_str")]
    pub gas_remaining: ScillaGas,
    pub contract_info: Option<ContractInfo>, // It's not included in the response for scilla libraries.
}

#[derive(Debug, Deserialize)]
pub struct Error {
    pub start_location: Location,
    pub error_message: String,
}

#[derive(Debug, Deserialize)]
pub struct Location {
    pub line: u64,
}

#[derive(Debug, Deserialize, Default)]
pub struct ContractInfo {
    pub scilla_major_version: String,
    pub fields: Vec<Param>,
    pub transitions: Vec<Transition>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct Transition {
    #[serde(rename = "vname")]
    pub name: String,
    pub params: Vec<TransitionParam>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct TransitionParam {
    #[serde(rename = "vname")]
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Param {
    #[serde(rename = "vname")]
    pub name: String,
    pub depth: u64,
    #[serde(rename = "type")]
    pub ty: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateOutput {
    #[serde(with = "num_as_str")]
    pub gas_remaining: ScillaGas,
}

#[derive(Debug, Deserialize)]
pub struct ErrorResponse {
    pub errors: Vec<Error>,
    #[serde(with = "num_as_str")]
    pub gas_remaining: ScillaGas,
}

#[derive(Debug, Deserialize)]
pub struct InvokeOutput {
    #[serde(rename = "_accepted", with = "bool_as_str")]
    pub accepted: bool,
    #[serde(default)]
    pub messages: Vec<Message>,
    #[serde(default)]
    pub events: Vec<ScillaEvent>,
    #[serde(with = "num_as_str")]
    pub gas_remaining: ScillaGas,
}

#[derive(Debug, Deserialize)]
pub struct ScillaEvent {
    #[serde(rename = "_eventname")]
    pub event_name: String,
    pub params: Vec<ParamValue>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct ParamValue {
    #[serde(rename = "vname")]
    pub name: String,
    pub value: Value,
    #[serde(rename = "type")]
    pub ty: String,
}

impl ParamValue {
    pub fn compute_hash(&self) -> Hash {
        Hash::builder()
            .with(self.ty.as_bytes())
            .with(self.value.to_string().as_bytes())
            .with(self.name.as_bytes())
            .finalize()
    }
}

#[derive(Debug, Deserialize)]
pub struct Message {
    #[serde(rename = "_tag")]
    pub tag: String,
    #[serde(rename = "_amount", with = "num_as_str")]
    pub amount: ZilAmount,
    #[serde(rename = "_recipient")]
    pub recipient: Address,
    pub params: Value,
}

#[derive(Debug)]
struct StateServer {
    addr: SocketAddr,
    handle: ServerHandle,
    /// This should be `Some` when a call is being made to the Scilla server. It stores the current contract address
    /// and state.
    active_call: Arc<Mutex<Option<ActiveCall>>>,
}

impl StateServer {
    async fn new() -> Result<StateServer> {
        let server = jsonrpsee::server::Server::builder()
            .build((Ipv4Addr::UNSPECIFIED, 0))
            .await?;
        let addr = server.local_addr()?;

        let mut module = RpcModule::new(());

        fn de_b64<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
            let b64 = base64::engine::general_purpose::STANDARD;

            let s = String::deserialize(d)?;
            b64.decode(&s)
                .map_err(|_| de::Error::invalid_value(Unexpected::Str(&s), &"a base64 string"))
        }

        fn err(e: impl ToString) -> ErrorObject<'static> {
            ErrorObject::owned(CALL_EXECUTION_FAILED_CODE, e.to_string(), None::<()>)
        }

        let active_call: Arc<Mutex<Option<ActiveCall>>> = Arc::new(Mutex::new(None));

        module.register_method("fetchStateValueB64", {
            let active_call = Arc::clone(&active_call);
            let b64 = base64::engine::general_purpose::STANDARD;
            move |params, (), _| {
                #[derive(Deserialize)]
                struct Params {
                    #[serde(deserialize_with = "de_b64")]
                    query: Vec<u8>,
                }

                let Params { query } = params.parse()?;
                let ProtoScillaQuery { name, indices, .. } =
                    ProtoScillaQuery::decode(query.as_slice()).map_err(err)?;

                let mut active_call = active_call.lock().unwrap();
                let Some(active_call) = active_call.as_mut() else {
                    return Err(err("no active call"));
                };

                let value = active_call.fetch_state_value(name, indices).map_err(err)?;

                let result = match value {
                    Some(v) => vec![true.into(), b64.encode(v.encode_to_vec()).into()],
                    None => vec![false.into(), String::new().into()],
                };

                Ok(Value::Array(result))
            }
        })?;
        module.register_method("fetchExternalStateValueB64", {
            let active_call = Arc::clone(&active_call);
            let b64 = base64::engine::general_purpose::STANDARD;
            move |params, (), _| {
                #[derive(Deserialize)]
                struct Params {
                    addr: Address,
                    #[serde(deserialize_with = "de_b64")]
                    query: Vec<u8>,
                }

                let Params { addr, query } = params.parse()?;
                let ProtoScillaQuery { name, indices, .. } =
                    ProtoScillaQuery::decode(query.as_slice()).map_err(err)?;

                let mut active_call = active_call.lock().unwrap();
                let Some(active_call) = active_call.as_mut() else {
                    return Err(err("no active call"));
                };

                let value = active_call
                    .fetch_external_state_value(addr, name, indices)
                    .map_err(err)?;

                let result = match value {
                    Some((v, ty)) => {
                        vec![true.into(), b64.encode(v.encode_to_vec()).into(), ty.into()]
                    }
                    None => vec![false.into(), String::new().into(), String::new().into()],
                };

                Ok(Value::Array(result))
            }
        })?;
        module.register_method("updateStateValueB64", {
            let active_call = Arc::clone(&active_call);
            move |params, (), _| {
                #[derive(Deserialize)]
                struct Params {
                    #[serde(deserialize_with = "de_b64")]
                    query: Vec<u8>,
                    #[serde(deserialize_with = "de_b64")]
                    value: Vec<u8>,
                }

                let Params { query, value } = params.parse()?;
                let ProtoScillaQuery {
                    name,
                    mapdepth: _,
                    indices,
                    ignoreval,
                } = ProtoScillaQuery::decode(query.as_slice()).map_err(err)?;
                let value = ProtoScillaVal::decode(value.as_slice()).map_err(err)?;

                let mut active_call = active_call.lock().unwrap();
                let Some(active_call) = active_call.as_mut() else {
                    return Err(err("no active call"));
                };

                match active_call.update_state_value(name, indices, ignoreval, value) {
                    Ok(()) => Ok(()),
                    Err(e) => Err(err(e)),
                }
            }
        })?;
        module.register_method("fetchBlockchainInfo", {
            let active_call = Arc::clone(&active_call);
            move |params, (), _| {
                #[derive(Deserialize)]
                struct Params {
                    query_name: String,
                    query_args: String,
                }

                let Params {
                    query_name,
                    query_args,
                } = params.parse()?;

                let mut active_call = active_call.lock().unwrap();
                let Some(active_call) = active_call.as_mut() else {
                    return Err(err("no active call"));
                };

                match active_call.fetch_blockchain_info(query_name, query_args) {
                    Ok((present, value)) => Ok(Value::Array(vec![present.into(), value.into()])),
                    Err(e) => Err(err(e)),
                }
            }
        })?;

        let handle = server.start(module);

        Ok(StateServer {
            addr,
            handle,
            active_call,
        })
    }

    fn active_call<R>(
        &mut self,
        sender: Address, // TODO: rename
        state: PendingState,
        f: impl FnOnce() -> Result<R>,
    ) -> Result<(R, PendingState)> {
        {
            let mut active_call = self.active_call.lock().unwrap();
            *active_call = Some(ActiveCall { sender, state });
        }

        let response = f()?;

        let mut active_call = self.active_call.lock().unwrap();
        let ActiveCall { state, .. } = active_call.take().unwrap();
        Ok((response, state))
    }
}

// Scilla values are stored on disk in a flattened structure. We concatenate the indices that locate a given value.
// Each index is separated by a `0x1F` (ASCII unit separator) byte. This is currently safe, because this byte cannot
// occur in Scilla values, but we include an assertion to make sure this remains true.

// Separate each index with the ASCII unit separator byte.
const SEPARATOR: u8 = 0x1F;

pub fn storage_key(var_name: &str, indices: &[Vec<u8>]) -> Bytes {
    let len = var_name.len() + indices.len() + indices.iter().map(|v| v.len()).sum::<usize>();
    let mut bytes = BytesMut::with_capacity(len);
    bytes.extend_from_slice(var_name.as_bytes());
    for index in indices {
        assert!(!index.contains(&SEPARATOR));
        bytes.put_u8(SEPARATOR);
        bytes.extend_from_slice(index.as_slice());
    }
    bytes.freeze()
}

pub fn split_storage_key(key: impl AsRef<[u8]>) -> Result<(String, Vec<Vec<u8>>)> {
    let mut parts = key.as_ref().split(|b| *b == SEPARATOR);
    let var_name = parts.next().expect("split always returns one element");
    let var_name = String::from_utf8(var_name.to_vec())?;
    let indices = parts.map(|s| s.to_vec()).collect();

    Ok((var_name, indices))
}

#[derive(Debug)]
struct ActiveCall {
    sender: Address,
    state: PendingState,
}

impl ActiveCall {
    fn fetch_value_inner(
        &mut self,
        addr: Address,
        name: String,
        indices: Vec<Vec<u8>>,
    ) -> Result<Option<(ProtoScillaVal, String)>> {
        let (ty, depth) = self.state.load_var_info(addr, &name)?;
        let ty = ty.to_owned();

        if indices.len() > depth as usize {
            return Err(anyhow!("too many indices"));
        }

        let value = if depth as usize == indices.len() {
            let value = self.state.load_storage(addr, &name, &indices)?.clone();
            let Some(value) = value else {
                return Ok(None);
            };
            ProtoScillaVal {
                val_type: Some(ValType::Bval(value.to_vec())),
            }
        } else {
            let value = self.state.load_storage_by_prefix(addr, &name, &indices)?;

            fn convert(value: BTreeMap<Vec<u8>, StorageValue>) -> ProtoScillaVal {
                ProtoScillaVal::map(
                    value
                        .into_iter()
                        .filter_map(|(k, v)| {
                            let k = serde_json::from_slice(&k).ok()?;
                            Some((
                                k,
                                match v {
                                    StorageValue::Map { map, complete } => {
                                        assert!(complete);
                                        convert(map)
                                    }
                                    StorageValue::Value(Some(value)) => {
                                        ProtoScillaVal::bytes(value.into())
                                    }
                                    StorageValue::Value(None) => {
                                        return None;
                                    }
                                },
                            ))
                        })
                        .collect(),
                )
            }

            convert(value)
        };

        Ok(Some((value, ty)))
    }

    fn fetch_state_value(
        &mut self,
        name: String,
        indices: Vec<Vec<u8>>,
    ) -> Result<Option<ProtoScillaVal>> {
        Ok(self
            .fetch_value_inner(self.sender, name, indices)?
            .map(|(v, _)| v))
    }

    fn fetch_external_state_value(
        &mut self,
        addr: Address,
        name: String,
        indices: Vec<Vec<u8>>,
    ) -> Result<Option<(ProtoScillaVal, String)>> {
        fn scilla_val(b: Vec<u8>) -> ProtoScillaVal {
            ProtoScillaVal {
                val_type: Some(ValType::Bval(b)),
            }
        }

        let account = self.state.load_account(addr)?;
        match name.as_str() {
            "_balance" => {
                let balance = ZilAmount::from_amount(account.account.balance);
                let val = scilla_val(format!("\"{balance}\"").into_bytes());
                Ok(Some((val, "Uint128".to_owned())))
            }
            "_nonce" => {
                let val = scilla_val(format!("\"{}\"", account.account.nonce + 1).into_bytes());
                Ok(Some((val, "Uint64".to_owned())))
            }
            "_this_address" => {
                let val = scilla_val(format!("\"0x{:#x}\"", addr).into_bytes());
                Ok(Some((val, "ByStr20".to_owned())))
            }
            "_codehash" => {
                let code_bytes = match &account.account.code {
                    Code::Evm(bytes) => bytes.clone(),
                    Code::Scilla { code, .. } => code.clone().into_bytes(),
                };

                let mut hasher = Sha256::new();
                DynDigest::update(&mut hasher, &code_bytes);

                let mut hash = [0u8; 32];
                DynDigest::finalize_into(hasher, &mut hash[..]).unwrap();

                let val = scilla_val(format!("\"0x{}\"", hash.encode_hex()).into_bytes());
                Ok(Some((val, "ByStr32".to_owned())))
            }
            _ => self.fetch_value_inner(addr, name.clone(), indices.clone()),
        }
    }

    fn update_state_value(
        &mut self,
        name: String,
        indices: Vec<Vec<u8>>,
        ignore_value: bool,
        value: ProtoScillaVal,
    ) -> Result<()> {
        let (_, depth) = self.state.load_var_info(self.sender, &name)?;
        let depth = depth as usize;

        if indices.len() > depth {
            return Err(anyhow!("too many indices"));
        }

        if ignore_value {
            // We only supporting deleting a single value of a map.
            assert_eq!(indices.len(), depth);
            let storage_slot = self.state.load_storage(self.sender, &name, &indices)?;
            *storage_slot = None;
        } else if indices.len() == depth {
            let Some(ValType::Bval(value)) = value.val_type else {
                return Err(anyhow!("invalid value"));
            };
            let storage_slot = self.state.load_storage(self.sender, &name, &indices)?;
            *storage_slot = Some(value.into());
        } else {
            fn convert(value: ProtoScillaVal) -> Result<StorageValue> {
                let Some(value) = value.val_type else {
                    return Err(anyhow!("missing val_type"));
                };
                match value {
                    ValType::Bval(bytes) => Ok(StorageValue::Value(Some(bytes.into()))),
                    ValType::Mval(scilla_proto::Map { m }) => {
                        let map = m
                            .into_iter()
                            .map(|(k, v)| Ok((k.into_bytes(), convert(v)?)))
                            .collect::<Result<_>>()?;
                        Ok(StorageValue::Map {
                            map,
                            // Note that we mark the map as complete here. The field has been fully overridden and any
                            // existing values should be deleted.
                            complete: true,
                        })
                    }
                }
            }

            self.state
                .set_storage(self.sender, &name, &indices, convert(value)?)?;
        }

        Ok(())
    }

    fn fetch_blockchain_info(&self, name: String, args: String) -> Result<(bool, String)> {
        match name.as_str() {
            "CHAINID" => Ok((true, self.state.zil_chain_id().to_string())),
            "BLOCKNUMBER" => match self.state.get_highest_canonical_block_number()? {
                Some(block_number) => Ok((true, block_number.to_string())),
                None => Ok((false, "".to_string())),
            },
            "BLOCKHASH" => {
                let block_number: u64 = args.parse()?;
                match self.state.get_canonical_block_by_number(block_number)? {
                    Some(block) => Ok((true, block.hash().to_string())),
                    None => Ok((false, "".to_string())),
                }
            }
            "TIMESTAMP" => {
                let block_number: u64 = args.parse()?;
                match self.state.get_canonical_block_by_number(block_number)? {
                    Some(block) => Ok((
                        true,
                        block
                            .timestamp()
                            .duration_since(SystemTime::UNIX_EPOCH)?
                            .as_micros()
                            .to_string(),
                    )),
                    None => Ok((false, "".to_string())),
                }
            }
            _ => Err(anyhow!(
                "fetch_blockchain_info: `{name}` not implemented yet."
            )),
        }
    }
}
