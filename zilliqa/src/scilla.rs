mod output;
mod request;
mod state_server;

use std::{
    str,
    sync::{
        Arc, Mutex,
        mpsc::{Receiver, Sender, channel},
    },
    thread,
    time::Duration,
};

use alloy::primitives::Address;
use anyhow::{Result, anyhow};
use bytes::{BufMut, Bytes, BytesMut};
use jsonrpsee::{
    core::{ClientError, client::ClientT, params::ObjectParams},
    http_client::HttpClientBuilder,
};
pub use output::{
    CheckOutput, ContractInfo, CreateOutput, Error, ErrorResponse, InvokeOutput, Location, Message,
    Param, ParamValue, ScillaEvent, Transition, TransitionParam,
};
use request::{ScillaServerRequestBuilder, ScillaServerRequestType};
use serde::Deserialize;
use serde_json::Value;
use state_server::StateServer;
use tokio::runtime;
use tracing::trace;

use crate::{
    cfg::{Fork, ScillaExtLibsPathInScilla},
    exec::PendingState,
    state::ContractInit,
    transaction::{ScillaGas, ZilAmount},
};

#[derive(Debug)]
pub struct Scilla {
    request_tx: Sender<(&'static str, ObjectParams)>,
    response_rx: Mutex<Receiver<Result<Value, ClientError>>>,
    state_server: Arc<Mutex<StateServer>>,
    scilla_stdlib_dir: String,
}

impl Scilla {
    const MAX_ATTEMPTS: u8 = 3;
    const REQ_TIMEOUT: Duration = Duration::from_secs(600);

    pub fn new(address: String, socket_dir: String, scilla_stdlib_dir: String) -> Scilla {
        let (request_tx, request_rx) = channel();
        let (response_tx, response_rx) = channel();

        thread::spawn(move || {
            let runtime = runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let client = HttpClientBuilder::default()
                .request_timeout(Self::REQ_TIMEOUT)
                .build(format!("{address}/run"))
                .unwrap();

            while let Ok((method, params)) = request_rx.recv() {
                let response = runtime.block_on(client.request(method, params));
                if response_tx.send(response).is_err() {
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
                let server = StateServer::new(&socket_dir).await.unwrap();
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
            scilla_stdlib_dir,
        }
    }

    fn state_server_addr(&self) -> String {
        self.state_server.lock().unwrap().endpoint.clone()
    }

    pub fn check_contract(
        &self,
        code: &str,
        gas_limit: ScillaGas,
        init: &ContractInit,
        ext_libs_dir: &ScillaExtLibsPathInScilla,
    ) -> Result<Result<CheckOutput, ErrorResponse>> {
        let mut attempt = 1;
        let response = loop {
            let request = ScillaServerRequestBuilder::new(ScillaServerRequestType::Check)
                .init(init.to_string())
                .lib_dirs(vec![self.scilla_stdlib_dir.clone(), ext_libs_dir.0.clone()])
                .code(code.to_owned())
                .gas_limit(gas_limit)
                .contract_info(true)
                .json_errors(true)
                .is_library(init.is_library()?)
                .build()?;

            tracing::debug!(%attempt,"Check attempt");
            self.request_tx.send(request)?;
            let response = self.response_rx.lock().unwrap().recv()?;

            match response {
                Ok(r) => break r,
                Err(ClientError::Call(e)) => break serde_json::from_str(e.message())?,
                Err(ClientError::RequestTimeout) if attempt < Self::MAX_ATTEMPTS => {
                    tracing::warn!(%attempt, "Check retry");
                    attempt += 1;
                }
                Err(e) => {
                    return Err(anyhow!("{e:?}"));
                }
            };
        };

        trace!(?response, "Check response");

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
        fork: &Fork,
        current_block: u64,
    ) -> Result<(Result<CreateOutput, ErrorResponse>, PendingState)> {
        let mut attempt = 1;
        let (response, state) = loop {
            let pending_state = state.clone();

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

            tracing::debug!(number=%current_block, %sender, %attempt,"Create attempt");
            let (response, state) = self.state_server.lock().unwrap().active_call(
                sender,
                pending_state,
                current_block,
                fork,
                || {
                    self.request_tx.send(request)?;
                    Ok(self.response_rx.lock().unwrap().recv()?)
                },
            )?;

            match response {
                Ok(r) => break (r, state),
                Err(ClientError::Call(e)) => break (serde_json::from_str(e.message())?, state),
                Err(ClientError::RequestTimeout) if attempt < Self::MAX_ATTEMPTS => {
                    tracing::warn!(number=%current_block, %sender, %attempt, "Create retry");
                    attempt += 1;
                }
                Err(e) => {
                    return Err(anyhow!("{e:?}"));
                }
            };
        };

        trace!(?response, "Create response");

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
    fn invoke_request(
        &self,
        code: &str,
        gas_limit: ScillaGas,
        contract_balance: ZilAmount,
        init: &ContractInit,
        msg: &Value,
        ext_libs_dir: &ScillaExtLibsPathInScilla,
    ) -> Result<(&'static str, ObjectParams)> {
        ScillaServerRequestBuilder::new(ScillaServerRequestType::Run)
            .init(init.to_string())
            .ipc_address(self.state_server_addr())
            .lib_dirs(vec![self.scilla_stdlib_dir.clone(), ext_libs_dir.0.clone()])
            .code(code.to_owned())
            .message(msg)?
            .balance(contract_balance)
            .gas_limit(gas_limit)
            .json_errors(true)
            .pplit(true)
            .build()
    }

    fn parse_invoke_response(
        response: Value,
        fork: &Fork,
    ) -> Result<Result<InvokeOutput, ErrorResponse>> {
        trace!(?response, "Invoke response");

        let mut response: Value = if let Some(response) = response.as_str() {
            serde_json::from_str(response)?
        } else {
            serde_json::from_value(response)?
        };
        if !fork.scilla_json_preserve_order {
            response.sort_all_objects();
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum OutputOrError {
            Err(ErrorResponse),
            Output(InvokeOutput),
        }

        match serde_json::from_value(response)? {
            OutputOrError::Err(e) => Ok(Err(e)),
            OutputOrError::Output(response) => Ok(Ok(response)),
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
        fork: &Fork,
        current_block: u64,
    ) -> Result<(Result<InvokeOutput, ErrorResponse>, PendingState)> {
        let mut attempt = 1;
        let (response, state) = loop {
            let pending_state = state.clone();

            let request =
                self.invoke_request(code, gas_limit, contract_balance, init, msg, ext_libs_dir)?;

            tracing::debug!(number=%current_block, %contract, %attempt,"Invoke attempt");
            let (response, state) = self.state_server.lock().unwrap().active_call(
                contract,
                pending_state,
                current_block,
                fork,
                || {
                    self.request_tx.send(request)?;
                    Ok(self.response_rx.lock().unwrap().recv()?)
                },
            )?;

            match response {
                Ok(r) => break (r, state),
                Err(ClientError::Call(e)) => break (serde_json::from_str(e.message())?, state),
                Err(ClientError::RequestTimeout) if attempt < Self::MAX_ATTEMPTS => {
                    tracing::warn!(number=%current_block, %contract, %attempt, "Invoke retry");
                    attempt += 1;
                }
                Err(e) => return Err(anyhow!("{e:?}")),
            };
        };

        Ok((Self::parse_invoke_response(response, fork)?, state))
    }
}

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
