use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    sync::{Arc, Mutex},
};

use alloy::{hex::ToHexExt, primitives::Address};
use anyhow::{Result, anyhow};
use base64::Engine;
use jsonrpsee::{
    IntoResponse, MethodCallback, MethodResponse, RpcModule,
    core::RegisterMethodError,
    server::ServerHandle,
    types::{ErrorObject, Params, error::CALL_EXECUTION_FAILED_CODE},
};
use prost::Message as _;
use rand::{Rng, distributions::Alphanumeric};
use revm::primitives::BLOCK_HASH_HISTORY;
use serde::{
    Deserialize, Deserializer,
    de::{self, Unexpected},
};
use serde_json::Value;
use sha2::Sha256;
use sha3::{Digest, digest::DynDigest};

use crate::{
    cfg::Fork,
    exec::{PendingState, StorageValue},
    scilla_proto::{self, ProtoScillaQuery, ProtoScillaVal, ValType},
    state::Code,
    time::SystemTime,
    transaction::ZilAmount,
};

#[derive(Debug)]
pub(super) struct StateServer {
    pub(super) endpoint: String,
    pub(super) handle: ServerHandle,
    active_call: Arc<Mutex<Option<ActiveCall>>>,
}

impl StateServer {
    pub(super) async fn new(socket_dir: &str) -> Result<StateServer> {
        fs::create_dir_all(socket_dir)?;
        let mut path = "scilla-state-server-".to_owned();
        let suffix: String = rand::thread_rng()
            .sample_iter(Alphanumeric)
            .take(6)
            .map(char::from)
            .collect();
        path.push_str(&suffix);
        let endpoint = Path::new(socket_dir)
            .join(path)
            .to_str()
            .unwrap()
            .to_owned();

        let server = reth_ipc::server::Builder::default()
            .max_response_body_size(1024 * 1024 * 1024)
            .build(endpoint.clone());

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

        fn register_method<F>(
            module: &mut RpcModule<()>,
            active_call: Arc<Mutex<Option<ActiveCall>>>,
            method_name: &'static str,
            callback: F,
        ) -> Result<(), RegisterMethodError>
        where
            F: Fn(Params<'_>, &mut ActiveCall) -> Result<Value, ErrorObject<'static>>
                + Send
                + Sync
                + 'static,
        {
            module.verify_and_insert(
                method_name,
                MethodCallback::Sync(Arc::new(
                    move |id, params, max_response_size, extensions| {
                        let mut active_call = active_call.lock().unwrap();

                        let Some(active_call) = active_call.as_mut() else {
                            return MethodResponse::response::<()>(
                                id,
                                Err(err("no active call")).into_response(),
                                max_response_size,
                            )
                            .with_extensions(extensions);
                        };

                        let max_response_size = if active_call.scilla_server_unlimited_response_size
                        {
                            max_response_size
                        } else {
                            10 * 1024 * 1024
                        };

                        let rp = callback(params, active_call).into_response();
                        MethodResponse::response(id, rp, max_response_size)
                            .with_extensions(extensions)
                    },
                )),
            )?;
            Ok(())
        }

        register_method(
            &mut module,
            Arc::clone(&active_call),
            "fetchStateValueB64",
            |params, active_call| {
                let b64 = base64::engine::general_purpose::STANDARD;
                #[derive(Deserialize)]
                struct Params {
                    #[serde(deserialize_with = "de_b64")]
                    query: Vec<u8>,
                }

                let Params { query } = params.parse()?;
                let ProtoScillaQuery { name, indices, .. } =
                    ProtoScillaQuery::decode(query.as_slice()).map_err(err)?;

                let value = active_call.fetch_state_value(name, indices).map_err(err)?;

                let result = match value {
                    Some(v) => vec![true.into(), b64.encode(v.encode_to_vec()).into()],
                    None => vec![false.into(), String::new().into()],
                };

                Ok(Value::Array(result))
            },
        )?;

        register_method(
            &mut module,
            Arc::clone(&active_call),
            "fetchExternalStateValueB64",
            |params, active_call| {
                let b64 = base64::engine::general_purpose::STANDARD;
                #[derive(Deserialize)]
                struct Params {
                    addr: Address,
                    #[serde(deserialize_with = "de_b64")]
                    query: Vec<u8>,
                }

                let Params { addr, query } = params.parse()?;
                let ProtoScillaQuery { name, indices, .. } =
                    ProtoScillaQuery::decode(query.as_slice()).map_err(err)?;

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
            },
        )?;
        register_method(
            &mut module,
            Arc::clone(&active_call),
            "updateStateValueB64",
            |params, active_call| {
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

                match active_call.update_state_value(name, indices, ignoreval, value) {
                    Ok(()) => Ok(Value::Null),
                    Err(e) => Err(err(e)),
                }
            },
        )?;
        register_method(
            &mut module,
            Arc::clone(&active_call),
            "fetchBlockchainInfo",
            |params, active_call| {
                #[derive(Deserialize)]
                struct Params {
                    query_name: String,
                    query_args: String,
                }

                let Params {
                    query_name,
                    query_args,
                } = params.parse()?;

                match active_call.fetch_blockchain_info(query_name, query_args) {
                    Ok((present, value)) => Ok(Value::Array(vec![present.into(), value.into()])),
                    Err(e) => Err(err(e)),
                }
            },
        )?;

        let handle = server.start(module).await?;

        Ok(StateServer {
            endpoint,
            handle,
            active_call,
        })
    }

    pub(super) fn active_call<R>(
        &mut self,
        sender: Address,
        state: PendingState,
        current_block: u64,
        fork: &Fork,
        f: impl FnOnce() -> Result<R>,
    ) -> Result<(R, PendingState)> {
        {
            let mut active_call = self.active_call.lock().unwrap();
            *active_call = Some(ActiveCall {
                sender,
                state,
                current_block,
                scilla_block_number_returns_current_block: fork
                    .scilla_block_number_returns_current_block,
                scilla_maps_are_encoded_correctly: fork.scilla_maps_are_encoded_correctly,
                scilla_server_unlimited_response_size: fork.scilla_server_unlimited_response_size,
            });
        }

        let response = f()?;

        let mut active_call = self.active_call.lock().unwrap();
        let ActiveCall { state, .. } = active_call.take().unwrap();
        Ok((response, state))
    }
}

#[derive(Debug)]
struct ActiveCall {
    sender: Address,
    state: PendingState,
    current_block: u64,
    scilla_block_number_returns_current_block: bool,
    scilla_maps_are_encoded_correctly: bool,
    scilla_server_unlimited_response_size: bool,
}

fn convert_map(
    scilla_maps_are_encoded_correctly: bool,
    value: BTreeMap<Vec<u8>, StorageValue>,
) -> ProtoScillaVal {
    ProtoScillaVal::map(
        value
            .into_iter()
            .filter_map(|(k, v)| {
                let k = if scilla_maps_are_encoded_correctly {
                    String::from_utf8(k).unwrap()
                } else {
                    serde_json::from_slice(&k).ok()?
                };
                Some((
                    k,
                    match v {
                        StorageValue::Map { map, complete } => {
                            assert!(complete);
                            convert_map(scilla_maps_are_encoded_correctly, map)
                        }
                        StorageValue::Value(Some(value)) => ProtoScillaVal::bytes(value.into()),
                        StorageValue::Value(None) => {
                            return None;
                        }
                    },
                ))
            })
            .collect(),
    )
}

fn scilla_val(b: Vec<u8>) -> ProtoScillaVal {
    ProtoScillaVal {
        val_type: Some(ValType::Bval(b)),
    }
}

fn codehash_val(code_bytes: &[u8]) -> ProtoScillaVal {
    let mut hasher = Sha256::new();
    DynDigest::update(&mut hasher, code_bytes);

    let mut hash = [0u8; 32];
    DynDigest::finalize_into(hasher, &mut hash[..]).unwrap();

    scilla_val(format!("\"0x{}\"", hash.encode_hex()).into_bytes())
}

fn proto_to_storage_value(value: ProtoScillaVal) -> Result<StorageValue> {
    let Some(value) = value.val_type else {
        return Err(anyhow!("missing val_type"));
    };
    match value {
        ValType::Bval(bytes) => Ok(StorageValue::Value(Some(bytes.into()))),
        ValType::Mval(scilla_proto::Map { m }) => {
            let map = m
                .into_iter()
                .map(|(k, v)| Ok((k.into_bytes(), proto_to_storage_value(v)?)))
                .collect::<Result<_>>()?;
            Ok(StorageValue::Map {
                map,
                complete: true,
            })
        }
    }
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
            let mut value = self.state.load_storage_by_prefix(addr, &name, &indices)?;

            if self.scilla_maps_are_encoded_correctly {
                for index in &indices {
                    if let Some(StorageValue::Map { map: inner_map, .. }) = value.remove(index) {
                        value = inner_map;
                    } else {
                        break;
                    }
                }
            }

            convert_map(self.scilla_maps_are_encoded_correctly, value)
        };

        Ok(Some((value, ty)))
    }

    fn fetch_state_value(
        &mut self,
        name: String,
        indices: Vec<Vec<u8>>,
    ) -> Result<Option<ProtoScillaVal>> {
        let result = self
            .fetch_value_inner(self.sender, name, indices)?
            .map(|(v, _)| v);
        Ok(result)
    }

    fn fetch_external_state_value(
        &mut self,
        addr: Address,
        name: String,
        indices: Vec<Vec<u8>>,
    ) -> Result<Option<(ProtoScillaVal, String)>> {
        let account = self.state.load_account(addr)?;
        let result = match name.as_str() {
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
                let val = scilla_val(format!("\"0x{addr:#x}\"").into_bytes());
                Ok(Some((val, "ByStr20".to_owned())))
            }
            "_codehash" => {
                let code_bytes = match &account.account.code {
                    Code::Evm(bytes) => bytes.clone(),
                    Code::Scilla { code, .. } => code.clone().into_bytes(),
                };
                Ok(Some((codehash_val(&code_bytes), "ByStr32".to_owned())))
            }
            _ => self.fetch_value_inner(addr, name.clone(), indices.clone()),
        }?;

        Ok(result)
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
            assert!(indices.len() <= depth);
            if indices.len() == depth {
                let storage_slot = self.state.load_storage(self.sender, &name, &indices)?;
                *storage_slot = None;
            } else {
                self.state.set_storage(
                    self.sender,
                    &name,
                    &indices,
                    StorageValue::complete_map(),
                )?;
            }
        } else if indices.len() == depth {
            let Some(ValType::Bval(value)) = value.val_type else {
                return Err(anyhow!("invalid value"));
            };
            let storage_slot = self.state.load_storage(self.sender, &name, &indices)?;
            *storage_slot = Some(value.into());
        } else {
            self.state
                .set_storage(self.sender, &name, &indices, proto_to_storage_value(value)?)?;
        }
        self.state.touch(self.sender);

        Ok(())
    }

    fn fetch_blockchain_info(&self, name: String, args: String) -> Result<(bool, String)> {
        let (exists, value) = match name.as_str() {
            "CHAINID" => Ok((true, self.state.zil_chain_id().to_string())),
            "BLOCKNUMBER" => {
                if self.scilla_block_number_returns_current_block {
                    Ok((true, self.current_block.to_string()))
                } else {
                    Ok((true, self.current_block.saturating_sub(1).to_string()))
                }
            }
            "BLOCKHASH" => {
                let block_number = args.parse()?;
                let Some(diff) = self.current_block.checked_sub(block_number) else {
                    return Ok((false, "".to_string()));
                };
                if diff == 0 {
                    return Ok((false, "".to_string()));
                }
                if diff <= BLOCK_HASH_HISTORY {
                    return Ok((false, "".to_string()));
                }
                match self.state.get_canonical_block_by_number(block_number)? {
                    Some(block) => Ok((true, block.hash().to_string())),
                    None => Ok((false, "".to_string())),
                }
            }
            "TIMESTAMP" => {
                let block_number = args.parse()?;
                let Some(diff) = self.current_block.checked_sub(block_number) else {
                    return Ok((false, "".to_string()));
                };
                if diff == 0 {
                    return Ok((false, "".to_string()));
                }
                if diff > BLOCK_HASH_HISTORY {
                    return Ok((false, "".to_string()));
                }
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
        }?;
        Ok((exists, value))
    }
}
