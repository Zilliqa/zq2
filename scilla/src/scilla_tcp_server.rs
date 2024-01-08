use tracing::*;
use evm::{
    backend::{Backend}};

//use base
use std::{
    collections::HashMap,
    str,
    sync::{Arc, Mutex},
};

use prost::Message;
use crate::backend_collector::BackendCollector;
use crate::call_scilla_server::JsonRpcRequest;
use base64::Engine;

use serde_json::json;
use anyhow::{anyhow, Result};
use futures::{future, FutureExt};
use jsonrpc_core::{BoxFuture, IoHandler, Params};
use primitive_types::{H160, H256};
use serde_json::Value;
use tracing::field::debug;

use crate::{
    //db::Db,
    proto::{
        proto_scilla_val::{self, ValType},
        ProtoScillaQuery, ProtoScillaVal,
    },
    //Account, TxBlock,
};

pub struct ScillaServer<'a, B: evm::backend::Backend> {
    pub inner: Inner<'a, B>,
    pub _tcp_server: IoHandler,
}

pub struct Inner<'a, B: evm::backend::Backend> {
    pub backend: BackendCollector<'a, B>,
    current_contract_addr: Option<(H160, H256, u64)>,
}

impl<'a, B: evm::backend::Backend> ScillaServer<'a, B> {

    pub fn handle_request(&mut self, request: JsonRpcRequest) -> Result<Value, jsonrpc_core::Error> {
        //let response = self._tcp_server.handle_request_sync(&request);

        //self.inner.set_current_contract_addr(request.contract_addr, request.state_root, request.block_number);

        match request.method.as_str() {
            //"fetchStateValueB64" => {
            //    let response = self.fetch_state_value_b64(request.params);
            //    Ok(response)
            //},
            //"fetchExternalStateValueB64" => {
            //    let response = self.fetch_external_state_value_b64(request.params);
            //    Ok(response)
            //},
            //"updateStateValueB64" => {
            //    let response = self.update_state_value_b64(request.params);
            //    Ok(response)
            //},
            "updateStateValue" => {
                self.inner.update_state_value_b64(request.params)

                //Ok(response)
            },
            //"fetchBlockchainInfo" => {
            //    let response = self.fetch_blockchain_info(request.params);
            //    Ok(response)
            //},
            _ => {
                //Err(anyhow!("method not listed.").into())
                Err(jsonrpc_core::Error::invalid_request())
                //Ok("asdfa".to_string())
            }
        }

        //Ok("asdfa".to_string())
    }

//
//    pub fn setup(&mut self) {
//
//        self._tcp_server.add_method("fetchStateValueB64", |params| {
//            //let inner = Arc::clone(&inner);
//            //move |params| inner.lock().unwrap().fetch_state_value_b64(params)
//
//            debug!("* fetchStateValueB64 called with params: {:?}", params);
//            future::ready(Ok(json!(true))).boxed()
//        });
//        self._tcp_server.add_method("fetchExternalStateValueB64", |params| {
//            //let inner = Arc::clone(&inner);
//            //move |params| inner.lock().unwrap().fetch_external_state_value_b64(params)
//            debug!("* fetchExternalStateValueB64 called with params: {:?}", params);
//            future::ready(Ok(json!(true))).boxed()
//        });
//        self._tcp_server.add_method("updateStateValueB64", |params| {
//            //let inner = Arc::clone(&inner);
//            debug!("* updateStateValueB64 called with params: {:?}", params);
//            //move |params| inner.lock().unwrap().update_state_value_b64(params)
//            future::ready(Ok(json!(true))).boxed()
//        });
//
//        //let inner_ref = &self.inner;
//        //let inner_arc = Arc::new(Mutex::new(&mut self.inner));
//        let cloned_arc = Arc::clone(&self.inner);
//
//        //self._tcp_server.add_method("updateStateValue", |params| self.inner.update_state_value_b64_nomut(params));
//
//        self._tcp_server.add_method("updateStateValue", |params| {
//            debug!("* updateStateValue called with params: {:?}", params);
//
//            // nathan
//            let inner_arc = Arc::clone(&cloned_arc);
//            move |params| inner_arc.lock().unwrap().update_state_value_b64(params);
//
//            future::ready(Ok(json!(true))).boxed()
//        });
//
//        self._tcp_server.add_method("fetchBlockchainInfo", |params| {
//            //let inner = Arc::clone(&inner);
//            //move |params| inner.lock().unwrap().fetch_blockchain_info(params)
//            debug!("* fetchBlockchainInfo called with params: {:?}", params);
//            future::ready(Ok(json!(true))).boxed()
//        });
//
//    }
//
    pub fn new(backend: BackendCollector<'a, B>) -> ScillaServer<'a, B> {
        //let inner = Inner {
        //    db,
        //    current_contract_addr: None,
        //};
        //let inner = Arc::new(Mutex::new(Inner { backend, }));
        let inner = Inner { backend: backend, current_contract_addr: None };
        let mut _tcp_server = IoHandler::new();

        //let inner_arc = Arc::new(Mutex::new(inner));

        //let _ipc_server = ServerBuilder::new(io)
        //    .request_separators(Separator::Byte(b'\n'), Separator::Byte(b'\n'))
        //    .start("/tmp/stateipc.sock")
        //    .unwrap();

        ScillaServer { inner: inner, _tcp_server: _tcp_server }
    }
//
//    //pub fn set_current_contract_addr(&self, addr: H160, state_root: H256, block_number: u64) {
//    //    self.inner.lock().unwrap().current_contract_addr = Some((addr, state_root, block_number));
//    //}
//
//    //pub fn reset_current_contract_addr(&self) -> H256 {
//    //    let (_, state_root, _) = self
//    //        .inner
//    //        .lock()
//    //        .unwrap()
//    //        .current_contract_addr
//    //        .take()
//    //        .unwrap();
//    //    state_root
//    //}
}
//
impl<'a, B: evm::backend::Backend> Inner<'a, B> {
    //fn fetch_state_value_b64(
    //    &mut self,
    //    params: Params,
    //) -> BoxFuture<Result<Value, jsonrpc_core::Error>> {
    //    fn err(s: &'static str) -> BoxFuture<Result<Value, jsonrpc_core::Error>> {
    //        futures::future::ready(Err(jsonrpc_core::Error::invalid_params(s))).boxed()
    //    }

    //    let b64 = base64::engine::general_purpose::STANDARD;

    //    let Params::Map(params) = params else { return err("expected a map"); };
    //    let Some(query) = params.get("query") else { return err("expected query in map"); };
    //    let Some(query) = query.as_str().map(str::to_owned) else { return err("query was not a string"); };
    //    let Ok(query) = b64.decode(query) else { return err("query was not base64"); };
    //    let Ok(query) = ProtoScillaQuery::decode(query.as_slice()) else { return err("could not parse query"); };

    //    let result = self.fetch_state_value_inner(query).map_err(convert_err);

    //    let result = result.map(|value| {
    //        let arr = match value {
    //            Some(value) => vec![true.into(), b64.encode(value.encode_to_vec()).into()],
    //            None => vec![false.into(), String::new().into()],
    //        };
    //        Value::Array(arr)
    //    });

    //    future::ready(result).boxed()
    //}

    //fn fetch_state_value_inner(
    //    &mut self,
    //    query: ProtoScillaQuery,
    //) -> Result<Option<ProtoScillaVal>> {
    //    trace!("Fetch state value: {query:?}");

    //    if ["_addr", "_version", "_depth", "_type", "_hasmap"].contains(&query.name.as_str()) {
    //        return Err(anyhow!("reserved variable name: {}", query.name));
    //    }

    //    let Some((addr, _, _)) = self.current_contract_addr else { return Err(anyhow!("no current contract")); };

    //    let addr_hex = format!("{addr:x}");
    //    let mut key = format!("{}\x16{}\x16", addr_hex, query.name);
    //    for index in &query.indices {
    //        key.push_str(str::from_utf8(index)?);
    //        key.push('\x16');
    //    }

    //    let value = match query.indices.len().cmp(&(query.mapdepth as usize)) {
    //        std::cmp::Ordering::Greater => {
    //            return Err(anyhow!("indices is deeper than map depth"));
    //        }
    //        std::cmp::Ordering::Equal => {
    //            // Result will not be a map and can be just fetched into the store
    //            let bytes = self.db.lock().unwrap().get_contract_state_data(&key)?;

    //            let Some(bytes) = bytes else { return Ok(None); };

    //            ProtoScillaVal {
    //                val_type: Some(ValType::Bval(bytes)),
    //            }
    //        }
    //        std::cmp::Ordering::Less => {
    //            // We're fetching a map value. We need to iterate through the DB lexicographically.
    //            let mut entries = HashMap::new();

    //            let existing_entries: Vec<_> = self
    //                .db
    //                .lock()
    //                .unwrap()
    //                .get_contract_state_data_with_prefix(&key)
    //                .collect();
    //            if existing_entries.is_empty() && !query.indices.is_empty() {
    //                return Ok(None);
    //            }
    //            for kv in existing_entries {
    //                let (k, v) = kv?;
    //                entries.insert(k, v);
    //            }

    //            let mut val = ProtoScillaVal {
    //                val_type: Some(ValType::Mval(proto_scilla_val::Map { m: HashMap::new() })),
    //            };
    //            for (k, v) in entries {
    //                let key_non_prefix = k
    //                    .strip_prefix(&key)
    //                    .ok_or_else(|| anyhow!("{key} is not a prefix of {k}"))?;
    //                let indices: Vec<_> = key_non_prefix.split_terminator('\x16').collect();

    //                let mut val_ref = &mut val;
    //                for index in &indices {
    //                    let Some(ValType::Mval(proto_scilla_val::Map { ref mut m })) = val_ref.val_type else { unreachable!(); };
    //                    val_ref = m.entry((*index).to_owned()).or_insert(ProtoScillaVal {
    //                        val_type: Some(ValType::Mval(Default::default())),
    //                    });
    //                }

    //                if query.indices.len() + indices.len() < query.mapdepth as usize {
    //                    // Assert that we have a protobuf-encoded empty map.
    //                    let empty_map = ProtoScillaVal::decode(v.as_slice())?;
    //                    match empty_map.val_type {
    //                        Some(ValType::Mval(map)) if map.m.is_empty() => {}
    //                        _ => {
    //                            return Err(anyhow!("Expected protobuf encoded empty map since entry has fewer keys than mapdepth"));
    //                        }
    //                    }
    //                    *val_ref = ProtoScillaVal {
    //                        val_type: Some(ValType::Mval(Default::default())),
    //                    };
    //                } else {
    //                    *val_ref = ProtoScillaVal {
    //                        val_type: Some(ValType::Bval(v)),
    //                    };
    //                }
    //            }
    //            val
    //        }
    //    };

    //    Ok(Some(value))
    //}

    //fn fetch_external_state_value_b64(
    //    &mut self,
    //    params: Params,
    //) -> BoxFuture<Result<Value, jsonrpc_core::Error>> {
    //    fn err(s: &'static str) -> BoxFuture<Result<Value, jsonrpc_core::Error>> {
    //        futures::future::ready(Err(jsonrpc_core::Error::invalid_params(s))).boxed()
    //    }

    //    let b64 = base64::engine::general_purpose::STANDARD;

    //    let Params::Map(params) = params else { return err("expected a map"); };
    //    let Some(addr) = params.get("addr") else { return err("expected addr in map"); };
    //    let Some(addr) = addr.as_str().map(str::to_owned) else { return err("addr was not a string"); };
    //    let Ok(addr) = addr.parse::<H160>() else { return err("addr parsing failed"); };
    //    let Some(query) = params.get("query") else { return err("expected query in map"); };
    //    let Some(query) = query.as_str().map(str::to_owned) else { return err("query was not a string"); };
    //    let Ok(query) = b64.decode(query) else { return err("query was not base64"); };

    //    let result = self
    //        .fetch_external_state_value_inner(addr, query)
    //        .map_err(convert_err);

    //    let result = result.map(|vt| {
    //        let arr = match vt {
    //            Some((value, ty)) => vec![
    //                true.into(),
    //                b64.encode(value.encode_to_vec()).into(),
    //                ty.into(),
    //            ],
    //            None => vec![false.into(), String::new().into(), String::new().into()],
    //        };
    //        Value::Array(arr)
    //    });

    //    future::ready(result).boxed()
    //}

    //fn fetch_external_state_value_inner(
    //    &mut self,
    //    addr: H160,
    //    query: Vec<u8>,
    //) -> Result<Option<(ProtoScillaVal, String)>> {
    //    let mut query = ProtoScillaQuery::decode(query.as_slice())?;

    //    trace!("Fetch external state value: {addr:?} - {query:?}");

    //    let Some(account) = self.db.lock().unwrap().get_account(addr)? else { return Ok(None); };
    //    let account = Account::from_proto(account)?;

    //    fn scilla_val(b: Vec<u8>) -> ProtoScillaVal {
    //        ProtoScillaVal {
    //            val_type: Some(ValType::Bval(b)),
    //        }
    //    }

    //    match query.name.as_str() {
    //        "_balance" => {
    //            let val = scilla_val(format!("\"{}\"", account.balance).into_bytes());
    //            return Ok(Some((val, "Uint128".to_owned())));
    //        }
    //        "_nonce" => {
    //            let val = scilla_val(format!("\"{}\"", account.nonce).into_bytes());
    //            return Ok(Some((val, "Uint64".to_owned())));
    //        }
    //        "_this_address" => {
    //            if account.contract.is_some() {
    //                let val = scilla_val(format!("\"0x{:?}\"", addr).into_bytes());
    //                return Ok(Some((val, "ByStr20".to_owned())));
    //            }
    //        }
    //        "_codehash" => {
    //            let code_hash = account.contract.map(|c| c.code_hash).unwrap_or_default();
    //            let val = scilla_val(format!("\"0x{:?}\"", code_hash).into_bytes());
    //            return Ok(Some((val, "ByStr32".to_owned())));
    //        }
    //        "_code" => {
    //            let code = self
    //                .db
    //                .lock()
    //                .unwrap()
    //                .get_contract_code(addr)?
    //                .unwrap_or_default();
    //            let val = scilla_val(code);
    //            return Ok(Some((val, String::new())));
    //        }
    //        _ => {}
    //    }

    //    let addr_hex = format!("{addr:x}");

    //    let ty = if query.name == "_evm_storage" {
    //        Some("ByStr30".to_owned())
    //    } else {
    //        let ty_key = format!("{}\x16_type\x16{}\x16", addr_hex, query.name);
    //        self.get_state(&ty_key)?
    //            .map(String::from_utf8)
    //            .transpose()?
    //    };
    //    let Some(ty) = ty else { return Ok(None); };

    //    let depth_key = format!("{}\x16_depth\x16{}\x16", addr_hex, query.name);
    //    let depth = String::from_utf8(
    //        self.get_state(&depth_key)?
    //            .ok_or_else(|| anyhow!("no depth"))?,
    //    )?
    //        .parse()?;
    //    query.mapdepth = depth;

    //    let Some(contract) = account.contract else { return Err(anyhow!("state read from non-contract")); };

    //    let Some((old_addr, old_state_root, block_num)) = self.current_contract_addr else { return Err(anyhow!("no current contract")); };

    //    self.current_contract_addr = Some((addr, contract.state_root, block_num));
    //    let value = self.fetch_state_value_inner(query)?;
    //    self.current_contract_addr = Some((old_addr, old_state_root, block_num));

    //    Ok(value.map(|v| (v, ty)))
    //}

    pub fn update_state_value_b64(
        &mut self,
        params: Params,
    ) -> Result<Value, jsonrpc_core::Error> {
        fn err(s: &'static str) -> Result<Value, jsonrpc_core::Error> {
            debug!("* updateStateValueB64 ERROR called *** {:?}", s);
            Err(jsonrpc_core::Error::invalid_params(s))
        }

        debug!("* updateStateValueB64 called ***");

        let b64 = base64::engine::general_purpose::STANDARD;

        let Params::Map(params) = params else { return err("expected a map"); };
        let Some(query) = params.get("query") else { return err("expected query in map"); };
        let Some(query) = query.as_str().map(str::to_owned) else { return err("query was not a string"); };
        //let Ok(query) = b64.decode(query) else { return err("query was not base64"); };
        let query = query.as_bytes().to_vec();
        let Some(value) = params.get("value") else { return err("expected value in map"); };
        let Some(value) = value.as_str().map(str::to_owned) else { return err("value was not a string"); };
        //let Ok(value) = b64.decode(value) else { return err("value was not base64"); };

        let result = self
            .update_state_value_inner(query, value.as_bytes().to_vec())
            .map_err(convert_err);

        //let result = self.inner.backend.set_storage(query, value).map_err(convert_err);

        //Ok(Value::Null)
        result

        //Ok(json!("hehe".to_string()))
    }

    fn update_state_value_inner(&mut self, query: Vec<u8>, value: Vec<u8>) -> Result<Value> {
        let query = ProtoScillaQuery::decode(query.as_slice())?;
        let value = ProtoScillaVal::decode(value.as_slice())?;

        trace!("Update state value: {query:?} -> {value:?}");

        if ["_addr", "_version", "_depth", "_type", "_hasmap"].contains(&query.name.as_str()) {
            return Err(anyhow!("reserved variable name: {}", query.name));
        }

        // todo: this.
        self.current_contract_addr = Some((H160::zero(), H256::zero(), 0));

        // nathan
        let Some((addr, _, _)) = self.current_contract_addr else { return Err(anyhow!("no current contract")); };

        let addr_hex = format!("{addr:x}");
        let mut key = format!("{}\x16{}\x16", addr_hex, query.name);

        trace!("key: {:?}", key);
        trace!("query: {:?}", query.ignoreval);

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

            //self.delete_by_prefix(&key)?; // todo: this.

            if self.key_is_empty(&parent_key)? {
                let empty_map = ProtoScillaVal {
                    val_type: Some(ValType::Mval(Default::default())),
                };
                self.update_state(&parent_key, &empty_map.encode_to_vec(), false)?;
            }
        } else {

            for index in &query.indices {
                trace!("index: {:?}", index);
                let index = str::from_utf8(index)?;
                key.push_str(index);
                key.push('\x16');
            }

            match query.indices.len().cmp(&(query.mapdepth as usize)) {
                std::cmp::Ordering::Greater => {
                    trace!("indices is deeper than map depth");
                    return Err(anyhow!("indices is deeper than map depth"));
                }
                std::cmp::Ordering::Equal => {
                    trace!("Result will not be a map and can be just fetched into the store");
                    let val_type = value.val_type.ok_or_else(|| anyhow!("no val_type"))?;
                    let ValType::Bval(bytes) = val_type else { return Err(anyhow!("expected bytes for value, but got a map")); };
                    self.update_state(&key, &bytes, true)?;
                }
                std::cmp::Ordering::Less => {
                    trace!("less");
                    self.delete_by_prefix(&key)?;

                    self.map_handler(key, &value)?;
                }
            }
        }

        debug!("returning true after successful operation.");
        Ok(Value::Null)
        //Ok(json!(true))
    }

    fn map_handler(
        //inner: &mut Self,
        &mut self,
        key_acc: String,
        value: &ProtoScillaVal,
    ) -> Result<()> {

        trace!("map_handler: {key_acc:?} - {value:?}");

        let val_type = value
            .val_type
            .as_ref()
            .ok_or_else(|| anyhow!("no val_type"))?;
        let ValType::Mval(val_type) = val_type else { return Err(anyhow!("expected map for value but got bytes")); };

        if val_type.m.is_empty() {
            // We have an empty map. Insert an entry for keyAcc in the store to indicate that the key itself exists.
            self.update_state(&key_acc, &value.encode_to_vec(), true)?;
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
                    self.map_handler(index, v)?;
                }
                ValType::Bval(bytes) => {
                    self.update_state(&index, bytes.as_slice(), true)?;
                }
            }
        }

        Ok(())
    }

    //fn fetch_blockchain_info(
    //    &mut self,
    //    params: Params,
    //) -> BoxFuture<Result<Value, jsonrpc_core::Error>> {
    //    fn err(s: &'static str) -> BoxFuture<Result<Value, jsonrpc_core::Error>> {
    //        futures::future::ready(Err(jsonrpc_core::Error::invalid_params(s))).boxed()
    //    }

    //    let Params::Map(params) = params else { return err("expected a map"); };
    //    let Some(query_name) = params.get("query_name") else { return err("expected query_name in map"); };
    //    let Some(query_name) = query_name.as_str().map(str::to_owned) else { return err("query_name was not a string"); };
    //    let Some(query_args) = params.get("query_args") else { return err("expected query_args in map"); };
    //    let Some(query_args) = query_args.as_str().map(str::to_owned) else { return err("query_args was not a string"); };

    //    let result = self
    //        .fetch_blockchain_info_inner(query_name, query_args)
    //        .map_err(convert_err);

    //    let result = result.map(|s| Value::Array(vec![true.into(), s.into()]));

    //    future::ready(result).boxed()
    //}

    //fn fetch_blockchain_info_inner(
    //    &mut self,
    //    query_name: String,
    //    query_args: String,
    //) -> Result<String> {
    //    trace!("Fetch blockchain info: {query_name} - {query_args}");

    //    match query_name.as_str() {
    //        "BLOCKNUMBER" => {
    //            let Some((_, _, block_number)) = self.current_contract_addr else { return Err(anyhow!("no current contract")); };
    //            Ok(block_number.to_string())
    //        }
    //        "TIMESTAMP" => {
    //            let block_num: u64 = query_args.parse()?;
    //            let block = self
    //                .db
    //                .lock()
    //                .unwrap()
    //                .get_tx_block(block_num)?
    //                .ok_or_else(|| anyhow!("invalid block"))?;
    //            let block = TxBlock::from_proto(block)?;
    //            Ok(block.timestamp.to_string())
    //        }
    //        "BLOCKHASH" => {
    //            let block_num: u64 = query_args.parse()?;
    //            let block = self
    //                .db
    //                .lock()
    //                .unwrap()
    //                .get_tx_block(block_num)?
    //                .ok_or_else(|| anyhow!("invalid block"))?;
    //            let block = TxBlock::from_proto(block)?;
    //            let block_hash = format!("{:x}", block.block_hash);
    //            Ok(block_hash)
    //        }
    //        "CHAINID" => Ok(1.to_string()),
    //        _ => Ok(String::new()),
    //    }
    //}

    //fn get_state(&self, key: &str) -> Result<Option<Vec<u8>>> {
    //    self.db.lock().unwrap().get_contract_state_data(key)
    //}

    fn key_is_empty(&self, key: &str) -> Result<bool> {
        Ok(true)
        ////let keys: Vec<_> = self
        //    .db
        //    .lock()
        //    .unwrap()
        //    .get_contract_state_data_with_prefix(key)
        //    .collect::<Result<_>>()?;

        //Ok(keys.is_empty())
    }

    fn delete_by_prefix(&mut self, prefix: &str) -> Result<()> {
        let Some((addr, state_root, block_number)) = self.current_contract_addr else { return Err(anyhow!("no current contract")); };
        // todo: this.
        //let state_root = self
        //    .db
        //    .lock()
        //    .unwrap()
        //    .delete_contract_state_with_prefix(state_root, prefix)?;
        //self.current_contract_addr = Some((addr, state_root, block_number));

        Ok(())
    }

    fn update_state(&mut self, key: &str, value: &[u8], clean_empty: bool) -> Result<()> {
        //if clean_empty {
        //    let indices: Vec<_> = key.split_terminator('\x16').collect();
        //    if indices.len() < 2 {
        //        return Err(anyhow!("not enough indices: {}", indices.len()));
        //    }

        //    let mut scan_key = format!("{}\x16{}\x16", indices[0], indices[1]);
        //    self.delete_state(&scan_key)?;

        //    if indices.len() > 2 {
        //        // Exclude the value key.
        //        for index in &indices[2..(indices.len() - 1)] {
        //            scan_key.push_str(index);
        //            scan_key.push('\x16');
        //            self.delete_state(&scan_key)?;
        //        }
        //    }
        //}

        //self.put_state(key, value)?;

        Ok(())
    }

    //fn put_state(&mut self, key: &str, value: &[u8]) -> Result<()> {
    //    let Some((addr, state_root, block_number)) = self.current_contract_addr else { return Err(anyhow!("no current contract")); };
    //    let state_root = self
    //        .db
    //        .lock()
    //        .unwrap()
    //        .put_contract_state(state_root, key, value)?;
    //    self.current_contract_addr = Some((addr, state_root, block_number));

    //    Ok(())
    //}

    //fn delete_state(&mut self, key: &str) -> Result<()> {
    //    let Some((addr, state_root, block_number)) = self.current_contract_addr else { return Err(anyhow!("no current contract")); };
    //    let state_root = self
    //        .db
    //        .lock()
    //        .unwrap()
    //        .delete_contract_state(state_root, key)?;
    //    self.current_contract_addr = Some((addr, state_root, block_number));

    //    Ok(())
    //}
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
