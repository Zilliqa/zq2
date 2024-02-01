use std::{collections::HashMap, str};

use anyhow::{anyhow, Result};
use base64::Engine;
use jsonrpc_core::Params;
use primitive_types::{H160, H256};
use prost::Message;
use serde_json::Value;
use sha3::{Digest, Keccak256};
use tracing::*;

use crate::{
    backend_collector::BackendCollector,
    proto::{proto_scilla_val, proto_scilla_val::ValType, ProtoScillaQuery, ProtoScillaVal},
    types::JsonRpcRequest,
};

pub struct ScillaServer<'a, B: evm::backend::Backend> {
    pub inner: Inner<'a, B>,
}

pub struct Inner<'a, B: evm::backend::Backend> {
    pub backend: BackendCollector<'a, B>,
    pub contract_addr: H160,
    pub state_root: H256,
    pub caller: H160,
}

impl<'a, B: evm::backend::Backend> ScillaServer<'a, B> {
    pub fn handle_request(
        &mut self,
        request: &JsonRpcRequest,
    ) -> Result<Value, jsonrpc_core::Error> {
        match request.method.as_str() {
            "fetchStateValueB64" => self.inner.fetch_state_value_b64(&request.params),
            "fetchStateValue" => self.inner.fetch_state_value_b64(&request.params),
            "fetchExternalStateValueB64" => {
                self.inner.fetch_external_state_value_b64(&request.params)
            }
            "fetchExternalStateValue" => self.inner.fetch_external_state_value_b64(&request.params),
            "updateStateValueB64" => self.inner.update_state_value_b64(&request.params),
            "updateStateValue" => self.inner.update_state_value_b64(&request.params),
            "fetchBlockchainInfo" => self.inner.fetch_blockchain_info(&request.params),
            _ => {
                warn!(
                    "Scilla server made a request for invalid method: {:?}",
                    request.method
                );
                Err(jsonrpc_core::Error::invalid_request())
            }
        }
    }

    pub fn new(
        backend: BackendCollector<'a, B>,
        caller: H160,
        contract_addr: H160,
        state_root: H256,
    ) -> ScillaServer<'a, B> {
        let inner = Inner {
            backend,
            contract_addr,
            state_root,
            caller,
        };

        ScillaServer { inner }
    }
}

impl<'a, B: evm::backend::Backend> Inner<'a, B> {
    // Parsing functions, then the inner functions
    pub fn update_state_value_b64(
        &mut self,
        params: &Params,
    ) -> Result<Value, jsonrpc_core::Error> {
        fn err(s: &'static str) -> Result<Value, jsonrpc_core::Error> {
            debug!("* updateStateValueB64 ERROR called *** {:?}", s);
            Err(jsonrpc_core::Error::invalid_params(s))
        }

        let b64 = base64::engine::general_purpose::STANDARD;

        let Params::Map(params) = params else {
            return err("expected a map");
        };
        let Some(query) = params.get("query") else {
            return err("expected query in map");
        };
        let Some(query) = query.as_str().map(str::to_owned) else {
            return err("query was not a string");
        };
        // Attempt both base64 and non-base64 decoding for query and value
        let query = b64.decode(query.clone()).unwrap_or(query.into());

        let Some(value) = params.get("value") else {
            return err("expected value in map");
        };
        let Some(value) = value.as_str().map(str::to_owned) else {
            return err("value was not a string");
        };
        let value = b64.decode(value.clone()).unwrap_or(value.into());

        self.update_state_value_inner(query, value)
            .map_err(convert_err)
    }

    // todo: this.
    fn fetch_state_value_b64(&mut self, params: &Params) -> Result<Value, jsonrpc_core::Error> {
        fn err(s: &'static str) -> Result<Value, jsonrpc_core::Error> {
            debug!("* fetchStateValue ERROR called *** {:?}", s);
            Err(jsonrpc_core::Error::invalid_params(s))
        }

        let b64 = base64::engine::general_purpose::STANDARD;

        let Params::Map(params) = params else {
            return err("expected a map");
        };
        let Some(query) = params.get("query") else {
            return err("expected query in map");
        };
        let Some(query) = query.as_str().map(str::to_owned) else {
            return err("query was not a string");
        };
        let query = b64.decode(query.clone()).unwrap_or(query.into());
        let Ok(query) = ProtoScillaQuery::decode(query.as_slice()) else {
            return err("could not parse query");
        };

        let result = self.fetch_state_value_inner(query).map_err(convert_err);

        result.map(|value| {
            let arr = match value {
                Some(value) => vec![true.into(), b64.encode(value.encode_to_vec()).into()],
                None => vec![false.into(), String::new().into()],
            };
            Value::Array(arr)
        })
    }

    // Todo: this.
    fn fetch_external_state_value_b64(
        &mut self,
        params: &Params,
    ) -> Result<Value, jsonrpc_core::Error> {
        fn err(s: &'static str) -> Result<Value, jsonrpc_core::Error> {
            debug!("* fetchExternalStateValue ERROR called *** {:?}", s);
            Err(jsonrpc_core::Error::invalid_params(s))
        }

        let b64 = base64::engine::general_purpose::STANDARD;

        let Params::Map(params) = params else {
            return err("expected a map");
        };
        let Some(addr) = params.get("addr") else {
            return err("expected addr in map");
        };
        let Some(addr) = addr.as_str().map(str::to_owned) else {
            return err("addr was not a string");
        };
        let Ok(addr) = addr.parse::<H160>() else {
            return err("addr parsing failed");
        };
        let Some(query) = params.get("query") else {
            return err("expected query in map");
        };
        let Some(query) = query.as_str().map(str::to_owned) else {
            return err("query was not a string");
        };
        //let Ok(query) = b64.decode(query) else { return err("query was not base64"); };
        let query = b64.decode(query.clone()).unwrap_or(query.into());

        let result = self
            .fetch_external_state_value_inner(addr, query)
            .map_err(convert_err);

        result.map(|vt| {
            let arr = match vt {
                Some((value, ty)) => vec![
                    true.into(),
                    b64.encode(value.encode_to_vec()).into(),
                    ty.into(),
                ],
                None => vec![false.into(), String::new().into(), String::new().into()],
            };
            Value::Array(arr)
        })
    }

    // todo: this.
    fn fetch_blockchain_info(&mut self, params: &Params) -> Result<Value, jsonrpc_core::Error> {
        fn err(s: &'static str) -> Result<Value, jsonrpc_core::Error> {
            debug!("* fetchBlockchainInfo ERROR called *** {:?}", s);
            Err(jsonrpc_core::Error::invalid_params(s))
        }

        let Params::Map(params) = params else {
            return err("expected a map");
        };
        let Some(query_name) = params.get("query_name") else {
            return err("expected query_name in map");
        };
        let Some(query_name) = query_name.as_str().map(str::to_owned) else {
            return err("query_name was not a string");
        };
        let Some(query_args) = params.get("query_args") else {
            return err("expected query_args in map");
        };
        let Some(query_args) = query_args.as_str().map(str::to_owned) else {
            return err("query_args was not a string");
        };

        let result = self
            .fetch_blockchain_info_inner(query_name, query_args)
            .map_err(convert_err);

        result.map(|s| Value::Array(vec![true.into(), s.into()]))
    }

    fn update_state_value_inner(&mut self, query: Vec<u8>, value: Vec<u8>) -> Result<Value> {
        let query = ProtoScillaQuery::decode(query.as_slice())?;
        let value = ProtoScillaVal::decode(value.as_slice())?;

        trace!("Update state value: {query:?} -> {value:?}");

        if ["_addr", "_version", "_depth", "_type", "_hasmap"].contains(&query.name.as_str()) {
            return Err(anyhow!("reserved variable name: {}", query.name));
        }

        let addr = self.contract_addr;
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

            self.delete_by_prefix(&key)?;

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
                    let ValType::Bval(bytes) = val_type else {
                        return Err(anyhow!("expected bytes for value, but got a map"));
                    };
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
    }

    fn fetch_blockchain_info_inner(
        &mut self,
        query_name: String,
        query_args: String,
    ) -> Result<String> {
        trace!("Fetch blockchain info: {query_name} - {query_args}");

        match query_name.as_str() {
            "BLOCKNUMBER" => {
                trace!("BLOCKNUMBER requested from scilla server");
                Ok(self.backend.get_block_number().to_string())
            }
            "TIMESTAMP" => {
                trace!("TIMESTAMP requested from scilla server");
                Ok(self.backend.get_timestamp().to_string())
            }
            "BLOCKHASH" => {
                trace!("BLOCKHASH requested from scilla server");
                Ok(self
                    .backend
                    .get_block_hash(self.backend.get_block_number().into())
                    .to_string())
            }
            "CHAINID" => {
                trace!("BLOCKHASH requested from scilla server");
                Ok(self.backend.get_chain_id().to_string())
            }
            _ => {
                warn!("unrecognised request from scilla server {:?}", query_name);
                Ok(String::new())
            }
        }
    }

    fn fetch_external_state_value_inner(
        &mut self,
        addr: H160,
        query: Vec<u8>,
    ) -> Result<Option<(ProtoScillaVal, String)>> {
        let mut query = ProtoScillaQuery::decode(query.as_slice())?;
        // nathan - we are here

        trace!("Fetch external state value: {addr:?} - {query:?}");

        let addr = self.contract_addr;
        let account = self.backend.get_account(addr);
        let balance = self.backend.get_balance(addr);
        let code_hash = Keccak256::digest(&account.code); // todo: need to create this code hash - is this correct?
        let code = account.code;

        fn scilla_val(b: Vec<u8>) -> ProtoScillaVal {
            ProtoScillaVal {
                val_type: Some(ValType::Bval(b)),
            }
        }

        match query.name.as_str() {
            "_balance" => {
                let val = scilla_val(format!("\"{}\"", balance).into_bytes());
                return Ok(Some((val, "Uint128".to_owned())));
            }
            // Todo: check that nonces are correct (off by one in scilla)
            "_nonce" => {
                let val = scilla_val(format!("\"{}\"", account.nonce).into_bytes());
                return Ok(Some((val, "Uint64".to_owned())));
            }
            "_this_address" => {
                if !code.is_empty() {
                    let val = scilla_val(format!("\"0x{:?}\"", addr).into_bytes());
                    return Ok(Some((val, "ByStr20".to_owned())));
                }
            }
            "_codehash" => {
                let val = scilla_val(format!("\"0x{:?}\"", code_hash).into_bytes());
                return Ok(Some((val, "ByStr32".to_owned())));
            }
            "_code" => {
                let val = scilla_val(code);
                return Ok(Some((val, String::new())));
            }
            _ => {
                warn!(
                    "fetch_external_state_value_inner: unknown query name: {:?}",
                    query.name
                );
            }
        }

        let addr_hex = format!("{addr:x}");

        // todo: figure out this evm storage query
        let ty = if query.name == "_evm_storage" {
            Some("ByStr30".to_owned())
        } else {
            let ty_key = format!("{}\x16_type\x16{}\x16", addr_hex, query.name);
            self.get_state(&ty_key)?
                .map(String::from_utf8)
                .transpose()?
        };
        let Some(ty) = ty else {
            return Ok(None);
        };

        let depth_key = format!("{}\x16_depth\x16{}\x16", addr_hex, query.name);
        let depth = String::from_utf8(
            self.get_state(&depth_key)?
                .ok_or_else(|| anyhow!("no depth"))?,
        )?
        .parse()?;
        query.mapdepth = depth;

        //let Some(contract) = account.contract else { return Err(anyhow!("state read from non-contract")); };
        //let contract = account.code;

        // don't need to do this switch I think
        //let Some((old_addr, old_state_root, block_num)) = self.current_contract_addr else { return Err(anyhow!("no current contract")); };
        //self.current_contract_addr = Some((addr, contract.state_root, block_num));

        let value = self.fetch_state_value_inner(query)?;
        //self.current_contract_addr = Some((old_addr, old_state_root, block_num));

        Ok(value.map(|v| (v, ty)))
    }

    // todo: this.
    fn fetch_state_value_inner(
        &mut self,
        query: ProtoScillaQuery,
    ) -> Result<Option<ProtoScillaVal>> {
        trace!("Fetch state value: {query:?}");

        if ["_addr", "_version", "_depth", "_type", "_hasmap"].contains(&query.name.as_str()) {
            return Err(anyhow!("reserved variable name: {}", query.name));
        }

        //let (addr, _, _) = self.execution_context else { return Err(anyhow!("no current contract")); };
        let addr = self.contract_addr;

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
                //let bytes = self.db.lock().unwrap().get_contract_state_data(&key)?;
                let bytes = self.get_state(&key)?;

                let Some(bytes) = bytes else {
                    return Ok(None);
                };

                ProtoScillaVal {
                    val_type: Some(ValType::Bval(bytes)),
                }
            }
            std::cmp::Ordering::Less => {
                // We're fetching a map value. We need to iterate through the DB lexicographically.
                let entries: HashMap<String, Vec<u8>> = HashMap::new();

                //let existing_entries: Vec<_> = self
                //    .db
                //    .lock()
                //    .unwrap()
                //    .get_contract_state_data_with_prefix(&key)
                //    .collect();

                // todo: this
                //let existing_entries: Vec<_> = self.get_state_with_prefix(&key).collect();
                let existing_entries: Vec<_> = self.get_state(&key).unwrap().unwrap();

                if existing_entries.is_empty() && !query.indices.is_empty() {
                    return Ok(None);
                }

                // todo: this.
                //for kv in existing_entries {
                //    let (k, v) = kv;
                //    entries.insert(k, v);
                //}

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
                        let Some(ValType::Mval(proto_scilla_val::Map { ref mut m })) =
                            val_ref.val_type
                        else {
                            unreachable!();
                        };
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

    fn map_handler(&mut self, key_acc: String, value: &ProtoScillaVal) -> Result<()> {
        trace!("map_handler: {key_acc:?} - {value:?}");

        let val_type = value
            .val_type
            .as_ref()
            .ok_or_else(|| anyhow!("no val_type"))?;
        let ValType::Mval(val_type) = val_type else {
            return Err(anyhow!("expected map for value but got bytes"));
        };

        if val_type.m.is_empty() {
            // We have an empty map. Insert an entry for keyAcc in the store to indicate that the key itself exists.
            self.update_state(&key_acc, &value.encode_to_vec(), true)?;
            return Ok(());
        }

        for (k, v) in &val_type.m {
            let mut index = key_acc.clone();
            index.push_str(k);
            index.push('\x16');

            let inner_val_type = v.val_type.as_ref().ok_or_else(|| anyhow!("no val_type"))?;
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

    fn key_is_empty(&self, _key: &str) -> Result<bool> {
        Ok(true)
    }

    fn delete_by_prefix(&mut self, prefix: &str) -> Result<()> {
        self.delete_state(prefix)?;
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
        self.backend
            .update_account_storage_scilla(self.contract_addr, key, value);
        Ok(())
    }

    fn get_state(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let value = self
            .backend
            .get_account_storage_scilla(self.contract_addr, key);
        Ok(Some(value))
    }

    fn delete_state(&mut self, key: &str) -> Result<()> {
        self.backend
            .update_account_storage_scilla(self.contract_addr, key, Default::default());
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
