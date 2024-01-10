use std::{
    str,
};

use anyhow::{anyhow, Result};
use base64::Engine;

use futures::{FutureExt};
use jsonrpc_core::{IoHandler, Params};
use primitive_types::{H160, H256, U256};
use prost::Message;
use serde_json::{Value};
//use sha2::digest::consts::U256;
use tracing::{*};

use crate::{
    backend_collector::BackendCollector,
    call_scilla_server::JsonRpcRequest,
    proto::{
        proto_scilla_val::{ValType},
        ProtoScillaQuery, ProtoScillaVal,
    },
};

pub struct ScillaServer<'a, B: evm::backend::Backend> {
    pub inner: Inner<'a, B>,
    pub _tcp_server: IoHandler,
}

pub struct Inner<'a, B: evm::backend::Backend> {
    pub backend: BackendCollector<'a, B>,
    current_contract_addr: (H160, H256, U256), // contract addr, state root, block number
}

impl<'a, B: evm::backend::Backend> ScillaServer<'a, B> {
    pub fn handle_request(
        &mut self,
        request: JsonRpcRequest,
    ) -> Result<Value, jsonrpc_core::Error> {

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
            }
            //"fetchBlockchainInfo" => {
            //    let response = self.fetch_blockchain_info(request.params);
            //    Ok(response)
            //},
            _ => {
                warn!(
                    "Scilla server made a request for invalid method: {:?}",
                    request.method
                );
                Err(jsonrpc_core::Error::invalid_request())
            }
        }
    }

    pub fn new(backend: BackendCollector<'a, B>, contract_addr: H160, state_root: H256, block_number: U256) -> ScillaServer<'a, B> {
        let inner = Inner {
            backend,
            current_contract_addr: (contract_addr, state_root, block_number),
        };
        let mut _tcp_server = IoHandler::new();

        ScillaServer {
            inner,
            _tcp_server,
        }
    }
}

impl<'a, B: evm::backend::Backend> Inner<'a, B> {
    pub fn update_state_value_b64(&mut self, params: Params) -> Result<Value, jsonrpc_core::Error> {
        fn err(s: &'static str) -> Result<Value, jsonrpc_core::Error> {
            debug!("* updateStateValueB64 ERROR called *** {:?}", s);
            Err(jsonrpc_core::Error::invalid_params(s))
        }

        debug!("* updateStateValueB64 called ***");

        let _b64 = base64::engine::general_purpose::STANDARD;

        let Params::Map(params) = params else {
            return err("expected a map");
        };
        let Some(query) = params.get("query") else {
            return err("expected query in map");
        };
        let Some(query) = query.as_str().map(str::to_owned) else {
            return err("query was not a string");
        };
        //let Ok(query) = b64.decode(query) else { return err("query was not base64"); };
        let query = query.as_bytes().to_vec();
        let Some(value) = params.get("value") else {
            return err("expected value in map");
        };
        let Some(value) = value.as_str().map(str::to_owned) else {
            return err("value was not a string");
        };
        //let Ok(value) = b64.decode(value) else { return err("value was not base64"); };

        let result = self
            .update_state_value_inner(query, value.as_bytes().to_vec())
            .map_err(convert_err);

        result
    }

    fn update_state_value_inner(&mut self, query: Vec<u8>, value: Vec<u8>) -> Result<Value> {
        let query = ProtoScillaQuery::decode(query.as_slice())?;
        let value = ProtoScillaVal::decode(value.as_slice())?;

        trace!("Update state value: {query:?} -> {value:?}");

        if ["_addr", "_version", "_depth", "_type", "_hasmap"].contains(&query.name.as_str()) {
            return Err(anyhow!("reserved variable name: {}", query.name));
        }

        //// todo: this.
        //self.current_contract_addr = Some((H160::zero(), H256::zero(), 0));

        //// nathan
        //let Some((addr, _, _)) = self.current_contract_addr else {
        //    return Err(anyhow!("no current contract"));
        //};

        let addr = self.current_contract_addr.0;
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

    fn delete_by_prefix(&mut self, _prefix: &str) -> Result<()> {
        //let Some((_addr, _state_root, _block_number)) = self.current_contract_addr else {
            //return Err(anyhow!("no current contract"));
        //};
        // todo: this.
        //let state_root = self
        //    .db
        //    .lock()
        //    .unwrap()
        //    .delete_contract_state_with_prefix(state_root, prefix)?;
        //self.current_contract_addr = Some((addr, state_root, block_number));

        todo!("delete_by_prefix");

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

        self.backend.update_account_storage_scilla(self.current_contract_addr.0, key, value);
        //let Some((addr, state_root, block_number)) = self.current_contract_addr else { return Err(anyhow!("no current contract")); };
        //let state_root = self
        //    .db
        //    .lock()
        //    .unwrap()
        //    .put_contract_state(state_root, key, value)?;
        //self.current_contract_addr = Some((addr, state_root, block_number));

        Ok(())
    }

    fn delete_state(&mut self, key: &str) -> Result<()> {
        //let Some((addr, state_root, block_number)) = self.current_contract_addr else { return Err(anyhow!("no current contract")); };
        //let state_root = self
        //    .db
        //    .lock()
        //    .unwrap()
        //    .delete_contract_state(state_root, key)?;
        //self.current_contract_addr = Some((addr, state_root, block_number));
        //todo!("delete_state");
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
