//! The Ethereum API, as documented at <https://ethereum.org/en/developers/docs/apis/json-rpc>.

use std::sync::{Arc, Mutex};

use jsonrpsee::{core::RpcResult, types::Params, RpcModule};

use crate::node::Node;

use super::to_hex::ToHex;

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    let mut module = RpcModule::new(node);

    macro_rules! method {
        ($name:expr, $imp:path) => {
            module.register_method($name, $imp).unwrap();
        };
    }

    method!("eth_accounts", accounts);
    method!("eth_blockNumber", block_number);
    method!("eth_chainId", chain_id);
    method!("eth_estimateGas", estimate_gas);
    method!("eth_getBalance", get_balance);
    method!("eth_gasPrice", gas_price);
    method!("net_version", version);

    module
}

fn accounts(_: Params, _: &Arc<Mutex<Node>>) -> RpcResult<[(); 0]> {
    Ok([])
}

fn block_number(_: Params, node: &Arc<Mutex<Node>>) -> RpcResult<Option<String>> {
    if let Some(block) = node.lock().unwrap().view().checked_sub(1) {
        Ok(Some(block.to_hex()))
    } else {
        Ok(None)
    }
}

fn chain_id(_: Params, _: &Arc<Mutex<Node>>) -> RpcResult<&'static str> {
    // TODO: Configurable
    Ok("0x1")
}

fn estimate_gas(_: Params, _: &Arc<Mutex<Node>>) -> RpcResult<&'static str> {
    // TODO: Implement
    Ok("0x100")
}

fn get_balance(_: Params, _: &Arc<Mutex<Node>>) -> RpcResult<&'static str> {
    // TODO: Implement
    Ok("0xf000000000000000")
}

fn gas_price(_: Params, _: &Arc<Mutex<Node>>) -> RpcResult<&'static str> {
    // TODO: Implement
    Ok("0x454b7b38e70")
}

fn version(_: Params, _: &Arc<Mutex<Node>>) -> RpcResult<&'static str> {
    // TODO: Configurable
    Ok("1")
}
