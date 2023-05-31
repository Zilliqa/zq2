pub mod eth;
mod net;
mod to_hex;
mod types;
mod web3;
pub mod zilliqa;

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    let mut module = RpcModule::new(node.clone());

    module.merge(eth::rpc_module(node.clone())).unwrap();
    module.merge(net::rpc_module(node.clone())).unwrap();
    module.merge(web3::rpc_module(node.clone())).unwrap();
    module.merge(zilliqa::rpc_module(node)).unwrap();

    module
}

/// Returns an `RpcModule<Arc<Mutex<Node>>>`. Call with the following syntax:
/// ```ignore
/// declare_module!(
///     node,
///     [
///         ("method1", method_one),
///         ("method2", method_two),
///     ],
/// )
/// ```
///
/// where `node` is an `Arc<Mutex<Node>>` and each implementation method has the signature
/// `Fn(jsonrpsee::types::Params, &Arc<Mutex<Node>>) -> Result<T>`.
///
/// Will panic if any of the method names collide.
macro_rules! declare_module {
    (
        $node:expr,
        [ $(($name:expr, $method:expr)),* $(,)? ] $(,)?
    ) => {{
        let mut module: jsonrpsee::RpcModule<std::sync::Arc<std::sync::Mutex<crate::node::Node>>> = jsonrpsee::RpcModule::new($node);
        let meter = opentelemetry::global::meter("");

        $(
            let rpc_server_duration = meter
                .f64_histogram("rpc.server.duration")
                .with_unit(opentelemetry::metrics::Unit::new("ms"))
                .init();
            let cx = opentelemetry::Context::new();
            module
                .register_method($name, move |params, context| {
                    let mut attributes = vec![
                        opentelemetry::KeyValue::new("rpc.system", "jsonrpc"),
                        opentelemetry::KeyValue::new("rpc.service", "zilliqa.eth"),
                        opentelemetry::KeyValue::new("rpc.method", $name),
                        opentelemetry::KeyValue::new("network.transport", "tcp"),
                        opentelemetry::KeyValue::new("rpc.jsonrpc.version", "2.0"),
                    ];

                    let start = std::time::SystemTime::now();
                    let result = $method(params, context).map_err(|e| {
                        tracing::error!(?e);
                        jsonrpsee::types::ErrorObject::owned(
                            jsonrpsee::types::error::ErrorCode::InternalError.code(),
                            e.to_string(),
                            None as Option<String>,
                        )
                    });
                    if let Err(err) = &result {
                        attributes.push(opentelemetry::KeyValue::new("rpc.jsonrpc.error_code", err.code() as i64));
                    }
                    rpc_server_duration.record(
                        &cx,
                        start.elapsed().map_or(0.0, |d| d.as_secs_f64() * 1000.0),
                        &attributes,
                    );
                    result
                })
                .unwrap();
        )*

        module
    }}
}

use std::sync::{Arc, Mutex};

use declare_module;
use jsonrpsee::RpcModule;

use crate::node::Node;
