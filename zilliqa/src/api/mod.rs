pub mod admin;
mod erigon;
pub mod eth;
mod net;
mod others;
pub mod ots;
pub mod subscription_id_provider;
pub mod to_hex;
mod trace;
pub mod types;
mod web3;
pub mod zil;

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    let mut module = RpcModule::new(node.clone());

    module.merge(erigon::rpc_module(node.clone())).unwrap();
    module.merge(eth::rpc_module(node.clone())).unwrap();
    module.merge(net::rpc_module(node.clone())).unwrap();
    module.merge(trace::rpc_module(node.clone())).unwrap();
    module.merge(ots::rpc_module(node.clone())).unwrap();
    module.merge(web3::rpc_module(node.clone())).unwrap();
    module.merge(zil::rpc_module(node.clone())).unwrap();
    module.merge(admin::rpc_module(node.clone())).unwrap();

    module.merge(others::rpc_module(node.clone())).unwrap();

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
        let meter = opentelemetry::global::meter("zilliqa");

        $(
            let rpc_server_duration = meter
                .f64_histogram(opentelemetry_semantic_conventions::metric::RPC_SERVER_DURATION)
                .with_unit("s")
                .build();
            module
                .register_method($name, move |params, context, _| {
                    let mut attributes = vec![
                        opentelemetry::KeyValue::new(opentelemetry_semantic_conventions::attribute::RPC_SYSTEM, "jsonrpc"),
                        opentelemetry::KeyValue::new(opentelemetry_semantic_conventions::attribute::RPC_SERVICE, "zilliqa.eth"),
                        opentelemetry::KeyValue::new(opentelemetry_semantic_conventions::attribute::RPC_METHOD, $name),
                        opentelemetry::KeyValue::new(opentelemetry_semantic_conventions::attribute::NETWORK_TRANSPORT, "tcp"),
                        opentelemetry::KeyValue::new(opentelemetry_semantic_conventions::attribute::RPC_JSONRPC_VERSION, "2.0"),
                    ];

                    let start = std::time::SystemTime::now();

                    #[allow(clippy::redundant_closure_call)]
                    let result = std::panic::catch_unwind(|| $method(params, context)).unwrap_or_else(|_| {
                        Err(anyhow::anyhow!("Unhandled panic in RPC handler {}", $name))
                    });

                    let result = result.map_err(|e| {
                        // If the error is already an `ErrorObjectOwned`, we can just return that. Otherwise, wrap it
                        // with an `InternalError` code.
                        match e.downcast::<jsonrpsee::types::ErrorObjectOwned>() {
                            Ok(e) => e,
                            Err(e) => {
                                if !e.to_string().starts_with("Txn Hash not Present") {
                                     tracing::error!(?e);
                                }
                                jsonrpsee::types::ErrorObject::owned(
                                jsonrpsee::types::error::ErrorCode::InternalError.code(),
                                e.to_string(),
                                None as Option<String>,
                            )}
                        }
                    });
                    if let Err(err) = &result {
                        attributes.push(opentelemetry::KeyValue::new(opentelemetry_semantic_conventions::attribute::RPC_JSONRPC_ERROR_CODE, err.code() as i64));
                    }
                    rpc_server_duration.record(
                        start.elapsed().map_or(0.0, |d| d.as_secs_f64()),
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
