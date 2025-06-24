pub mod admin;
mod debug;
mod erigon;
pub mod eth;
mod net;
pub mod ots;
pub mod subscription_id_provider;
pub mod to_hex;
mod trace;
mod txpool;
pub mod types;
mod web3;
pub mod zilliqa;

pub fn rpc_module(
    node: Arc<RwLock<Node>>,
    enabled_apis: &[EnabledApi],
) -> RpcModule<Arc<RwLock<Node>>> {
    let mut module = RpcModule::new(node.clone());

    module
        .merge(admin::rpc_module(node.clone(), enabled_apis))
        .unwrap();
    module
        .merge(debug::rpc_module(node.clone(), enabled_apis))
        .unwrap();
    module
        .merge(erigon::rpc_module(node.clone(), enabled_apis))
        .unwrap();
    module
        .merge(eth::rpc_module(node.clone(), enabled_apis))
        .unwrap();
    module
        .merge(net::rpc_module(node.clone(), enabled_apis))
        .unwrap();
    module
        .merge(ots::rpc_module(node.clone(), enabled_apis))
        .unwrap();
    module
        .merge(trace::rpc_module(node.clone(), enabled_apis))
        .unwrap();
    module
        .merge(txpool::rpc_module(node.clone(), enabled_apis))
        .unwrap();
    module
        .merge(web3::rpc_module(node.clone(), enabled_apis))
        .unwrap();
    module
        .merge(zilliqa::rpc_module(node.clone(), enabled_apis))
        .unwrap();

    module
}

pub fn all_enabled() -> Vec<crate::cfg::EnabledApi> {
    [
        "admin", "debug", "erigon", "eth", "net", "ots", "trace", "txpool", "web3", "zilliqa",
    ]
    .into_iter()
    .map(|ns| crate::cfg::EnabledApi::EnableAll(ns.to_owned()))
    .collect()
}

/// Returns an `RpcModule<Arc<RwLock<Node>>>`. Call with the following syntax:
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
/// where `node` is an `Arc<RwLock<Node>>` and each implementation method has the signature
/// `Fn(jsonrpsee::types::Params, &Arc<RwLock<Node>>) -> Result<T>`.
///
/// Will panic if any of the method names collide.
macro_rules! declare_module {
    (
        $node:expr,
        $enabled_apis:expr,
        [ $(($name:expr, $method:expr)),* $(,)? ] $(,)?
    ) => {{
        let mut module: jsonrpsee::RpcModule<std::sync::Arc<parking_lot::RwLock<crate::node::Node>>> = jsonrpsee::RpcModule::new($node.clone());
        let meter = opentelemetry::global::meter("zilliqa");

        $(
            let enabled = $enabled_apis.iter().any(|n| n.enabled($name));
            let rpc_server_duration = meter
                .f64_histogram(opentelemetry_semantic_conventions::metric::RPC_SERVER_DURATION)
                .with_boundaries(vec![0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0])
                .with_unit("s")
                .build();
            module
                .register_method($name, move |params, context, metadata| {
                    tracing::debug!("Full metadata: {:?}", metadata);
                    let a = metadata.get::<http::HeaderMap>();
                    tracing::debug!("all metadata HeaderMap: {:?}", a);
                    let forwarded_for = if let Some(headers) = metadata.get::<http::HeaderMap>() {
                        headers.get("x-forwarded-for")
                        .and_then(|h| h.to_str().ok())
                        .unwrap_or("not provided")
                    } else {
                        "not provided"
                    };
                    tracing::debug!("{}: params: {:?}, X-Forwarded-For: {}", $name, params, forwarded_for);

                    if !enabled {
                        return Err(jsonrpsee::types::ErrorObject::owned(
                            jsonrpsee::types::error::ErrorCode::InvalidRequest.code(),
                            format!("{} is disabled", $name),
                            None as Option<String>,
                        ));
                    }

                    let mut attributes = vec![
                        opentelemetry::KeyValue::new(opentelemetry_semantic_conventions::attribute::RPC_SYSTEM, "jsonrpc"),
                        opentelemetry::KeyValue::new(opentelemetry_semantic_conventions::attribute::RPC_SERVICE, "zilliqa.eth"),
                        opentelemetry::KeyValue::new(opentelemetry_semantic_conventions::attribute::RPC_METHOD, $name),
                        opentelemetry::KeyValue::new(opentelemetry_semantic_conventions::attribute::NETWORK_TRANSPORT, "tcp"),
                        opentelemetry::KeyValue::new(opentelemetry_semantic_conventions::attribute::RPC_JSONRPC_VERSION, "2.0"),
                    ];

                    let start = std::time::SystemTime::now();

                    #[allow(clippy::redundant_closure_call)]
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $method(params, context))).unwrap_or_else(|cause| {
                        Err(anyhow::anyhow!("Unhandled panic in RPC handler {} : {:?}", $name, cause))
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

use std::sync::Arc;

use declare_module;
use jsonrpsee::RpcModule;
use parking_lot::RwLock;

use crate::{cfg::EnabledApi, node::Node};
