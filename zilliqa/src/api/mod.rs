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

pub fn rpc_module(node: Arc<Node>, enabled_apis: &[EnabledApi]) -> RpcModule<Arc<Node>> {
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

    // Handle GET /health
    module
        .register_method(
            "system_health",
            |_, _, _| serde_json::json!({ "health": true }),
        )
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

use std::panic::PanicHookInfo;

thread_local! {
    pub static PANIC_INFO: std::cell::RefCell<Option<(String, String)>> = const { std::cell::RefCell::new(None) };
}

#[inline]
fn format_panic_as_error(name: &'static str) -> anyhow::Error {
    let (panic_msg, backtrace) = PANIC_INFO.with(|info| {
        info.borrow_mut().take().unwrap_or_else(|| {
            (
                "Unknown panic (no info captured)".to_string(),
                "No backtrace available".to_string(),
            )
        })
    });
    let error_msg =
        format!("Unhandled panic in RPC handler {name}: {panic_msg}\n\nBacktrace:\n{backtrace}");
    tracing::error!(
        "PANIC in RPC handler {}: {}\nBacktrace:\n{}",
        name,
        panic_msg,
        backtrace
    );
    anyhow::anyhow!(error_msg)
}

#[inline]
pub fn make_panic_hook() -> Box<dyn Fn(&PanicHookInfo) + Sync + Send + 'static> {
    Box::new(|panic_info: &PanicHookInfo| {
        let backtrace = std::backtrace::Backtrace::force_capture();
        let panic_msg = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "Unknown panic".to_string()
        };

        let location = if let Some(location) = panic_info.location() {
            format!(
                " at {}:{}:{}",
                location.file(),
                location.line(),
                location.column()
            )
        } else {
            String::new()
        };

        let full_panic_msg = format!("{panic_msg}{location}");

        PANIC_INFO.with(|info| {
            *info.borrow_mut() = Some((full_panic_msg, format!("{backtrace}")));
        });
    })
}

use anyhow::Error as AnyError;
use jsonrpsee::types::{ErrorObjectOwned as RpcError, error::ErrorCode};
#[inline]
pub fn into_rpc_error(e: AnyError) -> RpcError {
    // If it's already an RpcError, return it
    if let Some(existing) = e.downcast_ref::<RpcError>() {
        return existing.clone();
    }
    // Otherwise, log (unless it's the known benign case) and wrap as InternalError
    if !e.to_string().starts_with("Txn Hash not Present") {
        tracing::error!(error = %e);
    }
    RpcError::owned(
        ErrorCode::InternalError.code(),
        e.to_string(),
        Option::<String>::None,
    )
}

#[inline]
fn disabled_err(name: &'static str) -> RpcError {
    RpcError::owned(
        ErrorCode::InvalidRequest.code(),
        format!("{name} is disabled"),
        Option::<String>::None,
    )
}

use opentelemetry::KeyValue;
use opentelemetry_semantic_conventions::attribute::*;
#[inline]
fn rpc_base_attributes(method: &'static str) -> Vec<KeyValue> {
    vec![
        KeyValue::new(RPC_SYSTEM, "jsonrpc"),
        KeyValue::new(RPC_SERVICE, "zilliqa.eth"),
        KeyValue::new(RPC_METHOD, method),
        KeyValue::new(NETWORK_TRANSPORT, "tcp"),
        KeyValue::new(RPC_JSONRPC_VERSION, "2.0"),
    ]
}

enum HandlerType {
    Fast,
    Slow,
}

/// Returns an `RpcModule<Arc<Node>>`. Call with the following syntax:
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
/// where `node` is an `Arc<Node>` and each implementation method has the signature
/// `Fn(jsonrpsee::types::Params, &Arc<Node>) -> Result<T>`.
///
/// Will panic if any of the method names collide.
macro_rules! declare_module {
    (
        $node:expr,
        $enabled_apis:expr,
        [ $(($name:expr, $method:expr, $handler_type:expr)),* $(,)? ] $(,)?
    ) => {{
        let mut module: jsonrpsee::RpcModule<std::sync::Arc<crate::node::Node>> = jsonrpsee::RpcModule::new($node.clone());
        let meter = opentelemetry::global::meter("zilliqa");

        $(
            let enabled = $enabled_apis.iter().any(|n| n.enabled($name));
            let rpc_server_duration = meter
                .f64_histogram(opentelemetry_semantic_conventions::metric::RPC_SERVER_DURATION)
                .with_boundaries(vec![0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0])
                .with_unit("s")
                .build();


            match $handler_type {
                HandlerType::Slow => {
                    module
                    .register_blocking_method($name, move |params, context, _| {
                        tracing::debug!("API Call start {}: params: {:?}", $name, params);

                        if !enabled {
                            return Err(disabled_err($name));
                        }

                        let mut attributes = rpc_base_attributes($name);

                        let start = std::time::SystemTime::now();

                        // Store the original panic hook
                        let original_hook = std::panic::take_hook();

                        // Set our custom panic hook to capture backtrace
                        std::panic::set_hook(make_panic_hook());

                        #[allow(clippy::redundant_closure_call)]
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $method(params.clone(), &context)));

                        // Restore the original panic hook
                        std::panic::set_hook(original_hook);

                        let result = result.unwrap_or_else(|_| Err(format_panic_as_error($name)));

                        let result = result.map_err(into_rpc_error);

                        if let Err(err) = &result {
                            attributes.push(opentelemetry::KeyValue::new(opentelemetry_semantic_conventions::attribute::RPC_JSONRPC_ERROR_CODE, err.code() as i64));
                        }
                        let duration = start.elapsed().map_or(0.0, |d| d.as_secs_f64());

                        rpc_server_duration.record(
                            duration,
                            &attributes,
                        );
                        if duration > 1.0 {
                            tracing::error!("API Call long: {}{:?}, took {}s", $name, params, duration);
                        }
                        tracing::debug!("API Call end {}", $name);
                        result
                    })
                    .unwrap();
                }
                HandlerType::Fast => {
                    module
                    .register_method($name, move |params, context, _| {
                        tracing::debug!("API Call start {}: params: {:?}", $name, params);

                        if !enabled {
                            return Err(disabled_err($name));
                        }

                        let mut attributes = rpc_base_attributes($name);

                        let start = std::time::SystemTime::now();

                        // Store the original panic hook
                        let original_hook = std::panic::take_hook();

                        // Set our custom panic hook to capture backtrace
                        std::panic::set_hook(make_panic_hook());

                        #[allow(clippy::redundant_closure_call)]
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $method(params.clone(), context)));

                        // Restore the original panic hook
                        std::panic::set_hook(original_hook);

                        let result = result.unwrap_or_else(|_| Err(format_panic_as_error($name)));

                        let result = result.map_err(into_rpc_error);

                        if let Err(err) = &result {
                            attributes.push(opentelemetry::KeyValue::new(opentelemetry_semantic_conventions::attribute::RPC_JSONRPC_ERROR_CODE, err.code() as i64));
                        }
                        let duration = start.elapsed().map_or(0.0, |d| d.as_secs_f64());

                        rpc_server_duration.record(
                            duration,
                            &attributes,
                        );
                        if duration > 1.0 {
                            tracing::error!("API Call long: {}{:?}, took {}s", $name, params, duration);
                        }
                        tracing::debug!("API Call end {}", $name);
                        result
                    })
                    .unwrap();
                }
            }
        )*

        module
    }}
}

use std::sync::Arc;

use declare_module;
use jsonrpsee::RpcModule;

use crate::{cfg::EnabledApi, node::Node};
