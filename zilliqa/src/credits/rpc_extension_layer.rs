use std::{
    net::IpAddr,
    pin::Pin,
    task::{Context, Poll},
};

use anyhow::Result;
use dashmap::DashSet;
use futures::{FutureExt, TryFutureExt};
use http::header::AUTHORIZATION;
use jsonrpsee::{
    core::BoxError,
    server::{HttpRequest, HttpResponse},
};
use serde::Serialize;
use tower::{Layer, Service};

const X_FORWARDED_FOR: &str = "x-forwarded-for";
const RATE_LIMIT_KEY: &str = "rate-limit-key";

/// Adds some extra data to the request
#[derive(Debug, Clone, Default)]
pub struct RpcExtensionLayer {
    allow_ips: DashSet<IpAddr>,
    allow_keys: DashSet<String>,
}

impl RpcExtensionLayer {
    pub fn new() -> Self {
        // allowed list of IP addresses to bypass RPC limits.
        let allow_ips = std::env::var("ALLOWED_IPS").map_or_else(
            |_| DashSet::new(), // empty list
            |csv| DashSet::from_iter(csv.split(',').filter_map(|ip| ip.trim().parse().ok())),
        );
        let allow_keys = std::env::var("ALLOWED_KEYS").map_or_else(
            |_| DashSet::new(), // empty list
            |csv| {
                DashSet::from_iter(
                    csv.split(',')
                        .filter_map(|key| key.trim().to_uppercase().parse().ok()),
                )
            },
        );
        Self {
            allow_ips,
            allow_keys,
        }
    }
}

impl<S> Layer<S> for RpcExtensionLayer {
    type Service = RpcExtensionHeader<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RpcExtensionHeader {
            inner,
            allow_ips: self.allow_ips.clone(),
            allow_keys: self.allow_keys.clone(),
        }
    }
}

/// Supplement each request with added additional metadata.
/// https://docs.rs/jsonrpsee/latest/jsonrpsee/struct.Extensions.html
#[derive(Debug, Clone)]
pub struct RpcExtensionHeader<S> {
    inner: S,
    allow_ips: DashSet<IpAddr>,
    allow_keys: DashSet<String>,
}

impl<S> Service<HttpRequest> for RpcExtensionHeader<S>
where
    S: Service<HttpRequest, Response = HttpResponse>,
    S::Response: 'static,
    S::Error: Into<BoxError> + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, mut req: HttpRequest) -> Self::Future {
        // add the remote-ip
        let remote_ip = req
            .headers()
            .get(X_FORWARDED_FOR)
            .and_then(|val| val.to_str().ok())
            .and_then(|list| list.split(',').rev().nth(1)) // https://cloud.google.com/load-balancing/docs/https#x-forwarded-for_header
            .and_then(|first| first.trim().parse().ok())
            .filter(|ip| {
                if self.allow_ips.contains(ip) {
                    tracing::debug!(%ip, "RPC bypass");
                    false
                } else {
                    true
                }
            });

        let remote_key = req
            .headers()
            .get(RATE_LIMIT_KEY)
            .and_then(|val| val.to_str().ok())
            .map(|key| key.to_uppercase()) // non-case-sensitive
            .filter(|key| {
                if self.allow_keys.contains(key) {
                    tracing::debug!(%key, "RPC bypass");
                    true
                } else {
                    false
                }
            });

        // TODO: user-based quotas
        let remote_user = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|val| val.to_str().ok())
            .map(|user| user.to_string());

        // Add extra underlying metadata to the request extension.
        req.extensions_mut().insert(RpcHeaderExt {
            remote_ip,
            remote_user,
            remote_key,
        });

        self.inner.call(req).map_err(Into::into).boxed()
    }
}

/// Every POST request is modified by added additional headers with information.
#[derive(Debug, Clone, Serialize, Default)]
pub struct RpcHeaderExt {
    pub remote_ip: Option<IpAddr>,
    pub remote_user: Option<String>,
    pub remote_key: Option<String>,
}
