use std::{
    net::IpAddr,
    pin::Pin,
    str::FromStr,
    task::{Context, Poll},
};

use anyhow::Result;
use futures::{FutureExt, TryFutureExt};
use http::header::AUTHORIZATION;
use jsonrpsee::{
    core::BoxError,
    server::{HttpRequest, HttpResponse},
};
use serde::Serialize;
use tower::{Layer, Service};

const X_FORWARDED_FOR: &str = "x-forwarded-for";

/// Adds some extra data to the request
#[derive(Debug, Clone, Default)]
pub struct RpcExtensionLayer {
    // connection pool
}

impl RpcExtensionLayer {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<S> Layer<S> for RpcExtensionLayer {
    type Service = RpcExtensionHeader<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RpcExtensionHeader { inner }
    }
}

/// Every POST request is modified by added additional headers with information.
#[derive(Debug, Clone)]
pub struct RpcExtensionHeader<S> {
    inner: S,
    // connection pool
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
            .and_then(|list| list.split(',').next())
            .and_then(|first| IpAddr::from_str(first.trim()).ok());

        // add the remote-user
        let remote_user = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|val| val.to_str().ok())
            .map(|user| user.to_string());

        // Add extra underlying metadata to the request extension.
        req.extensions_mut().insert(RpcHeaderExt {
            remote_ip,
            remote_user,
        });

        self.inner.call(req).map_err(Into::into).boxed()
    }
}

/// Every POST request is modified by added additional headers with information.
#[derive(Debug, Clone, Serialize, Default)]
pub struct RpcHeaderExt {
    pub remote_ip: Option<IpAddr>,
    pub remote_user: Option<String>,
}

impl RpcHeaderExt {
    pub fn new(remote_ip: IpAddr, remote_user: String) -> Self {
        Self {
            remote_ip: Some(remote_ip),
            remote_user: Some(remote_user),
        }
    }
}
