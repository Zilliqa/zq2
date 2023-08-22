use std::{error::Error, pin::Pin};

use futures::Future;
use http::{Method, Request, Response, StatusCode};
use hyper::Body;
use tower::{layer::Layer, Service};

/// [Layer] that responds to `GET /health` calls with a 200 status code.
pub struct HealthLayer;

impl<S> Layer<S> for HealthLayer {
    type Service = HealthRequest<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HealthRequest { inner }
    }
}

pub struct HealthRequest<S> {
    inner: S,
}

impl<S> Service<Request<Body>> for HealthRequest<S>
where
    S: Service<Request<Body>, Response = Response<Body>>,
    S::Response: 'static,
    S::Error: Into<Box<dyn Error + Send + Sync>> + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = Box<dyn Error + Send + Sync + 'static>;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        if req.uri() == "/health" && req.method() == Method::GET {
            let response = hyper::Response::builder()
                .status(StatusCode::OK)
                .body(Body::empty())
                .unwrap();
            let res_fut = async move { Ok(response) };

            Box::pin(res_fut)
        } else {
            let fut = self.inner.call(req);
            let res_fut = async move {
                let res = fut.await.map_err(|err| err.into())?;
                Ok(res)
            };

            Box::pin(res_fut)
        }
    }
}
