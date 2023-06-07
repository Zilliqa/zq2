use std::io;
use futures::prelude::*;

use async_trait::async_trait;
use libp2p::core::upgrade::{read_length_prefixed, write_length_prefixed, ProtocolName};
pub use libp2p::request_response::{self, ProtocolSupport, RequestId, ResponseChannel};
use tracing::error;

#[derive(Debug, Clone)]
pub struct Zq2MessageProtocol();
#[derive(Clone)]
pub struct Zq2MessageCodec();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zq2Request(pub Vec<u8>);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zq2Response(pub Vec<u8>);

impl ProtocolName for Zq2MessageProtocol {
    fn protocol_name(&self) -> &[u8] {
        b"/zq2-message/1"
    }
}

#[async_trait]
impl request_response::Codec for Zq2MessageCodec {
    type Protocol = Zq2MessageProtocol;
    type Request = Zq2Request;
    type Response = Zq2Response;

    async fn read_request<T>(
        &mut self,
        _: &Zq2MessageProtocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let vec = read_length_prefixed(io, 1_000_000).await?;

        if vec.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }

        Ok(Zq2Request(vec))
    }

    async fn read_response<T>(
        &mut self,
        _: &Zq2MessageProtocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let vec = read_length_prefixed(io, 500_000_000).await?; // update transfer maximum

        if vec.is_empty() {
            error!("empty response - in request-response. This causes your connections to drop.");
            return Err(io::ErrorKind::UnexpectedEof.into());
        }

        Ok(Zq2Response(vec))
    }

    async fn write_request<T>(
        &mut self,
        _: &Zq2MessageProtocol,
        io: &mut T,
        Zq2Request(data): Zq2Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_length_prefixed(io, data).await?;
        io.close().await?;

        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &Zq2MessageProtocol,
        io: &mut T,
        Zq2Response(data): Zq2Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_length_prefixed(io, data).await?;
        io.close().await?;

        Ok(())
    }
}
