use futures::prelude::*;
use std::io;

use async_trait::async_trait;
use libp2p::core::upgrade::{read_length_prefixed, write_length_prefixed, ProtocolName};
pub use libp2p::request_response::{self, ProtocolSupport, RequestId, ResponseChannel};
use tracing::error;
use crate::message;

#[derive(Debug, Clone)]
pub struct MessageProtocol();
#[derive(Clone)]
pub struct MessageCodec();

//#[derive(Debug, Clone, PartialEq, Eq)]
//pub struct Request(pub Vec<u8>);
//#[derive(Debug, Clone, PartialEq, Eq)]
//pub struct Response(pub Vec<u8>);

impl ProtocolName for MessageProtocol {
    fn protocol_name(&self) -> &[u8] {
        b"/zq2-message/1"
    }
}

#[async_trait]
impl request_response::Codec for MessageCodec {
    type Protocol = MessageProtocol;
    type Request = message::Message;
    type Response = message::Message;

    async fn read_request<T>(
        &mut self,
        _: &MessageProtocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let vec = read_length_prefixed(io, 1_000_000).await?;

        if vec.is_empty() {
            error!("Received empty request - this causes your connection to drop!");
            return Err(io::ErrorKind::UnexpectedEof.into());
        }

        serde_json::from_slice::<Self::Response>(&vec);
    }

    async fn read_response<T>(
        &mut self,
        _: &MessageProtocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let vec = read_length_prefixed(io, 500_000_000).await?; // update transfer maximum

        if vec.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }

        serde_json::from_slice::<Self::Response>(&vec);
    }

    async fn write_request<T>(
        &mut self,
        _: &MessageProtocol,
        io: &mut T,
        data: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data = serde_json::to_vec(&data).unwrap();
        write_length_prefixed(io, data).await?;
        io.close().await?;

        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &MessageProtocol,
        io: &mut T,
        data: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data = serde_json::to_vec(&data).unwrap();
        write_length_prefixed(io, data).await?;
        io.close().await?;

        Ok(())
    }
}
