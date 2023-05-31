use async_std::io;
use futures::prelude::*;

use async_trait::async_trait;
use libp2p::core::upgrade::{read_length_prefixed, write_length_prefixed, ProtocolName};
pub use libp2p::request_response::{self, ProtocolSupport, RequestId, ResponseChannel};

#[derive(Debug)]
pub enum Event {
    InboundRequest {
        request: String,
        channel: ResponseChannel<FileResponse>,
    },
}

#[derive(Debug, Clone)]
pub struct FileExchangeProtocol();
#[derive(Clone)]
pub struct FileExchangeCodec();
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRequest(pub String);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileResponse(pub Vec<u8>);

impl ProtocolName for FileExchangeProtocol {
    fn protocol_name(&self) -> &[u8] {
        "/file-exchange/1".as_bytes()
    }
}

#[async_trait]
impl request_response::Codec for FileExchangeCodec {
    type Protocol = FileExchangeProtocol;
    type Request = FileRequest;
    type Response = FileResponse;

    async fn read_request<T>(
        &mut self,
        _: &FileExchangeProtocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
        where
            T: AsyncRead + Unpin + Send,
    {
        let vec = read_length_prefixed(io, 1_000_000).await?;

        if vec.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }

        Ok(FileRequest(String::from_utf8(vec).unwrap()))
    }

    async fn read_response<T>(
        &mut self,
        _: &FileExchangeProtocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
        where
            T: AsyncRead + Unpin + Send,
    {
        let vec = read_length_prefixed(io, 500_000_000).await?; // update transfer maximum

        if vec.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }

        Ok(FileResponse(vec))
    }

    async fn write_request<T>(
        &mut self,
        _: &FileExchangeProtocol,
        io: &mut T,
        FileRequest(data): FileRequest,
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
        _: &FileExchangeProtocol,
        io: &mut T,
        FileResponse(data): FileResponse,
    ) -> io::Result<()>
        where
            T: AsyncWrite + Unpin + Send,
    {
        write_length_prefixed(io, data).await?;
        io.close().await?;

        Ok(())
    }
}
