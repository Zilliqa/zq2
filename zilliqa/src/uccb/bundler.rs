use alloy::{
    primitives::{Address, B256},
    providers::{
        Identity, Provider as _, ProviderBuilder, RootProvider,
        fillers::{BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller},
    },
    rpc::types::{PackedUserOperation, SendUserOperation, SendUserOperationResponse},
};
use anyhow::Result;
use jsonrpsee::client_transport::ws::Url;

use crate::crypto::Hash;

/// Wrapper around a provider for a specific Bundler
pub struct Bundler {
    entrypoint: Address,
    provider: FillProvider<
        JoinFill<
            Identity,
            JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
        >,
        RootProvider,
    >,
}

impl Bundler {
    pub fn new(url: Url, entrypoint: Address) -> Self {
        let provider = ProviderBuilder::new().connect_hyper_http(url);
        Self {
            entrypoint,
            provider,
        }
    }

    pub async fn sendUserOp(
        &self,
        userop: PackedUserOperation,
        hash: Hash,
    ) -> Result<SendUserOperationResponse> {
        let send_op = SendUserOperation::EntryPointV07(userop);

        // Check if it is already submitted
        // self.provider.raw_request("eth_getUserOpByHash".into())

        // Send via raw JSON-RPC — the bundler exposes eth_sendUserOperation
        // params: [userOperation, entryPointAddress]
        Ok(self
            .provider
            .raw_request(
                "eth_sendUserOperation".into(),
                (send_op, super::ENTRYPOINT_V07), // FIXME: Use suitable one
            )
            .await?)
    }

    pub fn getNonce() -> Result<B256> {
        Ok(B256::ZERO)
    }

    pub async fn getUserOpHash(userop: PackedUserOperation) -> Result<Hash> {
        let send_op = SendUserOperation::EntryPointV07(userop);
        Ok(Hash::ZERO)
    }
}
