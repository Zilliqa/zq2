use alloy::{
    primitives::Bytes,
    primitives::U256,
    primitives::{Address, B256, address, b256},
    providers::{Provider as _, ProviderBuilder},
    rpc::types::{Filter, PackedUserOperation},
};
use anyhow::Result;
use futures::StreamExt as _;

use crate::{cfg::NodeConfig, crypto::SecretKey, uccb::SignUserOp};

const ERC7786_GATEWAY: Address = address!("0x0000000071727de22e5e9d8baf0edac6f37da032");
const ERC7786_MESSAGE_SENT: B256 =
    b256!("0x7e7041a74283c799a9a3b681816e897e935a8f5c9e472685714c67cd6a578663");

pub struct Watcher {
    config: NodeConfig,
    secret_key: SecretKey,
}

impl Watcher {
    pub fn new(config: NodeConfig, secret_key: SecretKey) -> Self {
        Self { secret_key, config }
    }

    pub async fn start_watcher(&mut self) -> Result<()> {
        // Spawn watchers: one for each SOURCE_CHAIN
        // Each thread will monitor logs for MESSAGE_SENT events, then:
        // 1. Construct the initial UserOp
        // 2. Send it to the processing queue.
        tracing::info!("Spawn {} SIGNER watchers", self.config.watchers.len());
        let mut watchers = futures::stream::SelectAll::new();
        for watcher in self.config.watchers.iter() {
            let rpc_url = watcher.rpc_url.clone();
            let provider = ProviderBuilder::new().connect_hyper_http(rpc_url);
            let filter = Filter::new()
                .address(ERC7786_GATEWAY)
                .event_signature(ERC7786_MESSAGE_SENT);
            let stream = provider.watch_logs(&filter).await?.into_stream();
            watchers.push(stream);
        }

        while let Some(logs) = watchers.next().await {
            for log in logs {
                // construct partial UserOp
                let userop = Self::new_user_op();

                // sign
                let op = SignUserOp {
                    blk_hash: log.block_hash.expect("block_hash != none").into(),
                    txn_hash: log.transaction_hash.expect("txn_hash != none").into(),
                    chain: 0,
                    userop: userop,
                };
                tracing::trace!(hash=%op.txn_hash,"MessageSent");
                // self.sign_tx.send(op).await?;
            }
        }

        Ok(())
    }

    /// Construct a UserOp
    pub fn new_user_op() -> PackedUserOperation {
        PackedUserOperation {
            sender: Address::random(),
            nonce: U256::ZERO,
            factory: Some(Address::random()),
            factory_data: Some(Bytes::new()),
            call_data: Bytes::new(),
            call_gas_limit: U256::random(),
            verification_gas_limit: U256::random(),
            pre_verification_gas: U256::random(),
            max_fee_per_gas: U256::random(),
            max_priority_fee_per_gas: U256::random(),
            paymaster: Some(Address::random()),
            paymaster_verification_gas_limit: Some(U256::random()),
            paymaster_post_op_gas_limit: Some(U256::random()),
            paymaster_data: Some(Bytes::new()),
            signature: Bytes::new(),
        }
    }
}
