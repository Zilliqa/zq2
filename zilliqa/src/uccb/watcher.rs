use std::sync::Arc;

use alloy::{
    primitives::{Address, B256, Bytes, U256, address, b256},
    providers::{Provider as _, ProviderBuilder},
    rpc::types::{Filter, PackedUserOperation},
};
use anyhow::Result;
use futures::StreamExt as _;

use crate::{cfg::NodeConfig, crypto::SecretKey, db::Db, uccb::SignUserOp};

const ERC7786_GATEWAY: Address = address!("0x0000000071727de22e5e9d8baf0edac6f37da032");
const ERC7786_MESSAGE_SENT: B256 =
    b256!("0x7e7041a74283c799a9a3b681816e897e935a8f5c9e472685714c67cd6a578663");

#[derive(Debug)]
pub struct Watcher {
    config: NodeConfig,
    secret_key: SecretKey,
    db: Arc<Db>,
}

impl Watcher {
    pub fn new(config: NodeConfig, secret_key: SecretKey, db: Arc<Db>) -> Self {
        Self {
            secret_key,
            config,
            db,
        }
    }

    pub async fn start_watcher(&mut self) -> Result<()> {
        while let Some(logs) = watchers.next().await {
            for log in logs {
                if log.removed {
                    continue;
                }
                // construct partial UserOp
                let userop = Self::new_user_op();
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
