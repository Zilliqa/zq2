use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use primitive_types::{H160, H256};
use serde_json::Value;

use crate::node::Node;

use super::{
    types::{
        Balance, BlockchainInfo, DsBlock, DsBlockListing, MinerInfo, NewTransaction, StateProof,
        Transaction, TransactionInfo, TransactionStatus, TxBlock, TxBlockListing,
        TxBodiesForTxBlockEx, TxForTxBlockEx,
    },
    zilliqa::Api,
};

#[rustfmt::skip] // To keep things compact while most of this is `todo()`.
impl Api for Arc<Mutex<Node>> {
    fn ds_block_listing(&self, _: u64) -> Result<DsBlockListing> { todo() }
    fn get_blockchain_info(&self) -> Result<BlockchainInfo> { todo() }
    fn get_current_ds_epoch(&self) -> Result<u64> { todo() }
    fn get_current_tx_epoch(&self) -> Result<u64> { todo() }
    fn get_ds_block(&self, _: u64) -> Result<DsBlock> { todo() }
    fn get_ds_block_rate(&self) -> Result<f64> { todo() }
    fn get_miner_info(&self, _: u64) -> Result<MinerInfo> { todo() }
    fn get_network_id(&self) -> Result<u32> { todo() }
    fn get_num_transactions(&self) -> Result<u64> { todo() }
    fn get_prev_difficulty(&self) -> Result<u64> { todo() }
    fn get_prev_ds_difficulty(&self) -> Result<u64> { todo() }
    fn get_total_coin_supply(&self) -> Result<u128> { todo() }
    fn get_tx_rate(&self) -> Result<f64> { todo() }
    fn get_tx_block(&self, _: u64) -> Result<TxBlock> { todo() }
    fn get_tx_block_rate(&self) -> Result<f64> { todo() }
    fn tx_block_listing(&self, _: u64) -> Result<TxBlockListing> { todo() }
    fn create_transaction(&self, _: NewTransaction) -> Result<TransactionInfo> { todo() }
    fn get_minimum_gas_price(&self) -> Result<u128> { todo() }
    fn get_num_txns_ds_epoch(&self) -> Result<u64> { todo() }
    fn get_num_txns_tx_epoch(&self) -> Result<u64> { todo() }
    fn get_recent_transactions(&self) -> Result<Vec<H256>> { todo() }
    fn get_transaction(&self, _: H256) -> Result<Transaction> { todo() }
    fn get_transaction_status(&self, _: H256) -> Result<TransactionStatus> { todo() }
    fn get_transactions_for_tx_block(&self, _: u64) -> Result<Vec<Vec<H256>>> { todo() }
    fn get_transactions_for_tx_block_ex(&self, _: u64, _: u64) -> Result<TxForTxBlockEx> { todo() }
    fn get_tx_bodies_for_tx_block(&self, _: u64) -> Result<Vec<Transaction>> { todo() }
    fn get_tx_bodies_for_tx_block_ex(&self, _: u64, _: u64) -> Result<TxBodiesForTxBlockEx> { todo() }
    fn get_contract_address_from_transaction_id(&self, _: H256) -> Result<H160> { todo() }
    fn get_smart_contract_code(&self, _: H160) -> Result<String> { todo() }
    fn get_smart_contract_init(&self, _: H160) -> Result<Value> { todo() }
    fn get_smart_contracts(&self, _: H160) -> Result<Vec<H160>> { todo() }
    fn get_smart_contract_state(&self, _: H160) -> Result<Value> { todo() }
    fn get_smart_contract_sub_state(&self, _: H160, _: Option<String>, _: Vec<Value>) -> Result<Value> { todo() }
    fn get_state_proof(&self, _: H160, _: H256, _: String) -> Result<StateProof> { todo() }
    fn get_balance(&self, _: H160) -> Result<Balance> { todo() }
}

fn todo<T>() -> Result<T> {
    Err(anyhow!("not yet implemented"))
}
