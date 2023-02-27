//! The Zilliqa API, as documented at <https://dev.zilliqa.com/api/introduction/api-introduction>.

use anyhow::Result;
use jsonrpsee::RpcModule;
use primitive_types::{H160, H256};
use serde_json::Value;

use super::types::{
    Balance, BlockchainInfo, DsBlock, DsBlockListing, MinerInfo, NewTransaction, StateProof,
    Transaction, TransactionInfo, TransactionStatus, TxBlock, TxBlockListing, TxBodiesForTxBlockEx,
    TxForTxBlockEx,
};

pub fn rpc_module<T>(api: T) -> RpcModule<Box<dyn Api + Send + Sync>>
where
    T: Api + Send + Sync + 'static,
{
    let api: Box<dyn Api + Send + Sync> = Box::new(api);
    let mut module = RpcModule::new(api);

    // Blockchain-related methods
    module
        .register_method("DsBlockListing", |params, api| {
            let page = params.one()?;
            Ok(api.ds_block_listing(page)?)
        })
        .unwrap();
    module
        .register_method("GetBlockchainInfo", |_, api| Ok(api.get_blockchain_info()?))
        .unwrap();
    module
        .register_method("GetCurrentDSEpoch", |_, api| {
            Ok(api.get_current_ds_epoch()?.to_string())
        })
        .unwrap();
    module
        .register_method("GetCurrentMiniEpoch", |_, api| {
            Ok(api.get_current_tx_epoch()?.to_string())
        })
        .unwrap();
    module
        .register_method("GetDsBlock", |params, api| {
            let ds_block = params.one()?;
            Ok(api.get_ds_block(ds_block)?)
        })
        .unwrap();
    module
        .register_method("GetDSBlockRate", |_, api| Ok(api.get_ds_block_rate()?))
        .unwrap();
    module
        .register_method("GetLatestDsBlock", |_, api| Ok(api.get_latest_ds_block()?))
        .unwrap();
    module
        .register_method("GetLatestTxBlock", |_, api| Ok(api.get_latest_tx_block()?))
        .unwrap();
    module
        .register_method("GetMinerInfo", |params, api| {
            let ds_block = params.one()?;
            Ok(api.get_miner_info(ds_block)?)
        })
        .unwrap();
    module
        .register_method("GetNetworkId", |_, api| {
            Ok(api.get_network_id()?.to_string())
        })
        .unwrap();
    module
        .register_method("GetNumDSBlocks", |_, api| {
            Ok(api.get_num_ds_blocks()?.to_string())
        })
        .unwrap();
    module
        .register_method("GetNumTransactions", |_, api| {
            Ok(api.get_num_transactions()?.to_string())
        })
        .unwrap();
    module
        .register_method("GetNumTxBlocks", |_, api| {
            Ok(api.get_num_tx_blocks()?.to_string())
        })
        .unwrap();
    module
        .register_method("GetPrevDifficulty", |_, api| Ok(api.get_prev_difficulty()?))
        .unwrap();
    module
        .register_method("GetPrevDSDifficulty", |_, api| {
            Ok(api.get_prev_ds_difficulty()?)
        })
        .unwrap();
    module
        .register_method("GetTotalCoinSupply", |_, api| {
            Ok(api.get_total_coin_supply()?)
        })
        .unwrap();
    module
        .register_method("GetTransactionRate", |_, api| Ok(api.get_tx_rate()?))
        .unwrap();
    module
        .register_method("GetTxBlock", |params, api| {
            let tx_block = params.one()?;
            Ok(api.get_tx_block(tx_block)?)
        })
        .unwrap();
    module
        .register_method("GetTxBlockRate", |_, api| Ok(api.get_tx_block_rate()?))
        .unwrap();
    module
        .register_method("TxBlockListing", |params, api| {
            let page = params.one()?;
            Ok(api.tx_block_listing(page)?)
        })
        .unwrap();

    // Transaction-related methods
    module
        .register_method("CreateTransaction", |params, api| {
            let transaction = params.one()?;
            Ok(api.create_transaction(transaction)?)
        })
        .unwrap();
    module
        .register_method("GetMinimumGasPrice", |_, api| {
            Ok(api.get_minimum_gas_price()?.to_string())
        })
        .unwrap();
    module
        .register_method("GetNumTxnsDSEpoch", |_, api| {
            Ok(api.get_num_txns_ds_epoch()?.to_string())
        })
        .unwrap();
    module
        .register_method("GetNumTxnsTxEpoch", |_, api| {
            Ok(api.get_num_txns_tx_epoch()?.to_string())
        })
        .unwrap();
    module
        .register_method("GetRecentTransactions", |_, api| {
            Ok(api.get_recent_transactions()?)
        })
        .unwrap();
    module
        .register_method("GetTransaction", |params, api| {
            let txn_hash = params.one()?;
            Ok(api.get_transaction(txn_hash)?)
        })
        .unwrap();
    module
        .register_method("GetTransactionStatus", |params, api| {
            let txn_hash = params.one()?;
            Ok(api.get_transaction_status(txn_hash)?)
        })
        .unwrap();
    module
        .register_method("GetTransactionsForTxBlock", |params, api| {
            let tx_block = params.one()?;
            Ok(api.get_transactions_for_tx_block(tx_block)?)
        })
        .unwrap();
    module
        .register_method("GetTransactionsForTxBlockEx", |params, api| {
            let (tx_block, page) = params.parse()?;
            Ok(api.get_transactions_for_tx_block_ex(tx_block, page)?)
        })
        .unwrap();
    module
        .register_method("GetTxnBodiesForTxBlock", |params, api| {
            let tx_block = params.one()?;
            Ok(api.get_tx_bodies_for_tx_block(tx_block)?)
        })
        .unwrap();
    module
        .register_method("GetTxnBodiesForTxBlockEx", |params, api| {
            let (tx_block, page) = params.parse()?;
            Ok(api.get_tx_bodies_for_tx_block_ex(tx_block, page)?)
        })
        .unwrap();

    // Contract-related methods
    module
        .register_method("GetContractAddressFromTransactionID", |params, api| {
            let txn_hash = params.one()?;
            Ok(api.get_contract_address_from_transaction_id(txn_hash)?)
        })
        .unwrap();
    module
        .register_method("GetSmartContractCode", |params, api| {
            let address = params.one()?;
            Ok(api.get_smart_contract_code(address)?)
        })
        .unwrap();
    module
        .register_method("GetSmartContractInit", |params, api| {
            let address = params.one()?;
            Ok(api.get_smart_contract_init(address)?)
        })
        .unwrap();
    module
        .register_method("GetSmartContracts", |params, api| {
            let address = params.one()?;
            Ok(api
                .get_smart_contracts(address)?
                .into_iter()
                .map(|a| serde_json::json!({ "address": a }))
                .collect::<Vec<_>>())
        })
        .unwrap();
    module
        .register_method("GetSmartContractState", |params, api| {
            let address = params.one()?;
            Ok(api.get_smart_contract_state(address)?)
        })
        .unwrap();
    module
        .register_method("GetSmartContractSubState", |params, api| {
            let (address, variable, indices) = params.parse()?;
            Ok(api.get_smart_contract_sub_state(address, variable, indices)?)
        })
        .unwrap();
    module
        .register_method("GetStateProof", |params, api| {
            let (address, variable_hash, tx_block) = params.parse()?;
            Ok(api.get_state_proof(address, variable_hash, tx_block)?)
        })
        .unwrap();

    // Account-related methods
    module
        .register_method("GetBalance", |params, api| {
            let address = params.one()?;
            Ok(api.get_balance(address)?)
        })
        .unwrap();

    module
}

pub trait Api {
    fn ds_block_listing(&self, page: u64) -> Result<DsBlockListing>;
    fn get_blockchain_info(&self) -> Result<BlockchainInfo>;
    fn get_current_ds_epoch(&self) -> Result<u64>;
    fn get_current_tx_epoch(&self) -> Result<u64>;
    fn get_ds_block(&self, ds_block: u64) -> Result<DsBlock>;
    fn get_ds_block_rate(&self) -> Result<f64>;
    fn get_latest_ds_block(&self) -> Result<DsBlock> {
        self.get_ds_block(self.get_current_ds_epoch()?)
    }
    fn get_latest_tx_block(&self) -> Result<TxBlock> {
        self.get_tx_block(self.get_current_tx_epoch()?)
    }
    fn get_miner_info(&self, ds_block: u64) -> Result<MinerInfo>;
    fn get_network_id(&self) -> Result<u32>;
    fn get_num_ds_blocks(&self) -> Result<u64> {
        Ok(self.get_current_ds_epoch()? + 1)
    }
    fn get_num_transactions(&self) -> Result<u64>;
    fn get_num_tx_blocks(&self) -> Result<u64> {
        self.get_current_tx_epoch()
    }
    fn get_prev_difficulty(&self) -> Result<u64>;
    fn get_prev_ds_difficulty(&self) -> Result<u64>;
    fn get_total_coin_supply(&self) -> Result<u128>;
    fn get_tx_rate(&self) -> Result<f64>;
    fn get_tx_block(&self, tx_block: u64) -> Result<TxBlock>;
    fn get_tx_block_rate(&self) -> Result<f64>;
    fn tx_block_listing(&self, page: u64) -> Result<TxBlockListing>;
    fn create_transaction(&self, transaction: NewTransaction) -> Result<TransactionInfo>;
    fn get_minimum_gas_price(&self) -> Result<u128>;
    fn get_num_txns_ds_epoch(&self) -> Result<u64>;
    fn get_num_txns_tx_epoch(&self) -> Result<u64>;
    fn get_recent_transactions(&self) -> Result<Vec<H256>>;
    fn get_transaction(&self, txn_hash: H256) -> Result<Transaction>;
    fn get_transaction_status(&self, txn_hash: H256) -> Result<TransactionStatus>;
    fn get_transactions_for_tx_block(&self, tx_block: u64) -> Result<Vec<Vec<H256>>>;
    fn get_transactions_for_tx_block_ex(&self, tx_block: u64, page: u64) -> Result<TxForTxBlockEx>;
    fn get_tx_bodies_for_tx_block(&self, tx_block: u64) -> Result<Vec<Transaction>>;
    fn get_tx_bodies_for_tx_block_ex(
        &self,
        tx_block: u64,
        page: u64,
    ) -> Result<TxBodiesForTxBlockEx>;

    fn get_contract_address_from_transaction_id(&self, txn_hash: H256) -> Result<H160>;
    fn get_smart_contract_code(&self, address: H160) -> Result<String>;
    fn get_smart_contract_init(&self, address: H160) -> Result<Value>;
    fn get_smart_contracts(&self, address: H160) -> Result<Vec<H160>>;
    fn get_smart_contract_state(&self, address: H160) -> Result<Value>;
    fn get_smart_contract_sub_state(
        &self,
        address: H160,
        variable: Option<String>,
        indices: Vec<Value>,
    ) -> Result<Value>;
    fn get_state_proof(
        &self,
        address: H160,
        variable_hash: H256,
        tx_block: String,
    ) -> Result<StateProof>;
    fn get_balance(&self, address: H160) -> Result<Balance>;
}
