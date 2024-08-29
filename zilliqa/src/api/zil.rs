//! The Zilliqa API, as documented at <https://dev.zilliqa.com/api/introduction/api-introduction>.

use std::{
    fmt::Display,
    str::FromStr,
    sync::{Arc, Mutex},
};

use alloy::{
    eips::BlockId,
    primitives::{Address, B256},
};
use anyhow::{anyhow, Result};
use jsonrpsee::{types::Params, RpcModule};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};

use super::{
    to_hex::ToHex,
    types::zil::{
        self, BlockchainInfo, DSBlock, DSBlockHeaderVerbose, DSBlockListing, DSBlockListingResult,
        DSBlockRateResult, DSBlockVerbose, GetCurrentDSCommResult, PoWWinnerIP, SWInfo,
        ShardingStructure, SmartContract,
    },
};
use crate::{
    api::types::zil::{CreateTransactionResponse, GetTxResponse, RPCErrorCode},
    crypto::Hash,
    exec::zil_contract_address,
    node::Node,
    schnorr,
    scilla::split_storage_key,
    state::Code,
    transaction::{ScillaGas, SignedTransaction, TxZilliqa, ZilAmount, EVM_GAS_PER_SCILLA_GAS},
};

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(
        node,
        [
            ("CreateTransaction", create_transaction),
            (
                "GetContractAddressFromTransactionID",
                get_contract_address_from_transaction_id
            ),
            ("GetBlockchainInfo", get_blockchain_info),
            ("GetNumTxBlocks", get_num_tx_blocks),
            ("GetSmartContractState", get_smart_contract_state),
            ("GetSmartContractCode", get_smart_contract_code),
            ("GetSmartContractInit", get_smart_contract_init),
            ("GetTransaction", get_transaction),
            ("GetBalance", get_balance),
            ("GetCurrentMiniEpoch", get_current_mini_epoch),
            ("GetLatestTxBlock", get_latest_tx_block),
            ("GetMinimumGasPrice", get_minimum_gas_price),
            ("GetNetworkId", get_network_id),
            ("GetVersion", get_version),
            ("GetTransactionsForTxBlock", get_transactions_for_tx_block),
            ("GetTxBlock", |p, n| get_tx_block(p, n, false)),
            ("GetTxBlockVerbose", |p, n| get_tx_block(p, n, true)),
            ("GetSmartContracts", get_smart_contracts),
            ("GetDSBlock", get_ds_block),
            ("GetDSBlockVerbose", get_ds_block_verbose),
            ("GetLatestDSBlock", get_latest_ds_block),
            ("GetCurrentDSComm", get_current_ds_comm),
            ("GetCurrentDSEpoch", get_current_ds_epoch),
            ("DSBlockListing", ds_block_listing),
            ("GetDSBlockRate", get_ds_block_rate),
        ],
    )
}

#[derive(Deserialize)]
#[serde(transparent)]
struct ZilAddress {
    #[serde(deserialize_with = "deserialize_zil_address")]
    inner: Address,
}

impl From<ZilAddress> for Address {
    fn from(value: ZilAddress) -> Self {
        value.inner
    }
}

fn deserialize_zil_address<'de, D>(deserializer: D) -> Result<Address, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error as E;

    let s = String::deserialize(deserializer)?;

    bech32::decode(&s).map_or_else(
        |_| s.parse().map_err(E::custom),
        |(hrp, data)| {
            if hrp.as_str() == "zil" {
                (&data[..]).try_into().map_err(E::custom)
            } else {
                Err(E::custom("Invalid HRP, expected 'zil'"))
            }
        },
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransactionParams {
    version: u32,
    nonce: u64,
    to_addr: Address,
    #[serde(deserialize_with = "from_str")]
    amount: ZilAmount,
    pub_key: String,
    #[serde(deserialize_with = "from_str")]
    gas_price: ZilAmount,
    #[serde(deserialize_with = "from_str")]
    gas_limit: ScillaGas,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    data: Option<String>,
    signature: String,
}

fn from_str<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: Display,
{
    let s = String::deserialize(deserializer)?;
    s.parse().map_err(serde::de::Error::custom)
}

fn create_transaction(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<CreateTransactionResponse> {
    let transaction: TransactionParams = params.one()?;
    let mut node = node.lock().unwrap();

    let version = transaction.version & 0xffff;
    let chain_id = transaction.version >> 16;

    if (chain_id as u64) != (node.chain_id.zil) {
        return Err(anyhow!(
            "unexpected chain ID, expected: {}, got: {chain_id}",
            node.chain_id.zil
        ));
    }

    if version != 1 {
        return Err(anyhow!("unexpected version, expected: 1, got: {version}"));
    }

    let key = hex::decode(transaction.pub_key)?;

    let key = schnorr::PublicKey::from_sec1_bytes(&key)?;
    let sig = schnorr::Signature::from_str(&transaction.signature)?;

    // TODO: Perform some initial validation of the transaction

    let transaction = SignedTransaction::Zilliqa {
        tx: TxZilliqa {
            chain_id: chain_id as u16,
            nonce: transaction.nonce,
            gas_price: transaction.gas_price,
            gas_limit: transaction.gas_limit,
            to_addr: transaction.to_addr,
            amount: transaction.amount,
            code: transaction.code.unwrap_or_default(),
            data: transaction.data.unwrap_or_default(),
        },
        key,
        sig,
    };

    let transaction_hash = node.create_transaction(transaction.clone())?;

    let response = CreateTransactionResponse {
        contract_address: None,
        info: "Txn processed".to_string(),
        tran_id: transaction_hash.0.into(),
    };

    Ok(response)
}

fn get_contract_address_from_transaction_id(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<String> {
    let hash: B256 = params.one()?;
    let hash: Hash = Hash(hash.0);
    let receipt = node
        .lock()
        .unwrap()
        .get_transaction_receipt(hash)?
        .ok_or_else(|| anyhow!("Txn Hash not Present"))?;

    let contract_address = receipt
        .contract_address
        .ok_or_else(|| anyhow!("ID is not a contract txn"))?;

    Ok(contract_address.to_hex_no_prefix())
}

fn get_transaction(params: Params, node: &Arc<Mutex<Node>>) -> Result<GetTxResponse> {
    let jsonrpc_error_data: Option<String> = None;
    let hash: B256 = params.one()?;
    let hash: Hash = Hash(hash.0);

    let tx = node
        .lock()
        .unwrap()
        .get_transaction_by_hash(hash)?
        .ok_or_else(|| {
            jsonrpsee::types::ErrorObject::owned(
                RPCErrorCode::RpcDatabaseError as i32,
                "Txn Hash not Present".to_string(),
                jsonrpc_error_data.clone(),
            )
        })?;
    let receipt = node
        .lock()
        .unwrap()
        .get_transaction_receipt(hash)?
        .ok_or_else(|| {
            jsonrpsee::types::ErrorObject::owned(
                RPCErrorCode::RpcDatabaseError as i32,
                "Txn Hash not Present".to_string(),
                jsonrpc_error_data.clone(),
            )
        })?;
    let block = node
        .lock()
        .unwrap()
        .get_block(receipt.block_hash)?
        .ok_or_else(|| anyhow!("block does not exist"))?;

    GetTxResponse::new(tx, receipt, block.number())
}

fn get_balance(params: Params, node: &Arc<Mutex<Node>>) -> Result<Value> {
    let address: ZilAddress = params.one()?;
    let address: Address = address.into();

    let node = node.lock().unwrap();
    let block = node
        .get_block(BlockId::latest())?
        .ok_or_else(|| anyhow!("Unable to get latest block!"))?;

    let state = node.get_state(&block)?;

    if !state.has_account(address)? {
        return Err(jsonrpsee::types::ErrorObject::owned(
            RPCErrorCode::RpcInvalidAddressOrKey as i32,
            "Account is not created",
            None::<()>,
        )
        .into());
    }

    let account = state.get_account(address)?;

    // We need to scale the balance from units of (10^-18) ZIL to (10^-12) ZIL. The value is truncated in this process.
    let balance = account.balance / 10u128.pow(6);

    Ok(json!({"balance": balance.to_string(), "nonce": account.nonce}))
}

fn get_current_mini_epoch(_: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    Ok(node.lock().unwrap().number().to_string())
}

fn get_latest_tx_block(_: Params, node: &Arc<Mutex<Node>>) -> Result<zil::TxBlock> {
    let node = node.lock().unwrap();
    let block = node
        .get_block(BlockId::latest())?
        .ok_or_else(|| anyhow!("no blocks"))?;

    Ok((&block).into())
}

fn get_minimum_gas_price(_: Params, node: &Arc<Mutex<Node>>) -> Result<ZilAmount> {
    let price = node.lock().unwrap().get_gas_price();
    // `price` is the cost per unit of [EvmGas]. This API should return the cost per unit of [ScillaGas].
    let price = price * (EVM_GAS_PER_SCILLA_GAS as u128);

    Ok(ZilAmount::from_amount(price))
}

fn get_network_id(_: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    let network_id = node.lock().unwrap().chain_id.zil;
    Ok(network_id.to_string())
}

fn get_version(_: Params, _: &Arc<Mutex<Node>>) -> Result<Value> {
    let commit = env!("VERGEN_GIT_SHA");
    let version = env!("VERGEN_GIT_DESCRIBE");
    Ok(json!({
        "Commit": commit,
        "Version": version,
    }))
}

fn get_blockchain_info(_: Params, node: &Arc<Mutex<Node>>) -> Result<BlockchainInfo> {
    let node = node.lock().unwrap();

    let num_tx_blocks = node.get_chain_tip();
    let num_ds_blocks = (num_tx_blocks / TX_BLOCKS_PER_DS_BLOCK) + 1;

    Ok(BlockchainInfo {
        num_peers: 0,
        num_tx_blocks,
        num_ds_blocks,
        num_transactions: 0,
        transaction_rate: 0.0,
        tx_block_rate: 0.0,
        ds_block_rate: 0.0,
        current_mini_epoch: num_tx_blocks,
        current_ds_epoch: num_ds_blocks,
        num_txns_ds_epoch: 0,
        num_txns_tx_epoch: 0,
        sharding_structure: ShardingStructure { num_peers: vec![0] },
    })
}

fn get_num_tx_blocks(_: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    let node = node.lock().unwrap();

    Ok(node.get_chain_tip().to_string())
}

fn get_smart_contract_state(params: Params, node: &Arc<Mutex<Node>>) -> Result<Value> {
    let address: ZilAddress = params.one()?;
    let address: Address = address.into();

    let node = node.lock().unwrap();

    // First get the account and check that its a scilla account
    let block = node
        .get_block(BlockId::latest())?
        .ok_or_else(|| anyhow!("Unable to get latest block!"))?;

    let state = node.get_state(&block)?;
    let account = state.get_account(address)?;

    let result = json!({
        "_balance": ZilAmount::from_amount(account.balance).to_string(),
    });
    let Value::Object(mut result) = result else {
        unreachable!()
    };

    let is_scilla = account.code.scilla_code_and_init_data().is_some();
    if is_scilla {
        let limit = node.config.state_rpc_limit;

        let trie = state.get_account_trie(address)?;
        for (i, (k, v)) in trie.iter().enumerate() {
            if i >= limit {
                return Err(anyhow!(
                    "State of contract returned has size greater than the allowed maximum"
                ));
            }

            let (var_name, indices) = split_storage_key(&k)?;
            let mut var = result.entry(var_name.clone());

            for index in indices {
                let next = var.or_insert_with(|| Value::Object(Default::default()));
                let Value::Object(next) = next else {
                    unreachable!()
                };
                let key: String = serde_json::from_slice(&index)?;
                var = next.entry(key.clone());
            }

            var.or_insert(serde_json::from_slice(&v)?);
        }
    }

    Ok(result.into())
}

fn get_smart_contract_code(params: Params, node: &Arc<Mutex<Node>>) -> Result<Value> {
    let address: ZilAddress = params.one()?;
    let address: Address = address.into();

    let node = node.lock().unwrap();
    let block = node
        .get_block(BlockId::latest())?
        .ok_or_else(|| anyhow!("Unable to get the latest block!"))?;
    let account = node.get_state(&block)?.get_account(address)?;

    let (code, type_) = match account.code {
        Code::Evm(ref bytes) => (hex::encode(bytes), "evm"),
        Code::Scilla { code, .. } => (code, "scilla"),
    };

    Ok(json!({ "code": code, "type": type_ }))
}

fn get_smart_contract_init(params: Params, node: &Arc<Mutex<Node>>) -> Result<Value> {
    let address: ZilAddress = params.one()?;
    let address: Address = address.into();

    let node = node.lock().unwrap();
    let block = node
        .get_block(BlockId::latest())?
        .ok_or_else(|| anyhow!("Unable to get the latest block!"))?;
    let account = node.get_state(&block)?.get_account(address)?;

    let Some((_, init_data)) = account.code.scilla_code_and_init_data() else {
        return Err(anyhow!("Address not contract address"));
    };

    Ok(serde_json::from_str(&init_data)?)
}

fn get_transactions_for_tx_block(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Vec<Vec<String>>> {
    let block_number: String = params.one()?;
    let block_number: u64 = block_number.parse()?;

    let node = node.lock().unwrap();
    let Some(block) = node.get_block(block_number)? else {
        return Err(anyhow!("Tx Block does not exist"));
    };
    if block.transactions.is_empty() {
        return Err(anyhow!("TxBlock has no transactions"));
    }

    Ok(vec![block
        .transactions
        .into_iter()
        .map(|h| B256::from(h).to_hex_no_prefix())
        .collect()])
}

pub const TRANSACTIONS_PER_PAGE: usize = 2500;
pub const TX_BLOCKS_PER_DS_BLOCK: u64 = 100;

fn get_tx_block(
    params: Params,
    node: &Arc<Mutex<Node>>,
    verbose: bool,
) -> Result<Option<zil::TxBlock>> {
    let block_number: String = params.one()?;
    let block_number: u64 = block_number.parse()?;

    let node = node.lock().unwrap();
    let Some(block) = node.get_block(block_number)? else {
        return Ok(None);
    };
    let mut block: zil::TxBlock = (&block).into();

    if verbose {
        block.header.committee_hash = Some(B256::ZERO);
        block.body.cosig_bitmap_1 = vec![true; 8];
        block.body.cosig_bitmap_2 = vec![true; 8];
        let mut scalar = [0; 32];
        scalar[31] = 1;
        block.body.cosig_1 = Some(schnorr::Signature::from_scalars(scalar, scalar).unwrap());
    }

    Ok(Some(block))
}

fn get_smart_contracts(params: Params, node: &Arc<Mutex<Node>>) -> Result<Vec<SmartContract>> {
    let address: ZilAddress = params.one()?;
    let address: Address = address.into();

    let block = node
        .lock()
        .unwrap()
        .get_block(BlockId::latest())?
        .ok_or_else(|| anyhow!("Unable to get the latest block!"))?;

    let nonce = node
        .lock()
        .unwrap()
        .get_state(&block)?
        .get_account(address)?
        .nonce;

    let mut contracts = vec![];

    for i in 0..nonce {
        let contract_address = zil_contract_address(address, i);

        let is_scilla = node
            .lock()
            .unwrap()
            .get_state(&block)?
            .get_account(contract_address)?
            .code
            .scilla_code_and_init_data()
            .is_some();

        // Note that we only expose created Scilla contracts in this API.
        if is_scilla {
            contracts.push(SmartContract {
                address: contract_address,
            });
        }
    }

    Ok(contracts)
}

fn get_example_ds_block_verbose(dsblocknum: u64, txblocknum: u64) -> DSBlockVerbose {
    DSBlockVerbose {
        B1: vec![false, false, false],
        B2: vec![false, false],
        CS1: String::from("FBA696961142862169D03EED67DD302EAB91333CBC4EEFE7EDB230515DA31DC1B9746EEEE5E7C105685E22C483B1021867B3775D30215CA66D5D81543E9FE8B5"),
        PrevDSHash: String::from("585373fb2c607b324afbe8f592e43b40d0091bbcef56c158e0879ced69648c8e"),
        header: DSBlockHeaderVerbose {
            BlockNum: dsblocknum.to_string(),
            CommitteeHash: String::from("da38b3b21b26b71835bb1545246a0a248f97003de302ae20d70aeaf854403029"),
            Difficulty: 95,
            DifficultyDS: 156,
            EpochNum: txblocknum.to_string(),
            GasPrice: String::from("2000000000"),
            MembersEjected: vec![
              "0x02572A2FCD59F8115297B399F76D7ACCFDA7E82AC53702063C3A61FB4D85E0D0C1".into(),
              "0x029933F07FF634654C2ECB17A90EAD00CF9EE9F75395E206660CCEFB21874ECEA1".into(),
              "0x02AAD92E5A3C9D8ECB364225719478B51026DD5C786BF7312C5C9765353BC4C98B".into()
            ],
            PoWWinners: vec![
              "0x0207184EB580333132787B360CA6D93290000C9F71E0B6A02C4412E7148FB1AF81".into(),
              "0x0285B572471A9D3BA729719ED2EEE86395D3B8F243572E9099A5E8B750F46092A7".into(),
              "0x02C1D8C0C7884E65A22FFD76DF9ACC2EA3551133E4ADD59C2DF74F327E09F709FF".into(),
              "0x02D728E77C8DA14E900BA8A2014A0D4B5512C6BABCCB77B83F21381437E0038F44".into(),
              "0x0321B0E1A20F02C99394DD24B34AB4E79AE6CBF0C689C222F246431A764D6B59DB".into(),
              "0x038A724504899CCCA068BD165AE15CE2947667225C72912039CEE4EF3992334843".into(),
              "0x03AB477A7A895DD4E84F240A2F1FCF5F86B1A3D59B6AD3065C18CD69729D089959".into(),
              "0x03B29C7F3F85329B0621914AB0367BA78135889FB8E4F937DDB7DAA8123AD4DF3C".into(),
              "0x03E82B00B53ECC10073404E844841C519152E500A655EEF1D8EAD6612ABDF5B552".into()
            ],
            PoWWinnersIP: vec![
                PoWWinnerIP { IP: String::from("192.0.2.0"), port: 33133 },
                PoWWinnerIP { IP: String::from("192.0.2.1"), port: 33133 },
                PoWWinnerIP { IP: String::from("192.0.2.2"), port: 33133 },
                PoWWinnerIP { IP: String::from("192.0.2.3"), port: 33133 },
                PoWWinnerIP { IP: String::from("192.0.2.4"), port: 33133 },
                PoWWinnerIP { IP: String::from("192.0.2.5"), port: 33133 },
                PoWWinnerIP { IP: String::from("192.0.2.6"), port: 33133 },
                PoWWinnerIP { IP: String::from("192.0.2.7"), port: 33133 },
                PoWWinnerIP { IP: String::from("192.0.2.8"), port: 33133 },
            ],
            PrevHash: String::from("585373fb2c607b324afbe8f592e43b40d0091bbcef56c158e0879ced69648c8e"),
            ReservedField: String::from("0000000000000000000000000000000000000000000000000000000000000000"),
            SWInfo: SWInfo { Scilla: vec![0, 0, 0, 0, 0], Zilliqa: vec![0, 0, 0, 0, 0] },
            ShardingHash: String::from("3216a33bfd4801e1907e72c7d529cef99c38d57cd281d0e9d726639fd9882d25"),
            Timestamp: String::from("1606443830834512"),
            Version: 2,
        },
        signature: String::from("7EE023C56602A17F2C8ABA2BEF290386D7C2CE1ABD8E3621573802FA67B243DE60B3EBEE5C4CCFDB697C80127B99CB384DAFEB44F70CD7569F2816DB950877BB"),
    }
}

fn get_example_ds_block(dsblocknum: u64, txblocknum: u64) -> DSBlock {
    get_example_ds_block_verbose(dsblocknum, txblocknum).into()
}

pub fn get_ds_block(params: Params, _node: &Arc<Mutex<Node>>) -> Result<DSBlock> {
    // Dummy implementation
    let block_number: String = params.one()?;
    let block_number: u64 = block_number.parse()?;
    Ok(get_example_ds_block(
        block_number,
        block_number * TX_BLOCKS_PER_DS_BLOCK,
    ))
}

pub fn get_ds_block_verbose(params: Params, _node: &Arc<Mutex<Node>>) -> Result<DSBlockVerbose> {
    // Dummy implementation
    let block_number: String = params.one()?;
    let block_number: u64 = block_number.parse()?;
    Ok(get_example_ds_block_verbose(
        block_number,
        block_number * TX_BLOCKS_PER_DS_BLOCK,
    ))
}

pub fn get_latest_ds_block(_params: Params, node: &Arc<Mutex<Node>>) -> Result<DSBlock> {
    // Dummy implementation
    let node = node.lock().unwrap();
    let num_tx_blocks = node.get_chain_tip();
    let num_ds_blocks = (num_tx_blocks / TX_BLOCKS_PER_DS_BLOCK) + 1;
    Ok(get_example_ds_block(num_ds_blocks, num_tx_blocks))
}

pub fn get_current_ds_comm(
    _params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<GetCurrentDSCommResult> {
    // Dummy implementation
    let node = node.lock().unwrap();
    let num_tx_blocks = node.get_chain_tip();
    let num_ds_blocks = (num_tx_blocks / TX_BLOCKS_PER_DS_BLOCK) + 1;
    Ok(GetCurrentDSCommResult {
        CurrentDSEpoch: num_ds_blocks.to_string(),
        CurrentTxEpoch: num_tx_blocks.to_string(),
        NumOfDSGuard: 420,
        dscomm: vec![
            "0x020035B739426374C5327A1224B986005297102E01C29656B8B086BF4B352C6CA9".into(),
            "0x0200834D709AD621785A90673F6011BC36ECF4CB13475237EAA2D4DEDAE7E9E554".into(),
        ],
    })
}

pub fn get_current_ds_epoch(_params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    // Dummy implementation
    let node = node.lock().unwrap();
    let num_tx_blocks = node.get_chain_tip();
    let num_ds_blocks = (num_tx_blocks / TX_BLOCKS_PER_DS_BLOCK) + 1;
    Ok(num_ds_blocks.to_string())
}

pub fn ds_block_listing(params: Params, node: &Arc<Mutex<Node>>) -> Result<DSBlockListingResult> {
    // Dummy implementation
    let node = node.lock().unwrap();
    let num_tx_blocks = node.get_chain_tip();
    let num_ds_blocks = (num_tx_blocks / TX_BLOCKS_PER_DS_BLOCK) + 1;
    let max_pages = num_ds_blocks / 10;
    let page_requested: String = params.one()?;
    let page_requested: u64 = page_requested.parse()?;

    let base_blocknum = page_requested * 10;
    let end_blocknum = num_ds_blocks.min(base_blocknum + 10);
    let listings: Vec<DSBlockListing> = (base_blocknum..end_blocknum)
        .map(|blocknum| DSBlockListing {
            BlockNum: blocknum,
            Hash: "4DEED80AFDCC89D5B691DCB54CCB846AD9D823D448A56ACAC4DBE5E1213244C7".to_string(),
        })
        .collect();

    Ok(DSBlockListingResult {
        data: listings,
        maxPages: max_pages.try_into()?,
    })
}

pub fn get_ds_block_rate(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<DSBlockRateResult> {
    // Dummy implementation
    Ok(DSBlockRateResult {
        rate: 0.00014142137245459714,
    })
}
