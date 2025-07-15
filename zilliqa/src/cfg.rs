use std::{ops::Deref, str::FromStr, time::Duration};

use alloy::{primitives::Address, rlp::Encodable};
use anyhow::{Result, anyhow};
use libp2p::{Multiaddr, PeerId};
use rand::{Rng, distributions::Alphanumeric};
use revm::primitives::address;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use serde_json::json;

use crate::{
    crypto::{Hash, NodePublicKey},
    transaction::EvmGas,
};

// Note that z2 constructs instances of this to save as a configuration so it must be both
// serializable and deserializable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub network: String,
    /// Individual configuration for every node to run.
    #[serde(default)]
    pub nodes: Vec<NodeConfig>,
    /// The port to listen for P2P messages on. Optional - If not provided a random port will be used.
    #[serde(default)]
    pub p2p_port: u16,
    /// External address for this node. This is the address at which it can be reached by other nodes. This should
    /// include the P2P port. If this is not provided, we will trust other nodes to tell us our external address.
    /// However, be warned that this is insecure and unreliable in real-world networks and we will remove this
    /// behaviour at some point in the future (#1101).
    #[serde(default)]
    pub external_address: Option<Multiaddr>,
    /// The address of another node to dial when this node starts. To join the network, a node must know about at least
    /// one other existing node in the network.
    #[serde(default)]
    pub bootstrap_address: OneOrMany<(PeerId, Multiaddr)>,
    /// The base address of the OTLP collector. If not set, metrics will not be exported.
    #[serde(default)]
    pub otlp_collector_endpoint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OneOrMany<T>(pub Vec<T>);

impl<T> Default for OneOrMany<T> {
    fn default() -> Self {
        Self(vec![])
    }
}

impl<T: Serialize> Serialize for OneOrMany<T> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.0.len() == 1 {
            self.0[0].serialize(serializer)
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for OneOrMany<T> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Inner<T> {
            One(T),
            Many(Vec<T>),
        }

        match Inner::deserialize(deserializer)? {
            Inner::One(t) => Ok(OneOrMany(vec![t])),
            Inner::Many(t) => Ok(OneOrMany(t)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EnabledApi {
    EnableAll(String),
    Enabled {
        namespace: String,
        apis: Vec<String>,
    },
}

impl EnabledApi {
    pub fn enabled(&self, api: &str) -> bool {
        // APIs with no namespace default to the 'zilliqa' namespace.
        let (ns, method) = api.split_once('_').unwrap_or(("zilliqa", api));
        match self {
            EnabledApi::EnableAll(namespace) => namespace == ns,
            EnabledApi::Enabled { namespace, apis } => {
                namespace == ns && apis.iter().any(|m| m == method)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiServer {
    /// The port to listen for JSON-RPC requests on.
    pub port: u16,
    /// RPC APIs to enable.
    pub enabled_apis: Vec<EnabledApi>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncConfig {
    /// The maximum number of blocks to have outstanding requests for at a time when syncing.
    #[serde(default = "max_blocks_in_flight_default")]
    pub max_blocks_in_flight: usize,
    /// The maximum number of blocks to request in a single message when syncing.
    #[serde(default = "block_request_batch_size_default")]
    pub block_request_batch_size: usize,
    /// The N number of historical blocks to be kept in the DB during pruning. N >= 300.
    #[serde(default = "u64_max")]
    pub prune_interval: u64,
    /// Lowest block to sync from, during passive-sync.
    /// Cannot be set if prune_interval is set.
    #[serde(default = "u64_max")]
    pub base_height: u64,
    /// Service passive-sync flag
    #[serde(default)]
    pub ignore_passive: bool,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            max_blocks_in_flight: max_blocks_in_flight_default(),
            block_request_batch_size: block_request_batch_size_default(),
            prune_interval: u64_max(),
            base_height: u64_max(),
            ignore_passive: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// RPC API endpoints to expose.
    #[serde(default)]
    pub api_servers: Vec<ApiServer>,
    /// Chain identifier. Doubles as shard_id internally.
    #[serde(default = "eth_chain_id_default")]
    pub eth_chain_id: u64,
    /// Consensus-specific data.
    pub consensus: ConsensusConfig,
    /// The maximum duration between a recieved block's timestamp and the current time. Defaults to 10 seconds.
    #[serde(default = "allowed_timestamp_skew_default")]
    pub allowed_timestamp_skew: Duration,
    /// The location of persistence data. If not set, uses a temporary path.
    #[serde(default)]
    pub data_dir: Option<String>,
    /// Size of the in-memory state trie cache, in bytes. Defaults to 256 MiB.
    #[serde(default = "state_cache_size_default")]
    pub state_cache_size: usize,
    /// Persistence checkpoint to load.
    #[serde(default)]
    pub load_checkpoint: Option<Checkpoint>,
    /// Whether to enable exporting checkpoint state checkpoint files.
    #[serde(default)]
    pub do_checkpoints: bool,
    /// The maximum number of blocks we will send to another node in a single message.
    #[serde(default = "block_request_limit_default")]
    pub block_request_limit: usize,
    /// The maximum number of key value pairs allowed to be returned within the response of the `GetSmartContractState` RPC. Defaults to no limit.
    #[serde(default = "state_rpc_limit_default")]
    pub state_rpc_limit: usize,
    /// When a block request to a peer fails, do not send another request to this peer for this amount of time.
    /// Defaults to 10 seconds.
    #[serde(default = "failed_request_sleep_duration_default")]
    pub failed_request_sleep_duration: Duration,
    /// Enable additional indices used by some Otterscan APIs. Enabling this will use more disk space and block processing will take longer.
    #[serde(default)]
    pub enable_ots_indices: bool,
    /// Maximum allowed RPC response size
    #[serde(default = "max_rpc_response_size_default")]
    pub max_rpc_response_size: u32,
    /// Sync configuration
    #[serde(default)]
    pub sync: SyncConfig,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            api_servers: vec![],
            eth_chain_id: eth_chain_id_default(),
            consensus: ConsensusConfig::default(),
            allowed_timestamp_skew: allowed_timestamp_skew_default(),
            data_dir: None,
            state_cache_size: state_cache_size_default(),
            load_checkpoint: None,
            do_checkpoints: false,
            block_request_limit: block_request_limit_default(),
            sync: SyncConfig {
                max_blocks_in_flight: max_blocks_in_flight_default(),
                block_request_batch_size: block_request_batch_size_default(),
                base_height: u64_max(),
                prune_interval: u64_max(),
                ignore_passive: false,
            },
            state_rpc_limit: state_rpc_limit_default(),
            failed_request_sleep_duration: failed_request_sleep_duration_default(),
            enable_ots_indices: false,
            max_rpc_response_size: max_rpc_response_size_default(),
        }
    }
}

impl NodeConfig {
    pub fn validate(&self) -> Result<()> {
        if let serde_json::Value::Object(map) =
            serde_json::to_value(self.consensus.contract_upgrades.clone())?
        {
            for (contract, block_height) in map {
                if block_height.as_u64().unwrap_or(0) % self.consensus.blocks_per_epoch != 0 {
                    return Err(anyhow!(
                        "Contract upgrades must be configured to occur at epoch boundaries. blocks_per_epoch: {}, contract {} configured to be upgraded block: {}",
                        self.consensus.blocks_per_epoch,
                        contract,
                        block_height
                    ));
                }
            }
        }
        if self.sync.base_height != u64_max() && self.sync.prune_interval != u64_max() {
            return Err(anyhow!(
                "base_height and prune_interval cannot be set at the same time"
            ));
        }

        // when set, >> 15 to avoid pruning forks; > 256 to be EVM-safe; arbitrarily picked.
        if self.sync.prune_interval < crate::sync::MIN_PRUNE_INTERVAL {
            return Err(anyhow!(
                "prune_interval must be at least {}",
                crate::sync::MIN_PRUNE_INTERVAL
            ));
        }
        // 100 is a reasonable minimum for a node to be useful.
        if self.sync.block_request_batch_size < 100 {
            return Err(anyhow!("block_request_batch_size must be at least 100"));
        }
        // 1000 would saturate a typical node.
        if self.sync.max_blocks_in_flight > 1000 {
            return Err(anyhow!("max_blocks_in_flight must be at most 1000"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    /// Location of the checkpoint
    pub file: String,
    /// Trusted hash of the checkpoint block
    #[serde(
        serialize_with = "serialize_hash_hex",
        deserialize_with = "deserialize_hash_hex"
    )]
    pub hash: Hash,
}

fn serialize_hash_hex<S>(hash: &Hash, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    hex::encode(hash.0).serialize(serializer)
}

fn deserialize_hash_hex<'de, D>(deserializer: D) -> Result<Hash, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s = <String>::deserialize(deserializer)?;
    let bytes = hex::decode(s).unwrap();
    Hash::try_from(bytes.as_slice()).map_err(|_| {
        de::Error::invalid_value(de::Unexpected::Bytes(&bytes), &"a 32-byte hex value")
    })
}

pub fn u64_max() -> u64 {
    u64::MAX
}

pub fn allowed_timestamp_skew_default() -> Duration {
    Duration::from_secs(60)
}

pub fn state_cache_size_default() -> usize {
    256 * 1024 * 1024 // 256 MiB
}

pub fn eth_chain_id_default() -> u64 {
    700 + 0x8000
}

pub fn block_request_limit_default() -> usize {
    100
}

pub fn max_blocks_in_flight_default() -> usize {
    1000
}

pub fn block_request_batch_size_default() -> usize {
    100
}

pub fn max_rpc_response_size_default() -> u32 {
    10 * 1024 * 1024 // 10 MB
}

pub fn state_rpc_limit_default() -> usize {
    // isize maximum because toml serialisation supports i64 integers
    isize::MAX as usize
}

pub fn failed_request_sleep_duration_default() -> Duration {
    Duration::from_secs(10)
}

/// Wrapper for [u128] that (de)serializes with a string. `serde_toml` does not support `u128`s.
#[derive(Copy, Clone, Debug)]
pub struct Amount(pub u128);

impl From<u128> for Amount {
    fn from(value: u128) -> Self {
        Amount(value)
    }
}

impl Deref for Amount {
    type Target = u128;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for Amount {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Amount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut res = String::deserialize(deserializer)?;
        // Remove underscores
        res.retain(|c| c != '_');
        Ok(Amount(
            u128::from_str(&res).map_err(serde::de::Error::custom)?,
        ))
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ScillaExtLibsPathInZq2(pub String);

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ScillaExtLibsPathInScilla(pub String);

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ScillaExtLibsPath {
    /// Where are the external libraries stored in zq2 servers' filesystem
    pub zq2: ScillaExtLibsPathInZq2,
    /// Where are the external libraries stored in scilla servers' filesystem
    pub scilla: ScillaExtLibsPathInScilla,
}

impl ScillaExtLibsPath {
    pub fn generate_random_subdirs(&self) -> (ScillaExtLibsPathInZq2, ScillaExtLibsPathInScilla) {
        let sub_directory: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();

        (
            ScillaExtLibsPathInZq2(format!("{}/{}", self.zq2.0, sub_directory)),
            ScillaExtLibsPathInScilla(format!("{}/{}", self.scilla.0, sub_directory)),
        )
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ConsensusConfig {
    /// If main, deploy a shard registry contract.
    #[serde(default = "default_true")]
    pub is_main: bool,
    /// If not main, parent main shard.
    #[serde(default)]
    pub main_shard_id: Option<u64>,
    /// The maximum time to wait for consensus to proceed as normal, before proposing a new view.
    #[serde(default = "consensus_timeout_default")]
    pub consensus_timeout: Duration,
    /// The initially staked deposits in the deposit contract at genesis, composed of
    /// (public key, peerId, amount, reward address) tuples.
    #[serde(default)]
    pub genesis_deposits: Vec<GenesisDeposit>,
    /// Accounts that will be pre-funded at genesis.
    #[serde(default)]
    pub genesis_accounts: Vec<(Address, Amount)>,
    /// The expected time between blocks when no views are missed.
    #[serde(default = "block_time_default")]
    pub block_time: Duration,
    /// Address of the Scilla server. Defaults to "http://localhost:62831".
    #[serde(default = "scilla_address_default")]
    pub scilla_address: String,
    /// Where (in the Scilla server's filesystem) is the library directory containing Scilla library functions?
    #[serde(default = "scilla_stdlib_dir_default")]
    pub scilla_stdlib_dir: String,
    /// Where are the external libraries are stored on zq2 and scilla server's filesystem so that scilla server can find them?
    #[serde(default = "scilla_ext_libs_path_default")]
    pub scilla_ext_libs_path: ScillaExtLibsPath,
    /// Directory in which the Unix domain socket used by the Scilla state server is created. If the Scilla process is
    /// running in Docker, this directory should be mounted inside the container too. Defaults to
    /// "/tmp/scilla-state-server".
    #[serde(default = "scilla_server_socket_directory_default")]
    pub scilla_server_socket_directory: String,
    /// Reward amount issued per hour, in Wei.
    pub rewards_per_hour: Amount,
    /// Number of blocks per hour. The reward per block is set at (rewards_per_hour/blocks_per_hour) Wei.
    pub blocks_per_hour: u64,
    /// The minimum stake passed into the deposit contract constructor at genesis, in Wei. Subsequent changes to this
    /// parameter will have no effect. You must not use this parameter at run-time; obtain the minimum stake in effect
    /// from the contract - otherwise if this value ever changes, there will be a mismatch between what the deposit
    /// contract believes and what the validators believe to be the minimum stake.
    pub minimum_stake: Amount,
    /// Maximum amount of gas permitted in a single block; any transactions over this
    /// will be held until the next block. The white paper specifies this as 84_000_000.
    pub eth_block_gas_limit: EvmGas,
    #[serde(default = "blocks_per_epoch_default")]
    pub blocks_per_epoch: u64,
    #[serde(default = "epochs_per_checkpoint_default")]
    pub epochs_per_checkpoint: u64,
    /// The gas price, in Wei per unit of EVM gas.
    pub gas_price: Amount,
    /// The total supply of native token in the network in Wei. Any funds which are not immediately assigned to an account (via genesis_accounts and genesis_deposits env vars) will be assigned to the zero account (0x0).
    #[serde(default = "total_native_token_supply_default")]
    pub total_native_token_supply: Amount,
    /// The block heights at which we perform EIP-1967 contract upgrades
    /// Contract upgrades occur only at epoch boundaries, ie at block heights which are a multiple of blocks_per_epoch
    #[serde(default)]
    pub contract_upgrades: ContractUpgrades,
    /// The initial fork configuration at genesis block. This provides a complete description of the execution behavior
    /// at the genesis block.
    #[serde(default = "genesis_fork_default")]
    pub genesis_fork: Fork,
    /// Forks in block execution logic. Each entry describes the difference in logic and the block height at which that
    /// difference applies.
    #[serde(default)]
    pub forks: Vec<ForkDelta>,
    /// Interval at which NewView messages are broadcast when node is in timeout
    /// Defaut of 0 means never broadcast
    #[serde(default = "new_view_broadcast_interval_default")]
    pub new_view_broadcast_interval: Duration,
}

impl ConsensusConfig {
    /// Generates a list of forks by applying the delta forks initially to the genesis fork and then to the previous one.
    /// The genesis fork is the initial fork configuration at the genesis block.
    pub fn get_forks(&self) -> Result<Forks> {
        if self.genesis_fork.at_height != 0 {
            return Err(anyhow!("first fork must start at height 0"));
        }

        let mut delta_forks = self.forks.clone();
        delta_forks.sort_unstable_by_key(|f| f.at_height);

        let forks =
            delta_forks
                .into_iter()
                .fold(vec![self.genesis_fork.clone()], |mut forks, delta| {
                    let last_fork = forks.last().unwrap(); // Safe to call unwrap because we always have genesis_fork
                    let new_fork = last_fork.apply_delta_fork(&delta);
                    forks.push(new_fork);
                    forks
                });

        Ok(Forks(forks))
    }
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        ConsensusConfig {
            is_main: default_true(),
            main_shard_id: None,
            consensus_timeout: consensus_timeout_default(),
            genesis_deposits: vec![],
            genesis_accounts: vec![],
            block_time: block_time_default(),
            scilla_address: scilla_address_default(),
            scilla_stdlib_dir: scilla_stdlib_dir_default(),
            scilla_ext_libs_path: scilla_ext_libs_path_default(),
            scilla_server_socket_directory: scilla_server_socket_directory_default(),
            rewards_per_hour: 204_000_000_000_000_000_000_000u128.into(),
            blocks_per_hour: 3600 * 40,
            minimum_stake: 32_000_000_000_000_000_000u128.into(),
            eth_block_gas_limit: EvmGas(84000000),
            blocks_per_epoch: blocks_per_epoch_default(),
            epochs_per_checkpoint: epochs_per_checkpoint_default(),
            gas_price: 4_761_904_800_000u128.into(),
            total_native_token_supply: total_native_token_supply_default(),
            contract_upgrades: ContractUpgrades::default(),
            forks: vec![],
            genesis_fork: genesis_fork_default(),
            new_view_broadcast_interval: new_view_broadcast_interval_default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Forks(Vec<Fork>);

impl Forks {
    pub fn get(&self, height: u64) -> &Fork {
        // Binary search to find the fork at the specified height. If an entry was not found at exactly the specified
        // height, the `Err` returned from `binary_search_by_key` will contain the index where an element with this
        // height could be inserted. By subtracting one from this, we get the maximum entry with a height less than the
        // searched height.
        let index = self
            .0
            .binary_search_by_key(&height, |f| f.at_height)
            .unwrap_or_else(|i| i - 1);
        &self.0[index]
    }

    pub fn find_height_fork_first_activated(&self, fork_name: ForkName) -> Option<u64> {
        let mut sorted_fork = self.0.clone();
        sorted_fork.sort_by_key(|item| item.at_height);
        for fork in sorted_fork.iter() {
            if match fork_name {
                ForkName::ExecutableBlocks => fork.executable_blocks,
                ForkName::FailedScillaCallFromGasExemptCallerCausesRevert => {
                    fork.failed_scilla_call_from_gas_exempt_caller_causes_revert
                }
                ForkName::CallMode1SetsCallerToParentCaller => {
                    fork.call_mode_1_sets_caller_to_parent_caller
                }
                ForkName::ScillaMessagesCanCallEvmContracts => {
                    fork.scilla_messages_can_call_evm_contracts
                }
                ForkName::ScillaContractCreationIncrementsAccountBalance => {
                    fork.scilla_contract_creation_increments_account_balance
                }
                ForkName::ScillaJsonPreserveOrder => fork.scilla_json_preserve_order,
                ForkName::ScillaCallRespectsEvmStateChanges => {
                    fork.scilla_call_respects_evm_state_changes
                }
                ForkName::OnlyMutatedAccountsUpdateState => fork.only_mutated_accounts_update_state,
                ForkName::ScillaCallGasExemptAddrs => {
                    fork.scilla_call_gas_exempt_addrs.length() != 0
                }
                ForkName::ScillaBlockNumberReturnsCurrentBlock => {
                    fork.scilla_block_number_returns_current_block
                }
                ForkName::ScillaMapsAreEncodedCorrectly => fork.scilla_maps_are_encoded_correctly,
                ForkName::FundAccountsFromZeroAccount => {
                    !fork.fund_accounts_from_zero_account.is_empty()
                }
                ForkName::ScillaFailedTxnCorrectBalanceDeduction => {
                    fork.scilla_failed_txn_correct_balance_deduction
                }
                ForkName::ScillaTransitionsProperOrder => fork.scilla_transition_proper_order,
                ForkName::EvmToScillaValueTransferZero => fork.evm_to_scilla_value_transfer_zero,
                ForkName::RestoreXsgdContract => fork.restore_xsgd_contract,
                ForkName::EvmExecFailureCausesScillaWhitelistedAddrToFail => {
                    fork.evm_exec_failure_causes_scilla_precompile_to_fail
                }
                ForkName::RevertRestoreXsgdContract => fork.revert_restore_xsgd_contract,
                ForkName::ScillaFixContractCodeRemovalOnEvmTx => {
                    fork.scilla_fix_contract_code_removal_on_evm_tx
                }
            } {
                return Some(fork.at_height);
            }
        }
        None
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Fork {
    pub at_height: u64,
    pub executable_blocks: bool,
    pub failed_scilla_call_from_gas_exempt_caller_causes_revert: bool,
    pub call_mode_1_sets_caller_to_parent_caller: bool,
    pub scilla_messages_can_call_evm_contracts: bool,
    pub scilla_contract_creation_increments_account_balance: bool,
    pub scilla_json_preserve_order: bool,
    pub scilla_call_respects_evm_state_changes: bool,
    pub only_mutated_accounts_update_state: bool,
    pub scilla_call_gas_exempt_addrs: Vec<Address>,
    pub scilla_block_number_returns_current_block: bool,
    pub scilla_maps_are_encoded_correctly: bool,
    pub transfer_gas_fee_to_zero_account: bool,
    pub apply_scilla_delta_when_evm_succeeded: bool,
    pub apply_state_changes_only_if_transaction_succeeds: bool,
    pub scilla_deduct_funds_from_actual_sender: bool,
    pub fund_accounts_from_zero_account: Vec<(Address, Amount)>,
    pub scilla_delta_maps_are_applied_correctly: bool,
    pub scilla_server_unlimited_response_size: bool,
    pub scilla_failed_txn_correct_balance_deduction: bool,
    pub scilla_transition_proper_order: bool,
    pub evm_to_scilla_value_transfer_zero: bool,
    pub restore_xsgd_contract: bool,
    pub evm_exec_failure_causes_scilla_precompile_to_fail: bool,
    pub revert_restore_xsgd_contract: bool,
    pub scilla_fix_contract_code_removal_on_evm_tx: bool,
}

pub enum ForkName {
    ExecutableBlocks,
    FailedScillaCallFromGasExemptCallerCausesRevert,
    CallMode1SetsCallerToParentCaller,
    ScillaMessagesCanCallEvmContracts,
    ScillaContractCreationIncrementsAccountBalance,
    ScillaJsonPreserveOrder,
    ScillaCallRespectsEvmStateChanges,
    OnlyMutatedAccountsUpdateState,
    ScillaCallGasExemptAddrs,
    ScillaBlockNumberReturnsCurrentBlock,
    ScillaMapsAreEncodedCorrectly,
    FundAccountsFromZeroAccount,
    ScillaFailedTxnCorrectBalanceDeduction,
    ScillaTransitionsProperOrder,
    EvmToScillaValueTransferZero,
    RestoreXsgdContract,
    EvmExecFailureCausesScillaWhitelistedAddrToFail,
    RevertRestoreXsgdContract,
    ScillaFixContractCodeRemovalOnEvmTx,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForkDelta {
    pub at_height: u64,
    /// If true then transactions can be executed against blocks.
    /// Currently used to mark the height at which ZQ1 blocks end and ZQ2 blocks begin in converted persistence networks. This is required because their state root hashes are set to Hash::ZERO.
    pub executable_blocks: Option<bool>,
    /// If true, if a caller who is in the `scilla_call_gas_exempt_addrs` list makes a call to the `scilla_call`
    /// precompile and the inner Scilla call fails, the entire transaction will revert. If false, the normal EVM
    /// semantics apply where the caller can decide how to act based on the success of the inner call.
    pub failed_scilla_call_from_gas_exempt_caller_causes_revert: Option<bool>,
    /// If true, if a call is made to the `scilla_call` precompile with `call_mode` / `keep_origin` set to `1`, the
    /// `_sender` of the inner Scilla call will be set to the caller of the current call-stack. If false, the `_sender`
    /// will be set to the original transaction signer.
    ///
    /// For example:
    /// A (EOA) -> B (EVM) -> C (EVM) -> D (Scilla)
    ///
    /// When this flag is true, `D` will see the `_sender` as `B`. When this flag is false, `D` will see the `_sender`
    /// as `A`.
    pub call_mode_1_sets_caller_to_parent_caller: Option<bool>,
    /// If true, when a Scilla message is sent to an EVM contract, the EVM contract will be treated as if it was an
    /// EOA (i.e. any ZIL passed will be transferred to the contract and execution will continue). If false, sending a
    /// Scilla message to an EVM contract will cause the Scilla transaction to fail.
    pub scilla_messages_can_call_evm_contracts: Option<bool>,
    /// If true, when a contract is deployed, if the contract address is already funded,
    /// the contract balance will be sum of the existing balance and the amount sent in the deployment transaction.
    /// If false, the contract balance will be the amount sent in the deployment transaction.
    pub scilla_contract_creation_increments_account_balance: Option<bool>,
    /// If true, JSON maps that are passed to Scilla will be in their original order. If false, the entries will be
    /// sorted by their keys.
    pub scilla_json_preserve_order: Option<bool>,
    /// If true, interop calls to the `scilla_call` precompile will correctly see state changes already made by the EVM
    /// before that point in the transaction's execution. Also both Scilla and EVM will be able to update the same
    /// accounts without state changes being lost. If false, state changes can be lost if Scilla and EVM attempt to
    /// update the same account. This can sometimes lead to mined transactions which don't increase the caller's nonce.
    pub scilla_call_respects_evm_state_changes: Option<bool>,
    // If true, when an account is accessed but not mutated as part of transaction execution, we will not change the
    // state of that account in the state trie. If false, we will always update state to the read value of the account.
    // Most of the time this does not make a difference, because we would just be writing back the same value we read.
    // However, in some edge cases (e.g. precompiles) setting this value to `false` results in spurious writes of
    // default accounts to the state trie.
    pub only_mutated_accounts_update_state: Option<bool>,
    /// Calls to the `scilla_call` precompile from these addresses cost a different amount of gas. If the provided gas
    /// limit is not enough, the call will still succeed and we will charge as much gas as we can. This hack exists due
    /// to important contracts deployed on Zilliqa 1's mainnet that pass the incorrect gas limit to `scilla_call`.
    /// Zilliqa 1's implementation was broken and accepted these calls and these contracts are now widely used and
    /// bridged to other chains. Adding a value to this list in a [ForkDelta] will append it to the total list of
    /// exempt addresses.
    #[serde(default)]
    pub scilla_call_gas_exempt_addrs: Vec<Address>,
    /// If true, querying the `BLOCKNUMBER` from Scilla will correctly return the current block number (i.e. the one
    /// the transaction is about to be included in). If false, it will return the previous block number.
    pub scilla_block_number_returns_current_block: Option<bool>,
    /// If true, nested Scilla maps are returned to the Scilla intepreter in the correct format and keys are encoded
    /// properly. If false, Scilla transactions will work but they will be incorrect in undetermined ways.
    pub scilla_maps_are_encoded_correctly: Option<bool>,
    /// If true, the total gas paid by all transactions in a block is transferred to the zero address.
    /// This keeps the total supply of the network constant. If false, we still transfer funds to the zero address,
    /// but with an incorrect gas price of 1 Wei per gas.
    pub transfer_gas_fee_to_zero_account: Option<bool>,
    /// If true, when there are successful interop calls and in the end EVM transaction fails,
    /// no state changes are applied for affected accounts by interop calls
    pub apply_scilla_delta_when_evm_succeeded: Option<bool>,
    /// If true, only apply state changes if the transaction succeeds. If false, apply state changes even if the
    /// transaction fails.
    pub apply_state_changes_only_if_transaction_succeeds: Option<bool>,
    /// if true, funds are deducted from the sender of scilla message rather than the origin
    pub scilla_deduct_funds_from_actual_sender: Option<bool>,
    /// Send funds from zero account to faucet account
    pub fund_accounts_from_zero_account: Option<Vec<(Address, Amount)>>,
    /// If true, Scilla state deltas containing maps are applied correctly. If false, they are applied in an
    /// unspecified and incorrect way.
    pub scilla_delta_maps_are_applied_correctly: Option<bool>,
    /// If true, the Zilliqa process can send the Scilla process an unlimited (actually 1 GiB) amount of data in one
    /// call. If false, the size is limited to 10 MiB. Any responses larger than this will lead to a failed
    /// transaction.
    pub scilla_server_unlimited_response_size: Option<bool>,
    /// If true, for failed scilla transaction there will be only fee taken from sender balance and possible
    /// balance subtractions caused by scilla transitions will be discarded
    pub scilla_failed_txn_correct_balance_deduction: Option<bool>,
    /// If true, scilla transitions are pushed on the stack onto stack in the same order as they were
    /// emitted from scilla call
    pub scilla_transition_proper_order: Option<bool>,
    /// If true, values transfers from evm to scilla contracts are always reset to 0
    pub evm_to_scilla_value_transfer_zero: Option<bool>,
    /// If true, re-write XSGD contract to address 0x173CA6770aA56eb00511Dac8e6E13B3D7f16A5a5's code
    pub restore_xsgd_contract: Option<bool>,
    /// If true, any failed evm action (call, create, create2, etc) will automatically make
    /// entire transaction fail if there's been a call to whitelisted zrc2 contract via scilla precompile
    pub evm_exec_failure_causes_scilla_precompile_to_fail: Option<bool>,
    /// If true, set address 0x173CA6770aA56eb00511Dac8e6E13B3D7f16A5a5's code to "0x"
    pub revert_restore_xsgd_contract: Option<bool>,
    /// If true, an evm tx (legacy or eip1559) should not clear a Scilla contract's code when its address is interacted with
    pub scilla_fix_contract_code_removal_on_evm_tx: Option<bool>,
}

impl Fork {
    pub fn apply_delta_fork(&self, delta: &ForkDelta) -> Fork {
        Fork {
            at_height: delta.at_height,
            executable_blocks: delta.executable_blocks.unwrap_or(self.executable_blocks),
            failed_scilla_call_from_gas_exempt_caller_causes_revert: delta
                .failed_scilla_call_from_gas_exempt_caller_causes_revert
                .unwrap_or(self.failed_scilla_call_from_gas_exempt_caller_causes_revert),
            call_mode_1_sets_caller_to_parent_caller: delta
                .call_mode_1_sets_caller_to_parent_caller
                .unwrap_or(self.call_mode_1_sets_caller_to_parent_caller),
            scilla_messages_can_call_evm_contracts: delta
                .scilla_messages_can_call_evm_contracts
                .unwrap_or(self.scilla_messages_can_call_evm_contracts),
            scilla_contract_creation_increments_account_balance: delta
                .scilla_contract_creation_increments_account_balance
                .unwrap_or(self.scilla_contract_creation_increments_account_balance),
            scilla_json_preserve_order: delta
                .scilla_json_preserve_order
                .unwrap_or(self.scilla_json_preserve_order),
            scilla_call_respects_evm_state_changes: delta
                .scilla_call_respects_evm_state_changes
                .unwrap_or(self.scilla_call_respects_evm_state_changes),
            only_mutated_accounts_update_state: delta
                .only_mutated_accounts_update_state
                .unwrap_or(self.only_mutated_accounts_update_state),
            scilla_call_gas_exempt_addrs: {
                let mut addrs = self.scilla_call_gas_exempt_addrs.clone();
                addrs.extend_from_slice(&delta.scilla_call_gas_exempt_addrs);
                addrs
            },
            scilla_block_number_returns_current_block: delta
                .scilla_block_number_returns_current_block
                .unwrap_or(self.scilla_block_number_returns_current_block),
            scilla_maps_are_encoded_correctly: delta
                .scilla_maps_are_encoded_correctly
                .unwrap_or(self.scilla_maps_are_encoded_correctly),
            transfer_gas_fee_to_zero_account: delta
                .transfer_gas_fee_to_zero_account
                .unwrap_or(self.transfer_gas_fee_to_zero_account),
            apply_scilla_delta_when_evm_succeeded: delta
                .apply_scilla_delta_when_evm_succeeded
                .unwrap_or(self.apply_scilla_delta_when_evm_succeeded),
            apply_state_changes_only_if_transaction_succeeds: delta
                .apply_state_changes_only_if_transaction_succeeds
                .unwrap_or(self.apply_state_changes_only_if_transaction_succeeds),
            scilla_deduct_funds_from_actual_sender: delta
                .scilla_deduct_funds_from_actual_sender
                .unwrap_or(self.scilla_deduct_funds_from_actual_sender),
            fund_accounts_from_zero_account: delta
                .fund_accounts_from_zero_account
                .clone()
                .unwrap_or_default(),
            scilla_delta_maps_are_applied_correctly: delta
                .scilla_delta_maps_are_applied_correctly
                .unwrap_or(self.scilla_delta_maps_are_applied_correctly),
            scilla_server_unlimited_response_size: delta
                .scilla_server_unlimited_response_size
                .unwrap_or(self.scilla_server_unlimited_response_size),
            scilla_failed_txn_correct_balance_deduction: delta
                .scilla_failed_txn_correct_balance_deduction
                .unwrap_or(self.scilla_failed_txn_correct_balance_deduction),
            scilla_transition_proper_order: delta
                .scilla_transition_proper_order
                .unwrap_or(self.scilla_transition_proper_order),
            evm_to_scilla_value_transfer_zero: delta
                .evm_to_scilla_value_transfer_zero
                .unwrap_or(self.evm_to_scilla_value_transfer_zero),
            restore_xsgd_contract: delta
                .restore_xsgd_contract
                .unwrap_or(self.restore_xsgd_contract),
            evm_exec_failure_causes_scilla_precompile_to_fail: delta
                .evm_exec_failure_causes_scilla_precompile_to_fail
                .unwrap_or(self.evm_exec_failure_causes_scilla_precompile_to_fail),
            revert_restore_xsgd_contract: delta
                .revert_restore_xsgd_contract
                .unwrap_or(self.revert_restore_xsgd_contract),
            scilla_fix_contract_code_removal_on_evm_tx: delta
                .scilla_fix_contract_code_removal_on_evm_tx
                .unwrap_or(self.scilla_fix_contract_code_removal_on_evm_tx),
        }
    }
}

/// Scilla Code to be restored via restore_xsgd_contract
pub const XSGD_MAINNET_ADDR: Address = address!("0x173CA6770aA56eb00511Dac8e6E13B3D7f16A5a5");
pub const XSGD_CODE: &str = "7b225363696c6c61223a7b22636f6465223a227363696c6c615f76657273696f6e20305c6e5c6e5c6e696d706f727420426f6f6c5574696c7320496e745574696c735c6e5c6e6c6962726172792050726f7879436f6e74726163745c6e5c6e6c6574207a65726f203d2055696e7431323820305c6e5c6e6c6574206f6e655f6d7367203d5c6e66756e20286d7367203a204d65737361676529203d3e5c6e6c6574206e696c5f6d7367203d204e696c207b4d6573736167657d20696e5c6e436f6e73207b4d6573736167657d206d7367206e696c5f6d73675c6e5c6e6c6574206465636f6e7374727563745f6f7074696f6e5f75696e74313238203d5c6e66756e20286f7074696f6e5f75696e74313238203a204f7074696f6e2055696e7431323829203d3e5c6e6d61746368206f7074696f6e5f75696e7431323820776974685c6e7c20536f6d652061203d3e20615c6e7c205f203d3e207a65726f5c6e656e645c6e5c6e74797065204572726f72203d5c6e7c20436f64654e6f7441646d696e5c6e7c20436f64654e6f7443757272496d706c5c6e6c6574206d616b655f6572726f72203d5c6e66756e2028726573756c74203a204572726f7229203d3e5c6e6c657420726573756c745f636f6465203d205c6e6d6174636820726573756c7420776974685c6e7c20436f64654e6f7441646d696e2020202020202020202020202020202020203d3e20496e743332202d315c6e7c20436f64654e6f7443757272496d706c2020202020202020202020202020203d3e20496e743332202d325c6e656e645c6e696e5c6e7b205f657863657074696f6e203a205c224572726f725c223b20636f6465203a20726573756c745f636f6465207d5c6e5c6e5c6e5c6e636f6e74726163742050726f7879436f6e74726163745c6e285c6e636f6e74726163745f6f776e65723a20427953747232302c5c6e6e616d65203a20202020537472696e672c5c6e73796d626f6c203a2020537472696e672c5c6e646563696d616c73203a2055696e7433322c5c6e696e69745f737570706c79203a2055696e743132382c5c6e696e69745f696d706c656d656e746174696f6e203a20427953747232302c5c6e696e69745f61646d696e203a20427953747232305c6e295c6e776974685c6e6c657420737472696e675f69735f6e6f745f656d707479203d5c6e66756e202873203a20537472696e6729203d3e5c6e6c6574207a65726f203d2055696e743332203020696e5c6e6c657420735f6c656e677468203d206275696c74696e207374726c656e207320696e5c6e6c657420735f656d707479203d206275696c74696e20657120735f6c656e677468207a65726f20696e5c6e6e65676220735f656d7074795c6e696e5c6e6c6574206e616d655f6f6b203d20737472696e675f69735f6e6f745f656d707479206e616d6520696e5c6e6c65742073796d626f6c5f6f6b203d20737472696e675f69735f6e6f745f656d7074792073796d626f6c20696e5c6e6c6574206e616d655f73796d626f6c5f6f6b203d20616e6462206e616d655f6f6b2073796d626f6c5f6f6b20696e5c6e6c657420646563696d616c735f6f6b203d5c6e6c657420736978203d2055696e743332203620696e5c6e6c657420656967687465656e203d2055696e74333220313820696e5c6e6c657420646563696d616c735f61745f6c656173745f36203d2075696e7433325f6c652073697820646563696d616c7320696e5c6e6c657420646563696d616c735f6e6f5f6d6f72655f7468616e5f3138203d2075696e7433325f6c6520646563696d616c7320656967687465656e20696e5c6e616e646220646563696d616c735f61745f6c656173745f3620646563696d616c735f6e6f5f6d6f72655f7468616e5f313820696e5c6e616e6462206e616d655f73796d626f6c5f6f6b20646563696d616c735f6f6b5c6e3d3e5c6e5c6e6669656c6420696d706c656d656e746174696f6e203a2042795374723230203d20696e69745f696d706c656d656e746174696f6e5c6e6669656c642061646d696e203a2042795374723230203d20696e69745f61646d696e5c6e6669656c642062616c616e636573203a204d617020427953747232302055696e743132385c6e3d206c657420656d705f6d6170203d20456d7020427953747232302055696e7431323820696e5c6e6275696c74696e2070757420656d705f6d617020636f6e74726163745f6f776e657220696e69745f737570706c795c6e6669656c6420746f74616c5f737570706c79203a2055696e74313238203d20696e69745f737570706c795c6e6669656c6420616c6c6f77616e636573203a204d6170204279537472323020284d617020427953747232302055696e7431323829203d20456d70204279537472323020284d617020427953747232302055696e74313238295c6e5c6e70726f636564757265205468726f774572726f7228657272203a204572726f72295c6e65203d206d616b655f6572726f72206572723b5c6e7468726f7720655c6e656e645c6e5c6e70726f63656475726520697341646d696e28616464726573733a2042795374723230295c6e63757272656e745f61646d696e203c2d2061646d696e3b5c6e69735f61646d696e203d206275696c74696e2065712063757272656e745f61646d696e20616464726573733b5c6e6d617463682069735f61646d696e20776974685c6e7c2054727565203d3e5c6e7c2046616c7365203d3e5c6e657272203d20436f64654e6f7441646d696e3b5c6e5468726f774572726f72206572725c6e656e645c6e656e645c6e5c6e70726f63656475726520697343757272496d706c28616464726573733a2042795374723230295c6e63757272656e745f696d706c203c2d20696d706c656d656e746174696f6e3b5c6e69735f637572725f696d70203d206275696c74696e2065712063757272656e745f696d706c20616464726573733b5c6e6d617463682069735f637572725f696d7020776974685c6e7c2054727565203d3e205c6e7c2046616c7365203d3e5c6e657272203d20436f64654e6f7443757272496d706c3b5c6e5468726f774572726f72206572725c6e656e645c6e656e645c6e5c6e7472616e736974696f6e2055706772616465546f286e6577496d706c656d656e746174696f6e203a2042795374723230295c6e697341646d696e205f73656e6465723b5c6e5c6e696d706c656d656e746174696f6e203a3d206e6577496d706c656d656e746174696f6e3b5c6e65203d207b5f6576656e746e616d65203a205c2255706772616465645c223b20696d706c656d656e746174696f6e5f61646472657373203a206e6577496d706c656d656e746174696f6e7d3b5c6e6576656e7420655c6e656e645c6e5c6e7472616e736974696f6e204368616e676541646d696e286e657741646d696e203a2042795374723230295c6e697341646d696e205f73656e6465723b5c6e5c6e63757272656e7441646d696e203c2d2061646d696e3b5c6e61646d696e203a3d206e657741646d696e3b5c6e65203d207b5f6576656e746e616d65203a205c2241646d696e4368616e6765645c223b206f6c6441646d696e203a2063757272656e7441646d696e3b206e657741646d696e203a206e657741646d696e7d3b5c6e6576656e7420655c6e656e645c6e5c6e7472616e736974696f6e205472616e736665724f776e657273686970286e65774f776e6572203a2042795374723230295c6e63757272656e745f696d706c203c2d20696d706c656d656e746174696f6e3b5c6e6d7367203d207b5f746167203a205c225472616e736665724f776e6572736869705c223b205f726563697069656e74203a2063757272656e745f696d706c3b205f616d6f756e74203a207a65726f3b5c6e6e65774f776e6572203a206e65774f776e65723b20696e69746961746f72203a205f73656e6465727d3b5c6e6d736773203d206f6e655f6d7367206d73673b5c6e73656e64206d7367735c6e656e645c6e5c6e7472616e736974696f6e20506175736528295c6e63757272656e745f696d706c203c2d20696d706c656d656e746174696f6e3b5c6e6d7367203d207b5f746167203a205c2250617573655c223b205f726563697069656e74203a2063757272656e745f696d706c3b205f616d6f756e74203a207a65726f3b20696e69746961746f72203a205f73656e6465727d3b5c6e6d736773203d206f6e655f6d7367206d73673b5c6e73656e64206d7367735c6e656e645c6e5c6e7472616e736974696f6e20556e706175736528295c6e63757272656e745f696d706c203c2d20696d706c656d656e746174696f6e3b5c6e6d7367203d207b5f746167203a205c22556e70617573655c223b205f726563697069656e74203a2063757272656e745f696d706c3b205f616d6f756e74203a207a65726f3b20696e69746961746f72203a205f73656e6465727d3b5c6e6d736773203d206f6e655f6d7367206d73673b5c6e73656e64206d7367735c6e656e645c6e5c6e7472616e736974696f6e20557064617465506175736572286e6577506175736572203a2042795374723230295c6e63757272656e745f696d706c203c2d20696d706c656d656e746174696f6e3b5c6e6d7367203d207b5f746167203a205c225570646174655061757365725c223b205f726563697069656e74203a2063757272656e745f696d706c3b205f616d6f756e74203a207a65726f3b5c6e6e6577506175736572203a206e65775061757365723b20696e69746961746f72203a205f73656e6465727d3b5c6e6d736773203d206f6e655f6d7367206d73673b5c6e73656e64206d7367735c6e656e645c6e5c6e7472616e736974696f6e20426c61636b6c6973742861646472657373203a2042795374723230295c6e63757272656e745f696d706c203c2d20696d706c656d656e746174696f6e3b5c6e6d7367203d207b5f746167203a205c22426c61636b6c6973745c223b205f726563697069656e74203a2063757272656e745f696d706c3b205f616d6f756e74203a207a65726f3b5c6e61646472657373203a20616464726573733b20696e69746961746f72203a205f73656e6465727d3b5c6e6d736773203d206f6e655f6d7367206d73673b5c6e73656e64206d7367735c6e656e645c6e5c6e7472616e736974696f6e20556e626c61636b6c6973742861646472657373203a2042795374723230295c6e63757272656e745f696d706c203c2d20696d706c656d656e746174696f6e3b5c6e6d7367203d207b5f746167203a205c22556e626c61636b6c6973745c223b205f726563697069656e74203a2063757272656e745f696d706c3b205f616d6f756e74203a207a65726f3b5c6e61646472657373203a20616464726573733b20696e69746961746f72203a205f73656e6465727d3b5c6e6d736773203d206f6e655f6d7367206d73673b5c6e73656e64206d7367735c6e656e645c6e5c6e7472616e736974696f6e20557064617465426c61636b6c6973746572286e6577426c61636b6c6973746572203a2042795374723230295c6e63757272656e745f696d706c203c2d20696d706c656d656e746174696f6e3b5c6e6d7367203d207b5f746167203a205c22557064617465426c61636b6c69737465725c223b205f726563697069656e74203a2063757272656e745f696d706c3b205f616d6f756e74203a207a65726f3b5c6e6e6577426c61636b6c6973746572203a206e6577426c61636b6c69737465723b20696e69746961746f72203a205f73656e6465727d3b5c6e6d736773203d206f6e655f6d7367206d73673b5c6e73656e64206d7367735c6e656e645c6e5c6e7472616e736974696f6e204d696e7428726563697069656e743a20427953747232302c20616d6f756e74203a2055696e74313238295c6e63757272656e745f696d706c203c2d20696d706c656d656e746174696f6e3b5c6e63757272656e745f737570706c79203c2d20746f74616c5f737570706c793b5c6e6765745f746f5f62616c203c2d2062616c616e6365735b726563697069656e745d3b5c6e746f5f62616c203d206465636f6e7374727563745f6f7074696f6e5f75696e74313238206765745f746f5f62616c3b5c6e6d7367203d207b5f746167203a205c224d696e745c223b205f726563697069656e74203a2063757272656e745f696d706c3b205f616d6f756e74203a207a65726f3b20746f203a20726563697069656e743b5c6e616d6f756e74203a20616d6f756e743b20696e69746961746f72203a205f73656e6465723b20746f5f62616c203a20746f5f62616c3b2063757272656e745f737570706c79203a2063757272656e745f737570706c797d3b5c6e6d736773203d206f6e655f6d7367206d73673b5c6e73656e64206d7367735c6e656e645c6e5c6e7472616e736974696f6e204d696e7443616c6c4261636b28746f3a20427953747232302c206e65775f746f5f62616c3a2055696e743132382c206e65775f737570706c79203a2055696e74313238295c6e697343757272496d706c205f73656e6465723b5c6e5c6e62616c616e6365735b746f5d203a3d206e65775f746f5f62616c3b5c6e746f74616c5f737570706c79203a3d206e65775f737570706c795c6e656e645c6e5c6e7472616e736974696f6e20496e637265617365416c6c6f77616e636520287370656e646572203a20427953747232302c20616d6f756e74203a2055696e74313238295c6e63757272656e745f696d706c203c2d20696d706c656d656e746174696f6e3b5c6e5c6e6f7074696f6e5f616c6c6f77616e6365203c2d20616c6c6f77616e6365735b5f73656e6465725d5b7370656e6465725d3b5c6e616c6c6f77616e6365203d206465636f6e7374727563745f6f7074696f6e5f75696e74313238206f7074696f6e5f616c6c6f77616e63653b5c6e5c6e6d7367203d207b5f746167203a205c22496e637265617365416c6c6f77616e63655c223b205f726563697069656e74203a2063757272656e745f696d706c3b205f616d6f756e74203a207a65726f3b5c6e7370656e646572203a207370656e6465723b20616d6f756e74203a20616d6f756e743b20696e69746961746f72203a205f73656e6465723b2063757272656e745f616c6c6f77616e6365203a20616c6c6f77616e63657d3b5c6e6d736773203d206f6e655f6d7367206d73673b5c6e73656e64206d7367735c6e656e645c6e5c6e7472616e736974696f6e204465637265617365416c6c6f77616e636520287370656e646572203a20427953747232302c20616d6f756e74203a2055696e74313238295c6e63757272656e745f696d706c203c2d20696d706c656d656e746174696f6e3b5c6e5c6e6f7074696f6e5f616c6c6f77616e6365203c2d20616c6c6f77616e6365735b5f73656e6465725d5b7370656e6465725d3b5c6e616c6c6f77616e6365203d206465636f6e7374727563745f6f7074696f6e5f75696e74313238206f7074696f6e5f616c6c6f77616e63653b5c6e5c6e6d7367203d207b5f746167203a205c224465637265617365416c6c6f77616e63655c223b205f726563697069656e74203a2063757272656e745f696d706c3b205f616d6f756e74203a207a65726f3b5c6e7370656e646572203a207370656e6465723b20616d6f756e74203a20616d6f756e743b20696e69746961746f72203a205f73656e6465723b2063757272656e745f616c6c6f77616e6365203a20616c6c6f77616e63657d3b5c6e6d736773203d206f6e655f6d7367206d73673b5c6e73656e64206d7367735c6e656e645c6e5c6e7472616e736974696f6e20416c6c6f77616e636543616c6c4261636b28696e69746961746f72203a20427953747232302c207370656e646572203a20427953747232302c206e65775f616c6c6f77616e6365203a2055696e74313238295c6e697343757272496d706c205f73656e6465723b5c6e5c6e616c6c6f77616e6365735b696e69746961746f725d5b7370656e6465725d203a3d206e65775f616c6c6f77616e63655c6e656e645c6e5c6e7472616e736974696f6e205472616e7366657246726f6d202866726f6d203a20427953747232302c20746f203a20427953747232302c20616d6f756e74203a2055696e74313238295c6e63757272656e745f696d706c203c2d20696d706c656d656e746174696f6e3b5c6e6765745f746f5f62616c203c2d2062616c616e6365735b746f5d3b5c6e746f5f62616c203d206465636f6e7374727563745f6f7074696f6e5f75696e74313238206765745f746f5f62616c3b5c6e5c6e6765745f66726f6d5f62616c203c2d2062616c616e6365735b66726f6d5d3b5c6e66726f6d5f62616c203d206465636f6e7374727563745f6f7074696f6e5f75696e74313238206765745f66726f6d5f62616c3b5c6e5c6e6f7074696f6e5f616c6c6f77616e6365203c2d20616c6c6f77616e6365735b66726f6d5d5b5f73656e6465725d3b5c6e7370656e6465725f616c6c6f77616e6365203d206465636f6e7374727563745f6f7074696f6e5f75696e74313238206f7074696f6e5f616c6c6f77616e63653b5c6e5c6e6d7367203d207b5f746167203a205c225472616e7366657246726f6d5c223b205f726563697069656e74203a2063757272656e745f696d706c3b205f616d6f756e74203a207a65726f3b5c6e66726f6d203a2066726f6d3b20746f203a20746f3b20616d6f756e74203a20616d6f756e743b20696e69746961746f72203a205f73656e6465723b20746f5f62616c203a20746f5f62616c3b2066726f6d5f62616c203a2066726f6d5f62616c3b207370656e6465725f616c6c6f77616e6365203a207370656e6465725f616c6c6f77616e63657d3b5c6e6d736773203d206f6e655f6d7367206d73673b5c6e73656e64206d7367735c6e656e645c6e5c6e7472616e736974696f6e205472616e7366657246726f6d43616c6c4261636b2866726f6d203a20427953747232302c20746f203a20427953747232302c206e65775f66726f6d5f62616c203a2055696e743132382c206e65775f746f5f62616c203a2055696e74313238295c6e697343757272496d706c205f73656e6465723b5c6e5c6e62616c616e6365735b746f5d203a3d206e65775f746f5f62616c3b5c6e62616c616e6365735b66726f6d5d203a3d206e65775f66726f6d5f62616c5c6e656e645c6e5c6e7472616e736974696f6e205472616e736665722028746f203a20427953747232302c20616d6f756e74203a2055696e74313238295c6e63757272656e745f696d706c203c2d20696d706c656d656e746174696f6e3b5c6e6765745f746f5f62616c203c2d2062616c616e6365735b746f5d3b5c6e746f5f62616c203d206465636f6e7374727563745f6f7074696f6e5f75696e74313238206765745f746f5f62616c3b5c6e6765745f696e69745f62616c203c2d2062616c616e6365735b5f73656e6465725d3b5c6e696e69745f62616c203d206465636f6e7374727563745f6f7074696f6e5f75696e74313238206765745f696e69745f62616c3b5c6e6d7367203d207b5f746167203a205c225472616e736665725c223b205f726563697069656e74203a2063757272656e745f696d706c3b205f616d6f756e74203a207a65726f3b20746f203a20746f3b5c6e616d6f756e74203a20616d6f756e743b20696e69746961746f72203a205f73656e6465723b20746f5f62616c203a20746f5f62616c3b20696e69745f62616c203a20696e69745f62616c7d3b5c6e6d736773203d206f6e655f6d7367206d73673b5c6e73656e64206d7367735c6e656e645c6e5c6e7472616e736974696f6e205472616e7366657243616c6c4261636b28746f203a20427953747232302c20696e69746961746f72203a20427953747232302c206e65775f746f5f62616c203a2055696e743132382c206e65775f696e69745f62616c203a2055696e74313238295c6e697343757272496d706c205f73656e6465723b5c6e5c6e62616c616e6365735b746f5d203a3d206e65775f746f5f62616c3b5c6e62616c616e6365735b696e69746961746f725d203a3d206e65775f696e69745f62616c5c6e656e645c6e5c6e7472616e736974696f6e204275726e28616d6f756e74203a2055696e74313238295c6e63757272656e745f696d706c203c2d20696d706c656d656e746174696f6e3b5c6e63757272656e745f737570706c79203c2d20746f74616c5f737570706c793b5c6e6765745f6275726e5f62616c203c2d2062616c616e6365735b5f73656e6465725d3b5c6e6275726e5f62616c203d206465636f6e7374727563745f6f7074696f6e5f75696e74313238206765745f6275726e5f62616c3b5c6e6d7367203d207b5f746167203a205c224275726e5c223b205f726563697069656e74203a2063757272656e745f696d706c3b205f616d6f756e74203a207a65726f3b20616d6f756e74203a20616d6f756e743b20696e69746961746f72203a205f73656e6465723b20696e69746961746f725f62616c616e6365203a206275726e5f62616c3b2063757272656e745f737570706c79203a2063757272656e745f737570706c797d3b5c6e6d736773203d206f6e655f6d7367206d73673b5c6e73656e64206d7367735c6e656e645c6e5c6e7472616e736974696f6e204275726e43616c6c4261636b28696e69746961746f72203a20427953747232302c206e65775f6275726e5f62616c616e6365203a2055696e743132382c206e65775f737570706c79203a2055696e74313238295c6e697343757272496d706c205f73656e6465723b5c6e5c6e62616c616e6365735b696e69746961746f725d203a3d206e65775f6275726e5f62616c616e63653b5c6e746f74616c5f737570706c79203a3d206e65775f737570706c795c6e656e645c6e5c6e7472616e736974696f6e204c6177456e666f7263656d656e74576970696e674275726e2861646472657373203a2042795374723230295c6e63757272656e745f696d706c203c2d20696d706c656d656e746174696f6e3b5c6e63757272656e745f737570706c79203c2d20746f74616c5f737570706c793b5c6e6765745f616464725f62616c203c2d2062616c616e6365735b616464726573735d3b5c6e616464725f62616c203d206465636f6e7374727563745f6f7074696f6e5f75696e74313238206765745f616464725f62616c3b5c6e6d7367203d207b5f746167203a205c224c6177456e666f7263656d656e74576970696e674275726e5c223b205f726563697069656e74203a2063757272656e745f696d706c3b205f616d6f756e74203a207a65726f3b2061646472657373203a20616464726573733b20696e69746961746f72203a205f73656e6465723b20616464725f62616c203a20616464725f62616c3b2063757272656e745f737570706c79203a2063757272656e745f737570706c797d3b5c6e6d736773203d206f6e655f6d7367206d73673b5c6e73656e64206d7367735c6e656e645c6e5c6e7472616e736974696f6e204c6177456e666f7263656d656e74576970696e674275726e43616c6c4261636b2861646472657373203a20427953747232302c206e65775f737570706c79203a2055696e74313238295c6e697343757272496d706c205f73656e6465723b5c6e5c6e62616c616e6365735b616464726573735d203a3d207a65726f3b5c6e746f74616c5f737570706c79203a3d206e65775f737570706c795c6e656e645c6e5c6e7472616e736974696f6e20496e6372656173654d696e746572416c6c6f77616e6365286d696e746572203a20427953747232302c20616d6f756e74203a2055696e74313238295c6e63757272656e745f696d706c203c2d20696d706c656d656e746174696f6e3b5c6e6d7367203d207b5f746167203a205c22496e6372656173654d696e746572416c6c6f77616e63655c223b205f726563697069656e74203a2063757272656e745f696d706c3b205f616d6f756e74203a207a65726f3b206d696e746572203a206d696e7465723b5c6e616d6f756e74203a20616d6f756e743b20696e69746961746f72203a205f73656e6465727d3b5c6e6d736773203d206f6e655f6d7367206d73673b5c6e73656e64206d7367735c6e656e645c6e5c6e7472616e736974696f6e2044656372656173654d696e746572416c6c6f77616e6365286d696e746572203a20427953747232302c20616d6f756e74203a2055696e74313238295c6e63757272656e745f696d706c203c2d20696d706c656d656e746174696f6e3b5c6e6d7367203d207b5f746167203a205c2244656372656173654d696e746572416c6c6f77616e63655c223b205f726563697069656e74203a2063757272656e745f696d706c3b205f616d6f756e74203a207a65726f3b206d696e746572203a206d696e7465723b5c6e616d6f756e74203a20616d6f756e743b20696e69746961746f72203a205f73656e6465727d3b5c6e6d736773203d206f6e655f6d7367206d73673b5c6e73656e64206d7367735c6e656e645c6e5c6e7472616e736974696f6e205570646174654d61737465724d696e746572286e65774d61737465724d696e746572203a2042795374723230295c6e63757272656e745f696d706c203c2d20696d706c656d656e746174696f6e3b5c6e6d7367203d207b5f746167203a205c225570646174654d61737465724d696e7465725c223b205f726563697069656e74203a2063757272656e745f696d706c3b205f616d6f756e74203a207a65726f3b206e65774d61737465724d696e746572203a206e65774d61737465724d696e7465723b5c6e696e69746961746f72203a205f73656e6465727d3b5c6e6d736773203d206f6e655f6d7367206d73673b5c6e73656e64206d7367735c6e656e645c6e222c22696e69745f64617461223a5b7b22766e616d65223a225f7363696c6c615f76657273696f6e222c2276616c7565223a225c22305c22222c2274797065223a2255696e743332227d2c7b22766e616d65223a22636f6e74726163745f6f776e6572222c2276616c7565223a225c223078306638313637613043424666623841423164313931394533316638334443323643383633443046395c22222c2274797065223a2242795374723230227d2c7b22766e616d65223a226e616d65222c2276616c7565223a225c22585347445c22222c2274797065223a22537472696e67227d2c7b22766e616d65223a2273796d626f6c222c2276616c7565223a225c22585347445c22222c2274797065223a22537472696e67227d2c7b22766e616d65223a22646563696d616c73222c2276616c7565223a225c22365c22222c2274797065223a2255696e743332227d2c7b22766e616d65223a22696e69745f737570706c79222c2276616c7565223a225c22305c22222c2274797065223a2255696e74313238227d2c7b22766e616d65223a22696e69745f696d706c656d656e746174696f6e222c2276616c7565223a225c223078306638313637613043424666623841423164313931394533316638334443323643383633443046395c22222c2274797065223a2242795374723230227d2c7b22766e616d65223a22696e69745f61646d696e222c2276616c7565223a225c223078306638313637613043424666623841423164313931394533316638334443323643383633443046395c22222c2274797065223a2242795374723230227d2c7b22766e616d65223a225f6372656174696f6e5f626c6f636b222c2276616c7565223a225c223733323532395c22222c2274797065223a22424e756d227d2c7b22766e616d65223a225f746869735f61646472657373222c2276616c7565223a225c223078313733636136373730616135366562303035313164616338653665313362336437663136613561355c22222c2274797065223a2242795374723230227d5d2c227479706573223a7b2261646d696e223a5b2242795374723230222c305d2c22616c6c6f77616e636573223a5b224d61702028427953747232302920284d617020284279537472323029202855696e743132382929222c325d2c2262616c616e636573223a5b224d617020284279537472323029202855696e7431323829222c315d2c22696d706c656d656e746174696f6e223a5b2242795374723230222c305d2c22746f74616c5f737570706c79223a5b2255696e74313238222c305d7d2c227472616e736974696f6e73223a5b7b22766e616d65223a2255706772616465546f222c22706172616d73223a5b7b22766e616d65223a226e6577496d706c656d656e746174696f6e222c2274797065223a2242795374723230227d5d7d2c7b22766e616d65223a224368616e676541646d696e222c22706172616d73223a5b7b22766e616d65223a226e657741646d696e222c2274797065223a2242795374723230227d5d7d2c7b22766e616d65223a225472616e736665724f776e657273686970222c22706172616d73223a5b7b22766e616d65223a226e65774f776e6572222c2274797065223a2242795374723230227d5d7d2c7b22766e616d65223a225061757365222c22706172616d73223a5b5d7d2c7b22766e616d65223a22556e7061757365222c22706172616d73223a5b5d7d2c7b22766e616d65223a22557064617465506175736572222c22706172616d73223a5b7b22766e616d65223a226e6577506175736572222c2274797065223a2242795374723230227d5d7d2c7b22766e616d65223a22426c61636b6c697374222c22706172616d73223a5b7b22766e616d65223a2261646472657373222c2274797065223a2242795374723230227d5d7d2c7b22766e616d65223a22556e626c61636b6c697374222c22706172616d73223a5b7b22766e616d65223a2261646472657373222c2274797065223a2242795374723230227d5d7d2c7b22766e616d65223a22557064617465426c61636b6c6973746572222c22706172616d73223a5b7b22766e616d65223a226e6577426c61636b6c6973746572222c2274797065223a2242795374723230227d5d7d2c7b22766e616d65223a224d696e74222c22706172616d73223a5b7b22766e616d65223a22726563697069656e74222c2274797065223a2242795374723230227d2c7b22766e616d65223a22616d6f756e74222c2274797065223a2255696e74313238227d5d7d2c7b22766e616d65223a224d696e7443616c6c4261636b222c22706172616d73223a5b7b22766e616d65223a22746f222c2274797065223a2242795374723230227d2c7b22766e616d65223a226e65775f746f5f62616c222c2274797065223a2255696e74313238227d2c7b22766e616d65223a226e65775f737570706c79222c2274797065223a2255696e74313238227d5d7d2c7b22766e616d65223a22496e637265617365416c6c6f77616e6365222c22706172616d73223a5b7b22766e616d65223a227370656e646572222c2274797065223a2242795374723230227d2c7b22766e616d65223a22616d6f756e74222c2274797065223a2255696e74313238227d5d7d2c7b22766e616d65223a224465637265617365416c6c6f77616e6365222c22706172616d73223a5b7b22766e616d65223a227370656e646572222c2274797065223a2242795374723230227d2c7b22766e616d65223a22616d6f756e74222c2274797065223a2255696e74313238227d5d7d2c7b22766e616d65223a22416c6c6f77616e636543616c6c4261636b222c22706172616d73223a5b7b22766e616d65223a22696e69746961746f72222c2274797065223a2242795374723230227d2c7b22766e616d65223a227370656e646572222c2274797065223a2242795374723230227d2c7b22766e616d65223a226e65775f616c6c6f77616e6365222c2274797065223a2255696e74313238227d5d7d2c7b22766e616d65223a225472616e7366657246726f6d222c22706172616d73223a5b7b22766e616d65223a2266726f6d222c2274797065223a2242795374723230227d2c7b22766e616d65223a22746f222c2274797065223a2242795374723230227d2c7b22766e616d65223a22616d6f756e74222c2274797065223a2255696e74313238227d5d7d2c7b22766e616d65223a225472616e7366657246726f6d43616c6c4261636b222c22706172616d73223a5b7b22766e616d65223a2266726f6d222c2274797065223a2242795374723230227d2c7b22766e616d65223a22746f222c2274797065223a2242795374723230227d2c7b22766e616d65223a226e65775f66726f6d5f62616c222c2274797065223a2255696e74313238227d2c7b22766e616d65223a226e65775f746f5f62616c222c2274797065223a2255696e74313238227d5d7d2c7b22766e616d65223a225472616e73666572222c22706172616d73223a5b7b22766e616d65223a22746f222c2274797065223a2242795374723230227d2c7b22766e616d65223a22616d6f756e74222c2274797065223a2255696e74313238227d5d7d2c7b22766e616d65223a225472616e7366657243616c6c4261636b222c22706172616d73223a5b7b22766e616d65223a22746f222c2274797065223a2242795374723230227d2c7b22766e616d65223a22696e69746961746f72222c2274797065223a2242795374723230227d2c7b22766e616d65223a226e65775f746f5f62616c222c2274797065223a2255696e74313238227d2c7b22766e616d65223a226e65775f696e69745f62616c222c2274797065223a2255696e74313238227d5d7d2c7b22766e616d65223a224275726e222c22706172616d73223a5b7b22766e616d65223a22616d6f756e74222c2274797065223a2255696e74313238227d5d7d2c7b22766e616d65223a224275726e43616c6c4261636b222c22706172616d73223a5b7b22766e616d65223a22696e69746961746f72222c2274797065223a2242795374723230227d2c7b22766e616d65223a226e65775f6275726e5f62616c616e6365222c2274797065223a2255696e74313238227d2c7b22766e616d65223a226e65775f737570706c79222c2274797065223a2255696e74313238227d5d7d2c7b22766e616d65223a224c6177456e666f7263656d656e74576970696e674275726e222c22706172616d73223a5b7b22766e616d65223a2261646472657373222c2274797065223a2242795374723230227d5d7d2c7b22766e616d65223a224c6177456e666f7263656d656e74576970696e674275726e43616c6c4261636b222c22706172616d73223a5b7b22766e616d65223a2261646472657373222c2274797065223a2242795374723230227d2c7b22766e616d65223a226e65775f737570706c79222c2274797065223a2255696e74313238227d5d7d2c7b22766e616d65223a22496e6372656173654d696e746572416c6c6f77616e6365222c22706172616d73223a5b7b22766e616d65223a226d696e746572222c2274797065223a2242795374723230227d2c7b22766e616d65223a22616d6f756e74222c2274797065223a2255696e74313238227d5d7d2c7b22766e616d65223a2244656372656173654d696e746572416c6c6f77616e6365222c22706172616d73223a5b7b22766e616d65223a226d696e746572222c2274797065223a2242795374723230227d2c7b22766e616d65223a22616d6f756e74222c2274797065223a2255696e74313238227d5d7d2c7b22766e616d65223a225570646174654d61737465724d696e746572222c22706172616d73223a5b7b22766e616d65223a226e65774d61737465724d696e746572222c2274797065223a2242795374723230227d5d7d5d7d7d";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisDeposit {
    pub public_key: NodePublicKey,
    pub peer_id: PeerId,
    pub stake: Amount,
    pub reward_address: Address,
    pub control_address: Address,
}

pub fn consensus_timeout_default() -> Duration {
    Duration::from_secs(15)
}

pub fn block_time_default() -> Duration {
    Duration::from_millis(1000)
}

pub fn scilla_address_default() -> String {
    String::from("http://localhost:62831")
}

// This path is as viewed from Scilla, not zq2.
pub fn scilla_stdlib_dir_default() -> String {
    String::from("/scilla/0/_build/default/src/stdlib/")
}

pub fn scilla_ext_libs_path_default() -> ScillaExtLibsPath {
    ScillaExtLibsPath {
        zq2: ScillaExtLibsPathInZq2(String::from("/tmp/scilla_ext_libs")),
        scilla: ScillaExtLibsPathInScilla(String::from("/scilla_ext_libs")),
    }
}

pub fn scilla_server_socket_directory_default() -> String {
    String::from("/tmp/scilla-state-server")
}

pub fn blocks_per_epoch_default() -> u64 {
    3600
}

pub fn epochs_per_checkpoint_default() -> u64 {
    24
}

fn default_true() -> bool {
    true
}

pub fn total_native_token_supply_default() -> Amount {
    Amount::from(21_000_000_000_000_000_000_000_000_000)
}

pub fn withdrawal_period_default() -> u64 {
    // 2 weeks worth of blocks with 1 second block time
    2 * 7 * 24 * 60 * 60
}

/// The default implementation returns a single fork at the genesis block, with the most up-to-date
/// execution logic.
pub fn genesis_fork_default() -> Fork {
    Fork {
        at_height: 0,
        executable_blocks: true,
        failed_scilla_call_from_gas_exempt_caller_causes_revert: true,
        call_mode_1_sets_caller_to_parent_caller: true,
        scilla_messages_can_call_evm_contracts: true,
        scilla_contract_creation_increments_account_balance: true,
        scilla_json_preserve_order: true,
        scilla_call_respects_evm_state_changes: true,
        only_mutated_accounts_update_state: true,
        scilla_call_gas_exempt_addrs: vec![],
        scilla_block_number_returns_current_block: true,
        scilla_maps_are_encoded_correctly: true,
        transfer_gas_fee_to_zero_account: true,
        apply_scilla_delta_when_evm_succeeded: true,
        apply_state_changes_only_if_transaction_succeeds: true,
        scilla_deduct_funds_from_actual_sender: true,
        fund_accounts_from_zero_account: vec![],
        scilla_delta_maps_are_applied_correctly: true,
        scilla_server_unlimited_response_size: true,
        scilla_failed_txn_correct_balance_deduction: true,
        scilla_transition_proper_order: true,
        evm_to_scilla_value_transfer_zero: true,
        restore_xsgd_contract: true,
        evm_exec_failure_causes_scilla_precompile_to_fail: true,
        revert_restore_xsgd_contract: true,
        scilla_fix_contract_code_removal_on_evm_tx: true,
    }
}

pub fn new_view_broadcast_interval_default() -> Duration {
    Duration::from_secs(300)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReinitialiseParams {
    /// The minimum number of blocks a staker must wait before being able to withdraw unstaked funds
    pub withdrawal_period: u64,
}

impl Default for ReinitialiseParams {
    fn default() -> Self {
        Self {
            withdrawal_period: withdrawal_period_default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractUpgradeConfig {
    pub height: u64,
    pub reinitialise_params: Option<ReinitialiseParams>,
}

impl ContractUpgradeConfig {
    pub fn from_height(height: u64) -> Self {
        Self {
            height,
            reinitialise_params: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractUpgrades {
    pub deposit_v3: Option<ContractUpgradeConfig>,
    pub deposit_v4: Option<ContractUpgradeConfig>,
    pub deposit_v5: Option<ContractUpgradeConfig>,
}

impl ContractUpgrades {
    pub fn new(
        deposit_v3: Option<ContractUpgradeConfig>,
        deposit_v4: Option<ContractUpgradeConfig>,
        deposit_v5: Option<ContractUpgradeConfig>,
    ) -> ContractUpgrades {
        Self {
            deposit_v3,
            deposit_v4,
            deposit_v5,
        }
    }
    pub fn to_toml(&self) -> toml::Value {
        // toml doesn't like Option types. We need to manually map items in struct removing keys for None values as we go
        // ContractUpgrades's values are only either u64, None or a json object
        fn serde_value_to_toml_value(input: serde_json::Value) -> toml::Value {
            toml::Value::Table(
                input
                    .as_object()
                    .unwrap()
                    .clone()
                    .into_iter()
                    .filter_map(|(k, v)| {
                        if v.is_null() {
                            // Ignore None values
                            None
                        } else if v.is_u64() {
                            // Parse ints
                            Some((k, toml::Value::Integer(v.as_u64().unwrap() as i64)))
                        } else {
                            // Recursively parse objects
                            Some((k, serde_value_to_toml_value(v)))
                        }
                    })
                    .collect(),
            )
        }
        serde_value_to_toml_value(json!(self))
    }
}

impl Default for ContractUpgrades {
    fn default() -> Self {
        Self {
            deposit_v3: None,
            deposit_v4: None,
            deposit_v5: Some(ContractUpgradeConfig {
                height: 0,
                reinitialise_params: Some(ReinitialiseParams::default()),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_forks_with_no_forks() {
        let config = ConsensusConfig {
            genesis_fork: genesis_fork_default(),
            forks: vec![],
            ..Default::default()
        };

        let forks = config.get_forks().unwrap();
        assert_eq!(forks.0.len(), 1);
        assert_eq!(forks.get(0).at_height, 0);
    }

    #[test]
    fn test_get_forks_with_one_fork() {
        let config = ConsensusConfig {
            genesis_fork: genesis_fork_default(),
            forks: vec![ForkDelta {
                at_height: 10,
                executable_blocks: None,
                failed_scilla_call_from_gas_exempt_caller_causes_revert: None,
                call_mode_1_sets_caller_to_parent_caller: Some(false),
                scilla_messages_can_call_evm_contracts: None,
                scilla_contract_creation_increments_account_balance: Some(false),
                scilla_json_preserve_order: None,
                scilla_call_respects_evm_state_changes: None,
                only_mutated_accounts_update_state: None,
                scilla_call_gas_exempt_addrs: vec![],
                scilla_block_number_returns_current_block: None,
                scilla_maps_are_encoded_correctly: None,
                transfer_gas_fee_to_zero_account: None,
                apply_scilla_delta_when_evm_succeeded: None,
                apply_state_changes_only_if_transaction_succeeds: None,
                scilla_deduct_funds_from_actual_sender: None,
                fund_accounts_from_zero_account: None,
                scilla_delta_maps_are_applied_correctly: None,
                scilla_server_unlimited_response_size: None,
                scilla_failed_txn_correct_balance_deduction: None,
                scilla_transition_proper_order: None,
                evm_to_scilla_value_transfer_zero: None,
                restore_xsgd_contract: None,
                evm_exec_failure_causes_scilla_precompile_to_fail: None,
                revert_restore_xsgd_contract: None,
                scilla_fix_contract_code_removal_on_evm_tx: None,
            }],
            ..Default::default()
        };

        let forks = config.get_forks().unwrap();
        assert_eq!(forks.0.len(), 2);
        assert_eq!(forks.get(0).at_height, 0);
        assert_eq!(forks.get(11).at_height, 10);
        assert!(!forks.get(10).call_mode_1_sets_caller_to_parent_caller);
        assert!(
            !forks
                .get(10)
                .scilla_contract_creation_increments_account_balance
        );
    }

    #[test]
    fn test_get_forks_with_multiple_forks() {
        let config = ConsensusConfig {
            genesis_fork: genesis_fork_default(),
            forks: vec![
                ForkDelta {
                    at_height: 10,
                    executable_blocks: Some(true),
                    failed_scilla_call_from_gas_exempt_caller_causes_revert: Some(true),
                    call_mode_1_sets_caller_to_parent_caller: None,
                    scilla_messages_can_call_evm_contracts: Some(true),
                    scilla_contract_creation_increments_account_balance: None,
                    scilla_json_preserve_order: Some(true),
                    scilla_call_respects_evm_state_changes: None,
                    only_mutated_accounts_update_state: None,
                    scilla_call_gas_exempt_addrs: vec![],
                    scilla_block_number_returns_current_block: None,
                    scilla_maps_are_encoded_correctly: None,
                    transfer_gas_fee_to_zero_account: None,
                    apply_scilla_delta_when_evm_succeeded: None,
                    apply_state_changes_only_if_transaction_succeeds: None,
                    scilla_deduct_funds_from_actual_sender: None,
                    fund_accounts_from_zero_account: None,
                    scilla_delta_maps_are_applied_correctly: None,
                    scilla_server_unlimited_response_size: None,
                    scilla_failed_txn_correct_balance_deduction: None,
                    scilla_transition_proper_order: None,
                    evm_to_scilla_value_transfer_zero: None,
                    restore_xsgd_contract: None,
                    evm_exec_failure_causes_scilla_precompile_to_fail: None,
                    revert_restore_xsgd_contract: None,
                    scilla_fix_contract_code_removal_on_evm_tx: None,
                },
                ForkDelta {
                    at_height: 20,
                    executable_blocks: Some(true),
                    failed_scilla_call_from_gas_exempt_caller_causes_revert: Some(false),
                    call_mode_1_sets_caller_to_parent_caller: Some(true),
                    scilla_messages_can_call_evm_contracts: Some(false),
                    scilla_contract_creation_increments_account_balance: Some(true),
                    scilla_json_preserve_order: Some(true),
                    scilla_call_respects_evm_state_changes: None,
                    only_mutated_accounts_update_state: None,
                    scilla_call_gas_exempt_addrs: vec![],
                    scilla_block_number_returns_current_block: None,
                    scilla_maps_are_encoded_correctly: None,
                    transfer_gas_fee_to_zero_account: None,
                    apply_scilla_delta_when_evm_succeeded: None,
                    apply_state_changes_only_if_transaction_succeeds: None,
                    scilla_deduct_funds_from_actual_sender: None,
                    fund_accounts_from_zero_account: None,
                    scilla_delta_maps_are_applied_correctly: None,
                    scilla_server_unlimited_response_size: None,
                    scilla_failed_txn_correct_balance_deduction: None,
                    scilla_transition_proper_order: None,
                    evm_to_scilla_value_transfer_zero: None,
                    restore_xsgd_contract: None,
                    evm_exec_failure_causes_scilla_precompile_to_fail: None,
                    revert_restore_xsgd_contract: None,
                    scilla_fix_contract_code_removal_on_evm_tx: None,
                },
            ],
            ..Default::default()
        };

        let forks = config.get_forks().unwrap();
        assert_eq!(forks.0.len(), 3);
        assert_eq!(forks.get(0).at_height, 0);
        assert_eq!(forks.get(11).at_height, 10);
        assert_eq!(forks.get(21).at_height, 20);
        assert!(
            forks
                .get(10)
                .failed_scilla_call_from_gas_exempt_caller_causes_revert
        );
        assert!(forks.get(11).scilla_messages_can_call_evm_contracts);
        assert!(
            !forks
                .get(20)
                .failed_scilla_call_from_gas_exempt_caller_causes_revert
        );
        assert!(forks.get(20).call_mode_1_sets_caller_to_parent_caller);
        assert!(!forks.get(20).scilla_messages_can_call_evm_contracts);
        assert!(
            forks
                .get(20)
                .scilla_contract_creation_increments_account_balance
        );
    }

    #[test]
    fn test_get_forks_with_unsorted_forks() {
        let config = ConsensusConfig {
            genesis_fork: genesis_fork_default(),
            forks: vec![
                ForkDelta {
                    at_height: 20,
                    executable_blocks: Some(true),
                    failed_scilla_call_from_gas_exempt_caller_causes_revert: Some(false),
                    call_mode_1_sets_caller_to_parent_caller: None,
                    scilla_messages_can_call_evm_contracts: None,
                    scilla_contract_creation_increments_account_balance: None,
                    scilla_json_preserve_order: None,
                    scilla_call_respects_evm_state_changes: None,
                    only_mutated_accounts_update_state: None,
                    scilla_call_gas_exempt_addrs: vec![],
                    scilla_block_number_returns_current_block: None,
                    scilla_maps_are_encoded_correctly: None,
                    transfer_gas_fee_to_zero_account: None,
                    apply_scilla_delta_when_evm_succeeded: None,
                    apply_state_changes_only_if_transaction_succeeds: None,
                    scilla_deduct_funds_from_actual_sender: None,
                    fund_accounts_from_zero_account: None,
                    scilla_delta_maps_are_applied_correctly: None,
                    scilla_server_unlimited_response_size: None,
                    scilla_failed_txn_correct_balance_deduction: None,
                    scilla_transition_proper_order: None,
                    evm_to_scilla_value_transfer_zero: None,
                    restore_xsgd_contract: None,
                    evm_exec_failure_causes_scilla_precompile_to_fail: None,
                    revert_restore_xsgd_contract: None,
                    scilla_fix_contract_code_removal_on_evm_tx: None,
                },
                ForkDelta {
                    at_height: 10,
                    executable_blocks: Some(true),
                    failed_scilla_call_from_gas_exempt_caller_causes_revert: None,
                    call_mode_1_sets_caller_to_parent_caller: None,
                    scilla_messages_can_call_evm_contracts: None,
                    scilla_contract_creation_increments_account_balance: None,
                    scilla_json_preserve_order: None,
                    scilla_call_respects_evm_state_changes: None,
                    only_mutated_accounts_update_state: None,
                    scilla_call_gas_exempt_addrs: vec![],
                    scilla_block_number_returns_current_block: None,
                    scilla_maps_are_encoded_correctly: None,
                    transfer_gas_fee_to_zero_account: None,
                    apply_scilla_delta_when_evm_succeeded: None,
                    apply_state_changes_only_if_transaction_succeeds: None,
                    scilla_deduct_funds_from_actual_sender: None,
                    fund_accounts_from_zero_account: None,
                    scilla_delta_maps_are_applied_correctly: None,
                    scilla_server_unlimited_response_size: None,
                    scilla_failed_txn_correct_balance_deduction: None,
                    scilla_transition_proper_order: None,
                    evm_to_scilla_value_transfer_zero: None,
                    restore_xsgd_contract: None,
                    evm_exec_failure_causes_scilla_precompile_to_fail: None,
                    revert_restore_xsgd_contract: None,
                    scilla_fix_contract_code_removal_on_evm_tx: None,
                },
            ],
            ..Default::default()
        };

        let forks = config.get_forks().unwrap();
        assert_eq!(forks.0.len(), 3);
        assert_eq!(forks.get(0).at_height, 0);
        assert_eq!(forks.get(12).at_height, 10);
        assert_eq!(forks.get(22).at_height, 20);

        assert!(
            forks
                .get(10)
                .failed_scilla_call_from_gas_exempt_caller_causes_revert
        );
        assert!(
            !forks
                .get(20)
                .failed_scilla_call_from_gas_exempt_caller_causes_revert
        );
    }

    #[test]
    fn test_get_forks_with_missing_genesis_fork() {
        let config = ConsensusConfig {
            genesis_fork: Fork {
                at_height: 1,
                executable_blocks: true,
                failed_scilla_call_from_gas_exempt_caller_causes_revert: true,
                call_mode_1_sets_caller_to_parent_caller: true,
                scilla_messages_can_call_evm_contracts: true,
                scilla_contract_creation_increments_account_balance: true,
                scilla_json_preserve_order: true,
                scilla_call_respects_evm_state_changes: true,
                only_mutated_accounts_update_state: true,
                scilla_call_gas_exempt_addrs: vec![],
                scilla_block_number_returns_current_block: true,
                scilla_maps_are_encoded_correctly: true,
                transfer_gas_fee_to_zero_account: true,
                apply_scilla_delta_when_evm_succeeded: true,
                apply_state_changes_only_if_transaction_succeeds: true,
                scilla_deduct_funds_from_actual_sender: true,
                fund_accounts_from_zero_account: vec![],
                scilla_delta_maps_are_applied_correctly: true,
                scilla_server_unlimited_response_size: true,
                scilla_failed_txn_correct_balance_deduction: true,
                scilla_transition_proper_order: true,
                evm_to_scilla_value_transfer_zero: true,
                restore_xsgd_contract: true,
                evm_exec_failure_causes_scilla_precompile_to_fail: true,
                revert_restore_xsgd_contract: true,
                scilla_fix_contract_code_removal_on_evm_tx: true,
            },
            forks: vec![],
            ..Default::default()
        };

        let result = config.get_forks();
        assert!(result.is_err());
    }

    #[test]
    fn test_get_forks_boundary_cases() {
        let config = ConsensusConfig {
            genesis_fork: genesis_fork_default(),
            forks: vec![
                ForkDelta {
                    at_height: 10,
                    executable_blocks: None,
                    failed_scilla_call_from_gas_exempt_caller_causes_revert: None,
                    call_mode_1_sets_caller_to_parent_caller: None,
                    scilla_messages_can_call_evm_contracts: None,
                    scilla_contract_creation_increments_account_balance: None,
                    scilla_json_preserve_order: None,
                    scilla_call_respects_evm_state_changes: None,
                    only_mutated_accounts_update_state: None,
                    scilla_call_gas_exempt_addrs: vec![],
                    scilla_block_number_returns_current_block: None,
                    scilla_maps_are_encoded_correctly: None,
                    transfer_gas_fee_to_zero_account: None,
                    apply_scilla_delta_when_evm_succeeded: None,
                    apply_state_changes_only_if_transaction_succeeds: None,
                    scilla_deduct_funds_from_actual_sender: None,
                    fund_accounts_from_zero_account: None,
                    scilla_delta_maps_are_applied_correctly: None,
                    scilla_server_unlimited_response_size: None,
                    scilla_failed_txn_correct_balance_deduction: None,
                    scilla_transition_proper_order: None,
                    evm_to_scilla_value_transfer_zero: None,
                    restore_xsgd_contract: None,
                    evm_exec_failure_causes_scilla_precompile_to_fail: None,
                    revert_restore_xsgd_contract: None,
                    scilla_fix_contract_code_removal_on_evm_tx: None,
                },
                ForkDelta {
                    at_height: 20,
                    executable_blocks: None,
                    failed_scilla_call_from_gas_exempt_caller_causes_revert: None,
                    call_mode_1_sets_caller_to_parent_caller: None,
                    scilla_messages_can_call_evm_contracts: None,
                    scilla_contract_creation_increments_account_balance: None,
                    scilla_json_preserve_order: None,
                    scilla_call_respects_evm_state_changes: None,
                    only_mutated_accounts_update_state: None,
                    scilla_call_gas_exempt_addrs: vec![],
                    scilla_block_number_returns_current_block: None,
                    scilla_maps_are_encoded_correctly: None,
                    transfer_gas_fee_to_zero_account: None,
                    apply_scilla_delta_when_evm_succeeded: None,
                    apply_state_changes_only_if_transaction_succeeds: None,
                    scilla_deduct_funds_from_actual_sender: None,
                    fund_accounts_from_zero_account: None,
                    scilla_delta_maps_are_applied_correctly: None,
                    scilla_server_unlimited_response_size: None,
                    scilla_failed_txn_correct_balance_deduction: None,
                    scilla_transition_proper_order: None,
                    evm_to_scilla_value_transfer_zero: None,
                    restore_xsgd_contract: None,
                    evm_exec_failure_causes_scilla_precompile_to_fail: None,
                    revert_restore_xsgd_contract: None,
                    scilla_fix_contract_code_removal_on_evm_tx: None,
                },
            ],
            ..Default::default()
        };

        let forks = config.get_forks().unwrap();
        assert_eq!(forks.get(9).at_height, 0);
        assert_eq!(forks.get(10).at_height, 10);
        assert_eq!(forks.get(19).at_height, 10);
        assert_eq!(forks.get(20).at_height, 20);
        assert_eq!(forks.get(22).at_height, 20);
    }
}
