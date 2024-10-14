use std::{ops::Deref, str::FromStr, time::Duration};

use alloy::primitives::Address;
use libp2p::{Multiaddr, PeerId};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    crypto::{Hash, NodePublicKey},
    transaction::EvmGas,
};

// Note that z2 constructs instances of this to save as a configuration so it must be both
// serializable and deserializable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
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
    pub bootstrap_address: Option<(PeerId, Multiaddr)>,
    /// The base address of the OTLP collector. If not set, metrics will not be exported.
    #[serde(default)]
    pub otlp_collector_endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// The port to listen for JSON-RPC requests on. Defaults to 4201.
    #[serde(default = "json_rpc_port_default")]
    pub json_rpc_port: u16,
    /// If true, the JSON-RPC server is not started. Defaults to false.
    #[serde(default = "disable_rpc_default")]
    pub disable_rpc: bool,
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
    /// Persistence checkpoint to load.
    #[serde(default)]
    pub load_checkpoint: Option<Checkpoint>,
    /// Whether to enable exporting checkpoint state checkpoint files.
    #[serde(default)]
    pub do_checkpoints: bool,
    /// The maximum number of blocks we will send to another node in a single message.
    #[serde(default = "block_request_limit_default")]
    pub block_request_limit: usize,
    /// The maximum number of blocks to have outstanding requests for at a time when syncing.
    #[serde(default = "max_blocks_in_flight_default")]
    pub max_blocks_in_flight: u64,
    /// The maximum number of blocks to request in a single message when syncing.
    #[serde(default = "block_request_batch_size_default")]
    pub block_request_batch_size: u64,
    /// The maximum number of key value pairs allowed to be returned withing the response of the `GetSmartContractState` RPC. Defaults to no limit.
    #[serde(default = "state_rpc_limit_default")]
    pub state_rpc_limit: usize,
    /// When a block request to a peer fails, do not send another request to this peer for this amount of time.
    /// Defaults to 10 seconds.
    #[serde(default = "failed_request_sleep_duration_default")]
    pub failed_request_sleep_duration: Duration,
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

pub fn allowed_timestamp_skew_default() -> Duration {
    Duration::from_secs(10)
}

pub fn json_rpc_port_default() -> u16 {
    4201
}

pub fn eth_chain_id_default() -> u64 {
    700 + 0x8000
}

pub fn disable_rpc_default() -> bool {
    false
}

pub fn block_request_limit_default() -> usize {
    100
}

pub fn max_blocks_in_flight_default() -> u64 {
    1000
}

pub fn block_request_batch_size_default() -> u64 {
    100
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
    /// Minimum time to wait for consensus to propose new block if there are no transactions. This therefore acts also as the minimum block time.
    #[serde(default = "empty_block_timeout_default")]
    pub empty_block_timeout: Duration,
    /// Minimum remaining time before end of round in which Proposer has the opportunity to broadcast empty block proposal.
    /// If there is less time than this value left in a round then the view will likely move on before a proposal has time to be finalised.
    #[serde(default = "minimum_time_left_for_empty_block_default")]
    pub minimum_time_left_for_empty_block: Duration,
    /// Address of the Scilla server. Defaults to "http://localhost:3000".
    #[serde(default = "scilla_address_default")]
    pub scilla_address: String,
    /// Where (in the Scilla server's filesystem) is the library directory containing Scilla library functions?
    #[serde(default = "scilla_lib_dir_default")]
    pub scilla_lib_dir: String,
    /// Hostname at which this process is accessible by the Scilla process. Defaults to "localhost". If running the
    /// Scilla process in Docker and this process on the host, you probably want to pass
    /// `--add-host host.docker.internal:host-gateway` to Docker and set this to `host.docker.internal`.
    #[serde(default = "local_address_default")]
    pub local_address: String,
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
}

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
    Duration::from_secs(5)
}

pub fn empty_block_timeout_default() -> Duration {
    Duration::from_millis(1000)
}

pub fn minimum_time_left_for_empty_block_default() -> Duration {
    Duration::from_millis(3000)
}

pub fn scilla_address_default() -> String {
    String::from("http://localhost:3000")
}

pub fn scilla_lib_dir_default() -> String {
    String::from("/scilla/0/_build/default/src/stdlib/")
}

pub fn local_address_default() -> String {
    String::from("localhost")
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
