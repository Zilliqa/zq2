use std::time::Duration;

use revm::primitives::{B256, b256};

use crate::transaction::{EvmGas, ScillaGas};

// How big data slot a transaction can use
pub const EVM_TX_SLOT_IN_BYTES: usize = 32 * 1024;

// Maximum size of a transaction (4 slots)
pub const EVM_MAX_TX_INPUT_SIZE: usize = 4 * EVM_TX_SLOT_IN_BYTES; // 128KB

// Maximum bytecode size to permit for a contract
pub const EVM_MAX_CODE_SIZE: usize = 24576;

// Maximum init code to permit in create operations.
pub const EVM_MAX_INIT_CODE_SIZE: usize = 2 * EVM_MAX_CODE_SIZE;

// Minimum gas required for EVM transaction (without input data)
pub const EVM_MIN_GAS_UNITS: EvmGas = EvmGas(21000);

// Maximum code size allowed for zil transactions (imported from ZQ1)
pub const ZIL_MAX_CODE_SIZE: usize = 76800;

// Gas needed for invoking scilla contract
pub const ZIL_CONTRACT_INVOKE_GAS: usize = 10;

// Gas needed for creating scilla contract
pub const ZIL_CONTRACT_CREATE_GAS: usize = 50;

// Gas needed for making transfer using ZIL transaction
pub const ZIL_NORMAL_TXN_GAS: usize = 50;

// Maximum rate at which to send availability requests
pub const REQUEST_PEER_VIEW_AVAILABILITY_NOT_BEFORE: Duration = Duration::from_secs(300);

// We assume that every node has the last ALWAYS_RETAIN_LAST_N_BLOCKS blocks, otherwise
// it's hard ever to catch up. Set this too large and syncing will be hard because we will
// keep asking recently started nodes for blocks they don't have. Set it too small and
// it will be hard because we'll need to keep waiting for availability.
// Set to 10 because this is small enough that the statement is usually true (almost every node
// will have the last 10 blocks), but large enough that we can realistically fetch blocks
// near the head (set this to 1, for example, and we will loop requesting availability - at
// least until proposal broadcasts save us - see the comment at the top of block_cache.rs for
// details).
pub const RETAINS_LAST_N_BLOCKS: u64 = 10;

// How long do we wait before retrying a request to a peer?

// WARNING: these must be at least 1000*max_blocks_in_flight.
// All requests get this number of ms.
pub const BLOCK_REQUEST_RESPONSE_TIMEOUT: Duration = Duration::from_millis(4000);

// log2 of the number of ways in the block cache. Max 8.
pub const BLOCK_CACHE_LOG2_WAYS: usize = 4;
/// The block cache will deliberately keep this number of entries near the highest known view
/// so that it can catch up quickly when it reaches the current head of the chain.
/// Not required for correctness.
pub const BLOCK_CACHE_HEAD_BUFFER_ENTRIES: usize = 1024;

/// Max pending requests per peer
pub const MAX_PENDING_BLOCK_REQUESTS_PER_PEER: usize = 16;

/// Number of previous blocks to examine at each level of fork counter. Should be
/// set small enough to avoid serious database load, but large enough to jump any
/// plausible fork reasonably quickly.
pub const EXAMINE_BLOCKS_PER_FORK_COUNT: usize = 16;

// Gas costs.
pub const SCILLA_TRANSFER: ScillaGas = ScillaGas(50);
pub const SCILLA_INVOKE_CHECKER: ScillaGas = ScillaGas(100);
pub const SCILLA_INVOKE_RUNNER: ScillaGas = ScillaGas(300);

// Consensus
// Roughly how long to allow between finish propocessing of a Proposal and it being received by peers
pub const TIME_TO_ALLOW_PROPOSAL_BROADCAST: Duration = Duration::from_millis(100);

// Exponentional backoff timeout increases by this multiple for each view missed
pub const EXPONENTIAL_BACKOFF_TIMEOUT_MULTIPLIER: f32 = 1.25f32;

// Since we do not support base fee in blocks we set:
// base_fee: 0
// priority fee_per_gas: gas_price
pub const BASE_FEE_PER_GAS: u128 = 0;

/// P2P Configurations
pub const MAX_GOSSIP_SIZE: usize = 2 * 1024 * 1024;
pub const MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024;
pub const MAX_REQUEST_SIZE: usize = 1024 * 1024;

/// Size thresholds
pub const PROPOSAL_THRESHOLD: usize = MAX_GOSSIP_SIZE * 8 / 10; // 80%
pub const SYNC_THRESHOLD: usize = MAX_RESPONSE_SIZE - MAX_GOSSIP_SIZE;

/// Empty state trie hash
pub const EMPTY_ROOT_HASH: B256 =
    b256!("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");

// Jailing considers a window of past views and checks if the selected leader
// missed a number of views configured as threshold.
#[cfg(not(feature = "fake_time"))]
pub const MISSED_VIEW_WINDOW: u64 = 600;
#[cfg(feature = "fake_time")]
pub const MISSED_VIEW_WINDOW: u64 = 60;
pub const MISSED_VIEW_THRESHOLD: usize = 3;

// The window of past views taken into account for jailing is defined by
// the lag behind the current view. It must be large enough to make sure
// the views are already finalized. It also determines the lookahead for
// leader selection.
#[cfg(not(feature = "fake_time"))]
pub const LAG_BEHIND_CURRENT_VIEW: u64 = 50;
#[cfg(feature = "fake_time")]
pub const LAG_BEHIND_CURRENT_VIEW: u64 = 10;
