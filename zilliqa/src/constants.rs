use crate::transaction::EvmGas;

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

// Recompute available blocks after this many seconds
pub const RECOMPUTE_BLOCK_AVAILABILITY_AFTER_S: u64 = 2;

// Maximum rate at which to send availability requests
pub const REQUEST_PEER_VIEW_AVAILABILITY_NOT_BEFORE_MS: u64 = 1000;

// We assume that every node has the last ALWAYS_RETAIN_LAST_N_BLOCKS blocks, otherwise
// it's hard ever to catch up. Set this too large and syncing will be hard because we will
// keep asking recently started nodes for blocks they don't have. Set it too small and
// it will be hard because we'll need to keep waiting for availability.
pub const RETAINS_LAST_N_BLOCKS: u64 = 10;

// How long do we wait before retrying a request to a peer?

// WARNING: these must be at least 1000*max_blocks_in_flight.
// All requests get this number of ms.
pub const BLOCK_REQUEST_RESPONSE_TIMEOUT_MIN_MS: u64 = 4000;

// log2 of the number of ways in the block cache. Max 8.
pub const BLOCK_CACHE_LOG2_WAYS: usize = 4;
/// The block cache will deliberately keep this number of entries near the highest known view
/// so that it can catch up quickly when it reaches the current head of the chain.
/// Not required for correctness.
pub const BLOCK_CACHE_TAIL_BUFFER_ENTRIES: usize = 16;

/// Max pending requests per peer
pub const MAX_PENDING_REQUESTS_PER_PEER: usize = 4;

/// Number of previous blocks to examine at each level of fork counter. Should be
/// set small enough to avoid serious database load, but large enough to jump any
/// plausible fork reasonably quickly.
pub const EXAMINE_BLOCKS_PER_FORK_COUNT: usize = 16;
