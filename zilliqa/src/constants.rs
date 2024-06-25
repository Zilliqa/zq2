// How many data slots a transaction can use
pub const EVM_TX_SLOT_IN_BYTES: usize = 32 * 1024;

// Maximum size of a transaction (4 slots)
pub const EVM_MAX_TX_INPUT_SIZE: usize = 4 * EVM_TX_SLOT_IN_BYTES; // 128KB

// Maximum bytecode size to permit for a contract
pub const EVM_MAX_CODE_SIZE: usize = 24576;

// Maximum init code to permit in create operations.
pub const EVM_MAX_INIT_CODE_SIZE: usize = 2 * EVM_MAX_CODE_SIZE;

// There was no limit on txn input size in ZQ1 (however the payload was limited on the network level by 5 MB)
pub const ZIL_MAX_TX_INPUT_SIZE: usize = 5 * 1024 * 1024;
