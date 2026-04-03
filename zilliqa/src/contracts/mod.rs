use alloy::hex;
pub use deposit_v8 as deposit;
use serde_json::Value;

pub mod deposit_init {
    use ethabi::{Constructor, Function};
    use once_cell::sync::Lazy;

    use super::{Contract, contract};

    static CONTRACT: Lazy<Contract> =
        Lazy::new(|| contract("src/contracts/deposit_v1.sol", "DepositInit"));
    pub static CONSTRUCTOR: Lazy<Constructor> =
        Lazy::new(|| CONTRACT.abi.constructor().unwrap().clone());
    pub static INITIALIZE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("initialize").unwrap().clone());
    pub static UPGRADE_TO_AND_CALL: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("upgradeToAndCall").unwrap().clone());
    pub static VERSION: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("version").unwrap().clone());
    pub static GET_STAKERS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getStakers").unwrap().clone());
    pub static BYTECODE: Lazy<Vec<u8>> = Lazy::new(|| CONTRACT.bytecode.clone());
}

pub mod deposit_v2 {
    use ethabi::{Constructor, Function};
    use once_cell::sync::Lazy;

    use super::{Contract, contract};

    pub static CONTRACT: Lazy<Contract> =
        Lazy::new(|| contract("src/contracts/deposit_v2.sol", "Deposit"));
    pub static CONSTRUCTOR: Lazy<Constructor> =
        Lazy::new(|| CONTRACT.abi.constructor().unwrap().clone());
    pub static REINITIALIZE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("reinitialize").unwrap().clone());
    pub static UPGRADE_TO_AND_CALL: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("upgradeToAndCall").unwrap().clone());
    pub static VERSION: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("version").unwrap().clone());

    pub static BYTECODE: Lazy<Vec<u8>> = Lazy::new(|| CONTRACT.bytecode.clone());
    pub static LEADER_AT_VIEW: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("leaderAtView").unwrap().clone());
    pub static DEPOSIT: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("deposit").unwrap().clone());
    pub static DEPOSIT_TOPUP: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("depositTopup").unwrap().clone());
    pub static UNSTAKE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("unstake").unwrap().clone());
    pub static CURRENT_EPOCH: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("currentEpoch").unwrap().clone());
    pub static GET_STAKE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getStake").unwrap().clone());
    pub static GET_REWARD_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getRewardAddress").unwrap().clone());
    pub static GET_PEER_ID: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getPeerId").unwrap().clone());
    pub static GET_STAKERS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getStakers").unwrap().clone());
    pub static GET_TOTAL_STAKE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getTotalStake").unwrap().clone());
    pub static COMMITTEE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("committee").unwrap().clone());
    pub static MIN_DEPOSIT: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("minimumStake").unwrap().clone());
    pub static MAX_STAKERS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("maximumStakers").unwrap().clone());
    pub static BLOCKS_PER_EPOCH: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("blocksPerEpoch").unwrap().clone());
}

pub mod deposit_v3 {
    use ethabi::{Constructor, Function};
    use once_cell::sync::Lazy;

    use super::{Contract, contract};

    pub static CONTRACT: Lazy<Contract> =
        Lazy::new(|| contract("src/contracts/deposit_v3.sol", "Deposit"));
    pub static CONSTRUCTOR: Lazy<Constructor> =
        Lazy::new(|| CONTRACT.abi.constructor().unwrap().clone());
    pub static REINITIALIZE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("reinitialize").unwrap().clone());
    pub static UPGRADE_TO_AND_CALL: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("upgradeToAndCall").unwrap().clone());
    pub static VERSION: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("version").unwrap().clone());

    pub static BYTECODE: Lazy<Vec<u8>> = Lazy::new(|| CONTRACT.bytecode.clone());
    pub static LEADER_AT_VIEW: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("leaderAtView").unwrap().clone());
    pub static DEPOSIT: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("deposit").unwrap().clone());
    pub static DEPOSIT_TOPUP: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("depositTopup").unwrap().clone());
    pub static UNSTAKE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("unstake").unwrap().clone());
    pub static CURRENT_EPOCH: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("currentEpoch").unwrap().clone());
    pub static GET_STAKE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getStake").unwrap().clone());
    pub static GET_REWARD_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getRewardAddress").unwrap().clone());
    pub static GET_SIGNING_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getSigningAddress").unwrap().clone());
    pub static GET_CONTROL_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getControlAddress").unwrap().clone());
    pub static SET_SIGNING_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("setSigningAddress").unwrap().clone());
    pub static SET_CONTROL_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("setControlAddress").unwrap().clone());
    pub static GET_PEER_ID: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getPeerId").unwrap().clone());
    pub static GET_STAKERS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getStakers").unwrap().clone());
    pub static GET_TOTAL_STAKE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getTotalStake").unwrap().clone());
    pub static COMMITTEE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("committee").unwrap().clone());
    pub static MIN_DEPOSIT: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("minimumStake").unwrap().clone());
    pub static MAX_STAKERS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("maximumStakers").unwrap().clone());
    pub static BLOCKS_PER_EPOCH: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("blocksPerEpoch").unwrap().clone());
}

pub mod deposit_v4 {
    use ethabi::{Constructor, Function};
    use once_cell::sync::Lazy;

    use super::{Contract, contract};

    pub static CONTRACT: Lazy<Contract> =
        Lazy::new(|| contract("src/contracts/deposit_v4.sol", "Deposit"));
    pub static CONSTRUCTOR: Lazy<Constructor> =
        Lazy::new(|| CONTRACT.abi.constructor().unwrap().clone());
    pub static REINITIALIZE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("reinitialize").unwrap().clone());
    pub static UPGRADE_TO_AND_CALL: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("upgradeToAndCall").unwrap().clone());
    pub static VERSION: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("version").unwrap().clone());

    pub static BYTECODE: Lazy<Vec<u8>> = Lazy::new(|| CONTRACT.bytecode.clone());
    pub static LEADER_AT_VIEW: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("leaderAtView").unwrap().clone());
    pub static DEPOSIT: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("deposit").unwrap().clone());
    pub static DEPOSIT_TOPUP: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("depositTopup").unwrap().clone());
    pub static UNSTAKE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("unstake").unwrap().clone());
    pub static WITHDRAW: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("withdraw").unwrap().clone());
    pub static CURRENT_EPOCH: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("currentEpoch").unwrap().clone());
    pub static GET_STAKE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getStake").unwrap().clone());
    pub static GET_REWARD_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getRewardAddress").unwrap().clone());
    pub static GET_SIGNING_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getSigningAddress").unwrap().clone());
    pub static GET_CONTROL_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getControlAddress").unwrap().clone());
    pub static SET_SIGNING_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("setSigningAddress").unwrap().clone());
    pub static SET_CONTROL_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("setControlAddress").unwrap().clone());
    pub static GET_PEER_ID: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getPeerId").unwrap().clone());
    pub static GET_STAKERS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getStakers").unwrap().clone());
    pub static GET_TOTAL_STAKE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getTotalStake").unwrap().clone());
    pub static COMMITTEE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("committee").unwrap().clone());
    pub static MIN_DEPOSIT: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("minimumStake").unwrap().clone());
    pub static MAX_STAKERS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("maximumStakers").unwrap().clone());
    pub static BLOCKS_PER_EPOCH: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("blocksPerEpoch").unwrap().clone());
}

pub mod deposit_v5 {
    use ethabi::{Constructor, Function};
    use once_cell::sync::Lazy;

    use super::{Contract, contract};

    pub static CONTRACT: Lazy<Contract> =
        Lazy::new(|| contract("src/contracts/deposit_v5.sol", "Deposit"));
    pub static CONSTRUCTOR: Lazy<Constructor> =
        Lazy::new(|| CONTRACT.abi.constructor().unwrap().clone());
    pub static REINITIALIZE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("reinitialize").unwrap().clone());
    pub static UPGRADE_TO_AND_CALL: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("upgradeToAndCall").unwrap().clone());
    pub static VERSION: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("version").unwrap().clone());

    pub static BYTECODE: Lazy<Vec<u8>> = Lazy::new(|| CONTRACT.bytecode.clone());
    pub static LEADER_AT_VIEW: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("leaderAtView").unwrap().clone());
    pub static DEPOSIT: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("deposit").unwrap().clone());
    pub static DEPOSIT_TOPUP: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("depositTopup").unwrap().clone());
    pub static UNSTAKE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("unstake").unwrap().clone());
    pub static WITHDRAW: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("withdraw").unwrap().clone());
    pub static CURRENT_EPOCH: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("currentEpoch").unwrap().clone());
    pub static GET_STAKE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getStake").unwrap().clone());
    pub static GET_REWARD_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getRewardAddress").unwrap().clone());
    pub static GET_SIGNING_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getSigningAddress").unwrap().clone());
    pub static GET_CONTROL_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getControlAddress").unwrap().clone());
    pub static SET_SIGNING_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("setSigningAddress").unwrap().clone());
    pub static SET_CONTROL_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("setControlAddress").unwrap().clone());
    pub static GET_PEER_ID: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getPeerId").unwrap().clone());
    pub static GET_STAKERS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getStakers").unwrap().clone());
    pub static GET_TOTAL_STAKE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getTotalStake").unwrap().clone());
    pub static COMMITTEE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("committee").unwrap().clone());
    pub static MIN_DEPOSIT: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("minimumStake").unwrap().clone());
    pub static MAX_STAKERS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("maximumStakers").unwrap().clone());
    pub static BLOCKS_PER_EPOCH: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("blocksPerEpoch").unwrap().clone());
    pub static WITHDRAWAL_PERIOD: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("withdrawalPeriod").unwrap().clone());
}

pub mod deposit_v6 {
    use ethabi::{Constructor, Function};
    use once_cell::sync::Lazy;

    use super::{Contract, contract};

    pub static CONTRACT: Lazy<Contract> =
        Lazy::new(|| contract("src/contracts/deposit_v6.sol", "Deposit"));
    pub static CONSTRUCTOR: Lazy<Constructor> =
        Lazy::new(|| CONTRACT.abi.constructor().unwrap().clone());
    pub static REINITIALIZE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("reinitialize").unwrap().clone());
    pub static UPGRADE_TO_AND_CALL: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("upgradeToAndCall").unwrap().clone());
    pub static VERSION: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("version").unwrap().clone());

    pub static BYTECODE: Lazy<Vec<u8>> = Lazy::new(|| CONTRACT.bytecode.clone());
    pub static LEADER_AT_VIEW: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("leaderAtView").unwrap().clone());
    pub static DEPOSIT: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("deposit").unwrap().clone());
    pub static DEPOSIT_TOPUP: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("depositTopup").unwrap().clone());
    pub static UNSTAKE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("unstake").unwrap().clone());
    pub static WITHDRAW: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("withdraw").unwrap().clone());
    pub static CURRENT_EPOCH: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("currentEpoch").unwrap().clone());
    pub static GET_STAKE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getStake").unwrap().clone());
    pub static GET_REWARD_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getRewardAddress").unwrap().clone());
    pub static GET_SIGNING_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getSigningAddress").unwrap().clone());
    pub static GET_CONTROL_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getControlAddress").unwrap().clone());
    pub static SET_SIGNING_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("setSigningAddress").unwrap().clone());
    pub static SET_CONTROL_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("setControlAddress").unwrap().clone());
    pub static GET_PEER_ID: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getPeerId").unwrap().clone());
    pub static GET_STAKERS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getStakers").unwrap().clone());
    pub static GET_TOTAL_STAKE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getTotalStake").unwrap().clone());
    pub static COMMITTEE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("committee").unwrap().clone());
    pub static MIN_DEPOSIT: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("minimumStake").unwrap().clone());
    pub static MAX_STAKERS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("maximumStakers").unwrap().clone());
    pub static BLOCKS_PER_EPOCH: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("blocksPerEpoch").unwrap().clone());
    pub static WITHDRAWAL_PERIOD: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("withdrawalPeriod").unwrap().clone());
}

pub mod deposit_v7 {
    use ethabi::{Constructor, Function};
    use once_cell::sync::Lazy;

    use super::{Contract, contract};

    pub static CONTRACT: Lazy<Contract> =
        Lazy::new(|| contract("src/contracts/deposit_v7.sol", "Deposit"));
    pub static CONSTRUCTOR: Lazy<Constructor> =
        Lazy::new(|| CONTRACT.abi.constructor().unwrap().clone());
    pub static REINITIALIZE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.functions_by_name("reinitialize").unwrap()[0].clone());
    pub static REINITIALIZE_2: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.functions_by_name("reinitialize").unwrap()[1].clone());
    pub static UPGRADE_TO_AND_CALL: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("upgradeToAndCall").unwrap().clone());
    pub static VERSION: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("version").unwrap().clone());

    pub static BYTECODE: Lazy<Vec<u8>> = Lazy::new(|| CONTRACT.bytecode.clone());
    pub static LEADER_AT_VIEW: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("leaderAtView").unwrap().clone());
    pub static DEPOSIT: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("deposit").unwrap().clone());
    pub static DEPOSIT_TOPUP: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("depositTopup").unwrap().clone());
    pub static UNSTAKE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("unstake").unwrap().clone());
    pub static WITHDRAW: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("withdraw").unwrap().clone());
    pub static CURRENT_EPOCH: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("currentEpoch").unwrap().clone());
    pub static GET_STAKE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getStake").unwrap().clone());
    pub static GET_REWARD_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getRewardAddress").unwrap().clone());
    pub static GET_SIGNING_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getSigningAddress").unwrap().clone());
    pub static GET_CONTROL_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getControlAddress").unwrap().clone());
    pub static SET_SIGNING_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("setSigningAddress").unwrap().clone());
    pub static SET_CONTROL_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("setControlAddress").unwrap().clone());
    pub static GET_PEER_ID: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getPeerId").unwrap().clone());
    pub static GET_STAKERS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getStakers").unwrap().clone());
    pub static GET_TOTAL_STAKE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getTotalStake").unwrap().clone());
    pub static GET_FUTURE_STAKE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getFutureStake").unwrap().clone());
    pub static COMMITTEE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("committee").unwrap().clone());
    pub static MIN_DEPOSIT: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("minimumStake").unwrap().clone());
    pub static MAX_STAKERS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("maximumStakers").unwrap().clone());
    pub static BLOCKS_PER_EPOCH: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("blocksPerEpoch").unwrap().clone());
    pub static WITHDRAWAL_PERIOD: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("withdrawalPeriod").unwrap().clone());
}

pub mod deposit_v8 {
    use ethabi::{Constructor, Function};
    use once_cell::sync::Lazy;

    use super::{Contract, COMPILED_DEPOSIT_V8, contract_from};

    pub static CONTRACT: Lazy<Contract> =
        Lazy::new(|| contract_from(COMPILED_DEPOSIT_V8, "src/contracts/deposit_v8.sol", "Deposit"));
    pub static CONSTRUCTOR: Lazy<Constructor> =
        Lazy::new(|| CONTRACT.abi.constructor().unwrap().clone());
    pub static REINITIALIZE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.functions_by_name("reinitialize").unwrap()[0].clone());
    pub static REINITIALIZE_2: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.functions_by_name("reinitialize").unwrap()[1].clone());
    pub static UPGRADE_TO_AND_CALL: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("upgradeToAndCall").unwrap().clone());
    pub static VERSION: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("version").unwrap().clone());

    pub static BYTECODE: Lazy<Vec<u8>> = Lazy::new(|| CONTRACT.bytecode.clone());
    pub static LEADER_AT_VIEW: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("leaderAtView").unwrap().clone());

    pub static LEADER_AT_VIEW_WITH_RANDAO: Lazy<Function> = Lazy::new(|| {
        CONTRACT
            .abi
            .function("leaderAtViewWithRandao")
            .unwrap()
            .clone()
    });
    pub static DEPOSIT: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("deposit").unwrap().clone());
    pub static DEPOSIT_TOPUP: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("depositTopup").unwrap().clone());
    pub static UNSTAKE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("unstake").unwrap().clone());
    pub static WITHDRAW: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("withdraw").unwrap().clone());
    pub static CURRENT_EPOCH: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("currentEpoch").unwrap().clone());
    pub static GET_STAKE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getStake").unwrap().clone());
    pub static GET_FUTURE_STAKE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getFutureStake").unwrap().clone());
    pub static GET_REWARD_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getRewardAddress").unwrap().clone());
    pub static GET_SIGNING_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getSigningAddress").unwrap().clone());
    pub static GET_CONTROL_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getControlAddress").unwrap().clone());
    pub static SET_SIGNING_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("setSigningAddress").unwrap().clone());
    pub static SET_CONTROL_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("setControlAddress").unwrap().clone());
    pub static GET_PEER_ID: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getPeerId").unwrap().clone());
    pub static GET_STAKERS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getStakers").unwrap().clone());
    pub static GET_TOTAL_STAKE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getTotalStake").unwrap().clone());
    pub static COMMITTEE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("committee").unwrap().clone());
    pub static MIN_DEPOSIT: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("minimumStake").unwrap().clone());
    pub static MAX_STAKERS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("maximumStakers").unwrap().clone());
    pub static BLOCKS_PER_EPOCH: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("blocksPerEpoch").unwrap().clone());
    pub static WITHDRAWAL_PERIOD: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("withdrawalPeriod").unwrap().clone());
}

pub mod shard {
    use ethabi::Constructor;
    use once_cell::sync::Lazy;

    use super::{Contract, contract};

    static CONTRACT: Lazy<Contract> = Lazy::new(|| contract("src/contracts/shard.sol", "Shard"));

    pub static BYTECODE: Lazy<Vec<u8>> = Lazy::new(|| CONTRACT.bytecode.clone());
    pub static CONSTRUCTOR: Lazy<Constructor> =
        Lazy::new(|| CONTRACT.abi.constructor().unwrap().clone());
}

pub mod intershard_bridge {
    use ethabi::{Constructor, Event, Function};
    use once_cell::sync::Lazy;

    use super::{Contract, contract};

    static CONTRACT: Lazy<Contract> =
        Lazy::new(|| contract("src/contracts/intershard_bridge.sol", "IntershardBridge"));

    pub static BYTECODE: Lazy<Vec<u8>> = Lazy::new(|| CONTRACT.bytecode.clone());
    pub static CONSTRUCTOR: Lazy<Constructor> =
        Lazy::new(|| CONTRACT.abi.constructor().unwrap().clone());
    pub static BRIDGE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("bridge").unwrap().clone());
    pub static RELAYED_EVT: Lazy<Event> =
        Lazy::new(|| CONTRACT.abi.event("Relayed").unwrap().clone());
}

pub mod shard_registry {
    use ethabi::{Constructor, Event, Function};
    use once_cell::sync::Lazy;

    use super::{Contract, contract};

    static CONTRACT: Lazy<Contract> =
        Lazy::new(|| contract("src/contracts/shard_registry.sol", "ShardRegistry"));

    pub static BYTECODE: Lazy<Vec<u8>> = Lazy::new(|| CONTRACT.bytecode.clone());
    pub static CONSTRUCTOR: Lazy<Constructor> =
        Lazy::new(|| CONTRACT.abi.constructor().unwrap().clone());

    pub static ADD_SHARD: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("addShard").unwrap().clone());
    pub static SHARD_ADDED_EVT: Lazy<Event> =
        Lazy::new(|| CONTRACT.abi.event("ShardAdded").unwrap().clone());

    pub static ADD_LINK: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("addLink").unwrap().clone());
    pub static LINK_ADDED_EVT: Lazy<Event> =
        Lazy::new(|| CONTRACT.abi.event("LinkAdded").unwrap().clone());
}

pub mod eip1967_proxy {
    use ethabi::{Constructor, Event};
    use once_cell::sync::Lazy;

    use super::{Contract, contract};

    static CONTRACT: Lazy<Contract> = Lazy::new(|| {
        contract(
            "../vendor/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol",
            "ERC1967Proxy",
        )
    });

    pub static BYTECODE: Lazy<Vec<u8>> = Lazy::new(|| CONTRACT.bytecode.clone());
    pub static CONSTRUCTOR: Lazy<Constructor> =
        Lazy::new(|| CONTRACT.abi.constructor().unwrap().clone());

    pub static UPGRADED_EVT: Lazy<Event> =
        Lazy::new(|| CONTRACT.abi.event("Upgraded").unwrap().clone());
}

const COMPILED: &str = include_str!("compiled_legacy.json");
const COMPILED_DEPOSIT_V8: &str = include_str!("compiled_deposit_v8.json");

fn contract(src: &str, name: &str) -> Contract {
    contract_from(COMPILED, src, name)
}

fn contract_from(compiled_json: &str, src: &str, name: &str) -> Contract {
    let compiled = serde_json::from_str::<Value>(compiled_json).unwrap();
    let contract = &compiled["contracts"][src][name];
    let abi = serde_json::from_value(contract["abi"].clone()).unwrap();
    let bytecode = hex::decode(contract["evm"]["bytecode"]["object"].as_str().unwrap()).unwrap();

    Contract { abi, bytecode }
}

pub struct Contract {
    pub abi: ethabi::Contract,
    pub bytecode: Vec<u8>,
}

/// These tests assert the contract binaries in this module are correct and reproducible, by recompiling the source
/// files and checking the result is the same. This means we can keep the compiled source code in-tree, while also
/// asserting in CI that the compiled source code is genuine.
///
/// Each contract group has its own compiled JSON file and test. Tests only run when:
/// 1. The `test_contract_bytecode` feature is enabled, AND
/// 2. The `ZQ_COMPILE_CONTRACTS` env var includes the contract group name (comma-separated) or `all`.
///
/// By default, no contracts are recompiled. Set `ZQ_CONTRACT_TEST_BLESS=1` to write/update the compiled JSON files.
#[cfg(test)]
mod tests {
    use std::{fs::File, path::PathBuf};

    use foundry_compilers::{
        artifacts::{
            EvmVersion, Optimizer, Remapping, Settings, SolcInput, Source,
            output_selection::OutputSelection,
        },
        solc::SolcLanguage,
    };

    fn should_compile(group: &str) -> bool {
        std::env::var("ZQ_COMPILE_CONTRACTS")
            .map(|v| {
                v.split(',')
                    .any(|s| s.trim() == group || s.trim() == "all")
            })
            .unwrap_or(false)
    }

    fn solc_settings() -> Settings {
        Settings {
            remappings: vec![
                Remapping {
                    context: None,
                    name: "@openzeppelin/contracts-upgradeable".to_owned(),
                    path: "../vendor/openzeppelin-contracts-upgradeable/contracts".to_owned(),
                },
                Remapping {
                    context: None,
                    name: "@openzeppelin/contracts".to_owned(),
                    path: "../vendor/openzeppelin-contracts/contracts".to_owned(),
                },
            ],
            optimizer: Optimizer {
                enabled: Some(true),
                runs: Some(4294967295),
                details: None,
            },
            output_selection: OutputSelection::complete_output_selection(),
            evm_version: Some(EvmVersion::Shanghai),
            ..Default::default()
        }
    }

    fn compile_and_check(sources: &[&str], output_filename: &str) {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let input = SolcInput {
            language: SolcLanguage::Solidity,
            sources: Source::read_all(sources.iter().copied()).unwrap(),
            settings: solc_settings(),
        };

        let mut solc =
            foundry_compilers::solc::Solc::find_or_install(&semver::Version::new(0, 8, 28))
                .unwrap();
        solc.allow_paths.insert(PathBuf::from(
            "../vendor/openzeppelin-contracts-upgradeable",
        ));
        solc.allow_paths
            .insert(PathBuf::from("../vendor/openzeppelin-contracts"));

        let output = solc.compile_exact(&input).unwrap();
        if output.has_error() {
            for error in output.errors {
                eprintln!("{error}");
            }
            panic!("compilation failed");
        }
        let output_file = root.join("src").join("contracts").join(output_filename);

        if std::env::var_os("ZQ_CONTRACT_TEST_BLESS").is_some() {
            let file = File::create(output_file).unwrap();
            serde_json::to_writer_pretty(file, &output).unwrap();

            println!("`{output_filename}` updated, please commit these changes");
        } else {
            let file = File::open(output_file).unwrap();
            let current_output = serde_json::from_reader(file).unwrap();

            assert_eq!(output, current_output);
        }
    }

    /// Legacy contracts (deposit_v1 through v7, shard, intershard_bridge, shard_registry, ERC1967Proxy).
    ///
    /// **Do not run this test.** It exists only for historical compatibility. The legacy contracts in
    /// `compiled_legacy.json` were originally compiled with `foundry-compilers = 0.14.1` and recompiling with
    /// the current crate version will produce different bytecode.
    #[test]
    #[cfg_attr(not(feature = "test_contract_bytecode"), ignore)]
    fn compile_legacy() {
        if !should_compile("legacy") {
            eprintln!("Skipping legacy compilation (set ZQ_COMPILE_CONTRACTS=legacy or ZQ_COMPILE_CONTRACTS=all)");
            return;
        }

        compile_and_check(
            &[
                "src/contracts/deposit_v1.sol",
                "src/contracts/deposit_v2.sol",
                "src/contracts/deposit_v3.sol",
                "src/contracts/deposit_v4.sol",
                "src/contracts/deposit_v5.sol",
                "src/contracts/deposit_v6.sol",
                "src/contracts/deposit_v7.sol",
                "src/contracts/utils/deque.sol",
                "src/contracts/intershard_bridge.sol",
                "src/contracts/shard.sol",
                "src/contracts/shard_registry.sol",
                "../vendor/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol",
            ],
            "compiled_legacy.json",
        );
    }

    /// Compiles deposit_v8 into compiled_deposit_v8.json. Run with:
    /// ```sh
    /// ZQ_COMPILE_CONTRACTS=deposit_v8 ZQ_CONTRACT_TEST_BLESS=1 cargo test --features test_contract_bytecode -- contracts::tests::compile_deposit_v8
    /// ```
    #[test]
    #[cfg_attr(not(feature = "test_contract_bytecode"), ignore)]
    fn compile_deposit_v8() {
        if !should_compile("deposit_v8") {
            eprintln!("Skipping deposit_v8 compilation (set ZQ_COMPILE_CONTRACTS=deposit_v8 or ZQ_COMPILE_CONTRACTS=all)");
            return;
        }

        compile_and_check(
            &[
                "src/contracts/deposit_v8.sol",
                "src/contracts/utils/deque_v2.sol",
            ],
            "compiled_deposit_v8.json",
        );
    }
}
