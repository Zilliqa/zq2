// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import {Relayer} from "contracts/core/Relayer.sol";
import {DispatchReplayChecker} from "contracts/core/DispatchReplayChecker.sol";

interface IShardDispatcherErrors {
    error Unauthorized();
}

interface IShardDispatcherEvents {
    event Dispatched(uint indexed sourceShardId, uint indexed nonce);
}

contract ShardDispatcher is IShardDispatcherEvents, DispatchReplayChecker {
    modifier onlySelf() {
        if (msg.sender != address(this)) {
            revert IShardDispatcherErrors.Unauthorized();
        }
        _;
    }

    function replayDispatchCheck(
        uint sourceShardId,
        uint nonce
    ) external onlySelf {
        _replayDispatchCheck(sourceShardId, nonce);
        emit Dispatched(sourceShardId, nonce);
    }
}
