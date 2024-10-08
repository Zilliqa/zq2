// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import {Ownable, Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Registry} from "contracts/core/Registry.sol";

interface IRelayerEvents {
    event Relayed(
        uint indexed targetChainId,
        address target,
        bytes call,
        uint gasLimit,
        uint nonce
    );
}

interface IRelayer is IRelayerEvents {
    function relayWithMetadata(
        uint targetChainId,
        address target,
        bytes4 callSelector,
        bytes calldata callData,
        uint gasLimit
    ) external returns (uint);

    function relay(
        uint targetChainId,
        address target,
        bytes calldata call,
        uint gasLimit
    ) external returns (uint);
}

struct CallMetadata {
    uint sourceChainId;
    address sender;
}

contract Relayer is Ownable2Step, Registry, IRelayer {
    uint public nonce;

    constructor(address owner_) Ownable(owner_) {}

    // Use this function to relay a call with metadata. This is useful for calling surrogate contracts.
    // Ensure the surrogate implements this interface
    function relayWithMetadata(
        uint targetChainId,
        address target,
        bytes4 callSelector,
        bytes calldata callData,
        uint gasLimit
    ) external isRegistered(msg.sender) returns (uint) {
        emit Relayed(
            targetChainId,
            target,
            abi.encodeWithSelector(
                callSelector,
                CallMetadata(block.chainid, msg.sender),
                callData
            ),
            gasLimit,
            nonce
        );

        return nonce++;
    }

    function relay(
        uint targetChainId,
        address target,
        bytes calldata call,
        uint gasLimit
    ) external isRegistered(msg.sender) returns (uint) {
        emit Relayed(targetChainId, target, call, gasLimit, nonce);

        return nonce++;
    }

    function register(address newTarget) external override onlyOwner {
        _register(newTarget);
    }

    function unregister(address removeTarget) external override onlyOwner {
        _unregister(removeTarget);
    }
}
