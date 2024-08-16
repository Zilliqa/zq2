// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ValidatorManager} from "contracts/core/ValidatorManager.sol";
import {DispatchReplayChecker} from "contracts/core/DispatchReplayChecker.sol";

interface IChainDispatcherEvents {
    event Dispatched(
        uint indexed sourceChainId,
        address indexed target,
        bool success,
        bytes response,
        uint indexed nonce
    );
}

interface IChainDispatcherErrors {
    error NonContractCaller();
    error NotValidator();
}

interface IChainDispatcher is IChainDispatcherEvents, IChainDispatcherErrors {}

// Cross-chain only
contract ChainDispatcherWithoutFees is IChainDispatcher, DispatchReplayChecker {
    using MessageHashUtils for bytes;

    ValidatorManager public validatorManager;

    modifier onlyContract(address c) {
        if (c.code.length == 0) {
            revert NonContractCaller();
        }
        _;
    }

    constructor(address _validatorManager) {
        validatorManager = ValidatorManager(_validatorManager);
    }

    function dispatch(
        uint sourceChainId,
        address target,
        bytes calldata call,
        uint gasLimit,
        uint nonce,
        bytes[] calldata signatures
    ) external onlyContract(target) replayDispatchGuard(sourceChainId, nonce) {
        validatorManager.validateMessageWithSupermajority(
            abi
                .encode(
                    sourceChainId,
                    block.chainid,
                    target,
                    call,
                    gasLimit,
                    nonce
                )
                .toEthSignedMessageHash(),
            signatures
        );

        (bool success, bytes memory response) = (target).call{gas: gasLimit}(
            call
        );

        emit Dispatched(sourceChainId, target, success, response, nonce);
    }
}
