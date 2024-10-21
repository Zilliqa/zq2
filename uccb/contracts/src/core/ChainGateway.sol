// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import {ChainDispatcherWithoutFees} from "contracts/core/ChainDispatcherWithoutFees.sol";
import {Relayer} from "contracts/core/Relayer.sol";

contract ChainGateway is Relayer, ChainDispatcherWithoutFees {
    constructor(
        address _validatorManager,
        address _owner
    ) ChainDispatcherWithoutFees(_validatorManager) Relayer(_owner) {}
}
