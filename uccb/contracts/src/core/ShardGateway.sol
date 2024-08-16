// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import {Relayer} from "contracts/core/Relayer.sol";
import {ShardDispatcher} from "contracts/core/ShardDispatcher.sol";

contract ShardGateway is Relayer, ShardDispatcher {
    constructor() Relayer(msg.sender) {}
}
