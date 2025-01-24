// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.28;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract ERC20FixedSupply is ERC20("token", "TKN") {
    constructor() {
        _mint(msg.sender, 1_000_000_000);
    }
}
