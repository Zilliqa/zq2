// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity ^0.8.20;

contract CallMe {
    constructor() {}

    function currentBlock() external view returns (uint) {
        return block.number;
    }
}
