// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RevertMe {
    int256 public value = 0;

    function revertable(bool success) public {
        value += 1; // incur some gas cost
        if (!success) {
            revert("Reverting.");
        }
    }
}
