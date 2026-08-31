// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Minimal token for general-escrow tests: only `escrow` may mint.
contract EscrowMintableToken {
    address public immutable escrow;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(address escrow_) {
        escrow = escrow_;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == escrow, "only escrow");
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }
}
