// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.4;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract NativeToken is ERC20, Ownable {
    constructor() ERC20("Zilliqa Native Token", "ZIL") {}

    function mint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }

    function setBalance(address account, uint256 amount) public onlyOwner {
        uint256 balance = balanceOf(account);
        if (amount > balance) {
            _mint(account, amount - balance);
        } else if (amount < balance) {
            _burn(account, balance - amount);
        } else {
            // Do nothing
        }
    }
}
