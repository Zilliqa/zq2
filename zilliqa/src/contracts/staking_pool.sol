// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import "./deposit.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract StakingPool is ERC20 {
    Deposit private _deposit;
    bytes private _blsPubKey;
    bytes private _peerId;
    bytes private _signature;

    constructor(
        Deposit deposit_,
        string memory name,
        string memory symbol,
        bytes memory blsPubKey_,
        bytes memory peerId_,
        bytes memory signature_
    ) ERC20(name, symbol) {
        _deposit = deposit_;
        _blsPubKey = blsPubKey_;
        _peerId = peerId_;
        _signature = signature_;
    }

    function stake() public payable {
        _mint(msg.sender, msg.value);

        uint256 currentStake = _deposit.getStake(_blsPubKey);
        uint256 currentBalance = address(this).balance;
        if (currentBalance > 0 && (currentStake + currentBalance) >= _deposit._minimumStake()) {
            _deposit.deposit{value: currentBalance}(_blsPubKey, _peerId, _signature, address(this));
        }
    }

    function withdraw(uint256 amount) public {
        _burn(msg.sender, amount);
    }
}
