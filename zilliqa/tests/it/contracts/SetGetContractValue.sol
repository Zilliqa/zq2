// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SetGetContractValue {
  uint256 private value = 99;

  constructor() {}

  function getUint256() public view returns (uint256) {
    return value;
  }

  function setUint256(uint256 _value) public {
    value = _value;
  }
}
