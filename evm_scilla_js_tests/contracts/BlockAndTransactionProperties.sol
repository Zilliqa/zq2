// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract BlockAndTransactionProperties {
  uint public receivedValue;
  event Received(address sender, uint amount, bytes data);
  event GasLeft(uint256 gas);
  event GasPrice(uint256 gasPrice);
  event BlockHash(bytes32 blockHash);

  // Block Properties
  function getBlockHash(uint blockNumber) public view returns (bytes32) {
    return blockhash(blockNumber);
  }

  function getBaseFee() public view returns (uint) {
    return block.basefee;
  }

  function getChainId() public view returns (uint) {
    return block.chainid;
  }

  function getCoinbase() public view returns (address payable) {
    return block.coinbase;
  }

  function getGasLimit() public view returns (uint) {
    return block.gaslimit;
  }

  function getBlockNumber() public view returns (uint) {
    return block.number;
  }

  function getTimestamp() public view returns (uint) {
    return block.timestamp;
  }

  function emitBlockHash(uint256 blockNumber) public {
    emit BlockHash(blockhash(blockNumber));
  }

  // Transaction Properties
  function emitGasLeft() public {
    emit GasLeft(gasleft());
  }

  function getMsgData() public pure returns (bytes calldata) {
    return msg.data;
  }

  function getMsgSender() public view returns (address) {
    return msg.sender;
  }

  function getMsgSig() public pure returns (bytes4) {
    return msg.sig;
  }

  function getMsgValue() public payable {
    receivedValue = msg.value;
  }

  function receiveEther() public payable {
    require(msg.value > 0, "No ether sent");
    emit Received(msg.sender, msg.value, msg.data);
  }

  function emitGasPrice() public {
    emit GasPrice(tx.gasprice);
  }

  function getTxOrigin() public view returns (address) {
    return tx.origin;
  }
}
