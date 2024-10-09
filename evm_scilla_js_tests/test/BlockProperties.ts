import {expect} from "chai";
import hre from "hardhat";
import {Contract} from "ethers";
import {ethers} from "hardhat";

const ZERO = "0x0000000000000000000000000000000000000000000000000000000000000000";

describe("Block Properties", function () {
  let contract: Contract;
  before(async function () {
    contract = await hre.deployContract("BlockAndTransactionProperties");
  });

  it("Should be deployed successfully @block-1", async function () {
    expect(contract.address).to.be.properAddress;
  });

  it("should return the correct block number", async function () {
    const contractBlockNumber = await contract.getBlockNumber();
    const currentBlockNumber = await ethers.provider.getBlockNumber();

    expect(contractBlockNumber).to.equal(currentBlockNumber);
  });

  it("should return the correct block timestamp", async function () {
    const contractBlockTimestamp = await contract.getTimestamp();
    const currentBlock = await ethers.provider.getBlock("latest");

    expect(contractBlockTimestamp).to.equal(currentBlock.timestamp);
  });

  it("should return the correct base fee", async function () {
    const contractBaseFee = await contract.getBaseFee();

    expect(contractBaseFee).to.equal(await hre.ethers.provider.getGasPrice());
  });

  it("should return the correct chain id", async function () {
    const contractChainId = await contract.getChainId();
    const network = await ethers.provider.getNetwork();

    expect(contractChainId).to.equal(network.chainId);
  });

  // FIXME: Enable and fix this test when https://github.com/Zilliqa/zq2/issues/1340 is done
  xit("should return the correct coinbase", async function () {
    const contractCoinbase = await contract.getCoinbase();

    expect(contractCoinbase).to.equal("0x0000000000000000000000000000000000000000");
  });

  it("should return the correct gas limit", async function () {
    const contractGasLimit = await contract.getGasLimit();
    const currentBlock = await ethers.provider.getBlock("latest");

    expect(contractGasLimit).to.equal(currentBlock.gasLimit);
  });

  it("should emit blockhash correctly", async function () {
    const currentBlockNumber = await ethers.provider.getBlockNumber();

    // Call emitBlockHash with the current block number
    const tx = await contract.emitBlockHash(currentBlockNumber);
    const actualBlockHash = (await ethers.provider.getBlock(currentBlockNumber)).hash;

    await expect(tx).to.emit(contract, "BlockHash").withArgs(actualBlockHash);
  });

  it("should emit zero blockhash for current block that's not finalized yet", async function () {
    const currentBlockNumber = await ethers.provider.getBlockNumber();
    const tx = await contract.emitBlockHash(currentBlockNumber + 1);
    await expect(tx).to.emit(contract, "BlockHash").withArgs(ZERO);
  });

  it("should emit zero blockhash for a block number more than 256 blocks in the past", async function () {
    const currentBlockNumber = await ethers.provider.getBlockNumber();

    if (currentBlockNumber > 256) {
      const tx = await contract.emitBlockHash(currentBlockNumber - 256);
      await expect(tx).to.emit(contract, "BlockHash").withArgs(ZERO);
    } else {
      this.skip(); // Not possible to test if we don't have 256 or more blocks
    }
  });

  it("should emit zero blockhash for a future block number", async function () {
    const currentBlockNumber = await ethers.provider.getBlockNumber();
    const tx = await contract.emitBlockHash(currentBlockNumber + 100);
    await expect(tx).to.emit(contract, "BlockHash").withArgs(ZERO);
  });
});
