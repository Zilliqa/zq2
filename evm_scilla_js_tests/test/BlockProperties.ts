import {expect} from "chai";
import hre from "hardhat";
import {Contract} from "ethers";
import {ethers} from "hardhat";

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

  xit("should return the correct block hash", async function () {
    const currentBlockNumber = await ethers.provider.getBlockNumber();
    const contractBlockHash = await contract.getBlockHash(currentBlockNumber);
    const currentBlock = await ethers.provider.getBlock(currentBlockNumber);

    expect(contractBlockHash).to.equal(currentBlock.hash);
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

  it("should return the correct coinbase", async function () {
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
});
