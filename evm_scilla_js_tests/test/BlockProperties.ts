import {expect} from "chai";
import hre from "hardhat";
import {Contract} from "ethers";
import {ethers} from "hardhat";

const ZERO = "0x0000000000000000000000000000000000000000000000000000000000000000";

describe("Block Properties", function () {
  let contract: Contract;
  let toBeTestedBlockNumber: number;

  before(async function () {
    contract = await hre.deployContract("BlockAndTransactionProperties");
  });

  beforeEach(async function () {
    toBeTestedBlockNumber = await ethers.provider.getBlockNumber();
  });

  it("Should be deployed successfully @block-1", async function () {
    expect(contract.address).to.be.properAddress;
  });

  it("should return the correct block number", async function () {
    const contractBlockNumber = await contract.getBlockNumber({blockTag: toBeTestedBlockNumber});
    expect(contractBlockNumber).to.equal(toBeTestedBlockNumber);
  });

  it("should return the correct block timestamp", async function () {
    const contractBlockTimestamp = await contract.getTimestamp({blockTag: toBeTestedBlockNumber});
    const currentBlock = await ethers.provider.getBlock(toBeTestedBlockNumber);

    expect(contractBlockTimestamp).to.equal(currentBlock.timestamp);
  });

  xit("should return the correct base fee", async function () {
    const contractBaseFee = await contract.getBaseFee({blockTag: toBeTestedBlockNumber});
    const currentBlock = await ethers.provider.getBlock(toBeTestedBlockNumber);

    expect(contractBaseFee).to.equal(currentBlock.baseFeePerGas);
  });

  it("should return the correct chain id", async function () {
    const contractChainId = await contract.getChainId({blockTag: toBeTestedBlockNumber});
    const network = await ethers.provider.getNetwork();

    expect(contractChainId).to.equal(network.chainId);
  });

  // FIXME: Enable and fix this test when https://github.com/Zilliqa/zq2/issues/1340 is done
  xit("should return the correct coinbase", async function () {
    const contractCoinbase = await contract.getCoinbase();

    expect(contractCoinbase).to.equal("0x0000000000000000000000000000000000000000");
  });

  it("should return the correct gas limit", async function () {
    const contractGasLimit = await contract.getGasLimit({blockTag: toBeTestedBlockNumber});
    const currentBlock = await ethers.provider.getBlock(toBeTestedBlockNumber);

    expect(contractGasLimit).to.equal(currentBlock.gasLimit);
  });

  it("should emit blockhash correctly", async function () {
    const tx = await contract.emitBlockHash(toBeTestedBlockNumber);
    const actualBlockHash = (await ethers.provider.getBlock(toBeTestedBlockNumber)).hash;

    await expect(tx).to.emit(contract, "BlockHash").withArgs(actualBlockHash);
  });

  it("should emit zero blockhash for current block that's not finalized yet", async function () {
    const tx = await contract.emitBlockHash(toBeTestedBlockNumber + 2);
    await expect(tx).to.emit(contract, "BlockHash").withArgs(ZERO);
  });

  it("should emit zero blockhash for a block number more than 256 blocks in the past", async function () {
    const blockNumber = await ethers.provider.getBlockNumber();
    if (blockNumber > 256) {
      const tx = await contract.emitBlockHash(blockNumber - 256);
      await expect(tx).to.emit(contract, "BlockHash").withArgs(ZERO);
    } else {
      this.skip(); // Not possible to test if we don't have 256 or more blocks
    }
  });

  it("should emit zero blockhash for a future block number", async function () {
    const tx = await contract.emitBlockHash(toBeTestedBlockNumber + 100);
    await expect(tx).to.emit(contract, "BlockHash").withArgs(ZERO);
  });
});
