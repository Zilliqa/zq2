import {expect} from "chai";
import hre from "hardhat";
import {Contract} from "ethers";
import {ethers} from "hardhat";

// TODO: Change the description to something more meaningful.
describe("Blockchain Instructions contract #parallel", function () {
  let contract: Contract;
  before(async function () {
    contract = await hre.deployContract("BlockchainInstructions");
  });

  it("Should be deployed successfully @block-1", async function () {
    expect(contract.address).to.be.properAddress;
  });

  it("Should return the owner address when getOrigin function is called @block-1", async function () {
    const owner = contract.signer;
    expect(await contract.getOrigin()).to.be.eq(await owner.getAddress());
  });

  it("should return the correct block number", async function () {
    const contractBlockNumber = await contract.getCurrentBlockNumber();
    const currentBlockNumber = await ethers.provider.getBlockNumber();

    expect(contractBlockNumber).to.equal(currentBlockNumber);
  });

  it("should return the correct block timestamp", async function () {
    const contractBlockTimestamp = await contract.getCurrentBlockTimestamp();
    const currentBlock = await ethers.provider.getBlock("latest");

    expect(contractBlockTimestamp).to.equal(currentBlock.timestamp);
  });
});
