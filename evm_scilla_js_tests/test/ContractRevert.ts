import {expect} from "chai";
import hre from "hardhat";
import {Contract} from "ethers";
import {SignerWithAddress} from "@nomiclabs/hardhat-ethers/signers";
const {expectRevert} = require("@openzeppelin/test-helpers"); // No declaration files found for oz-helpers

// FIXME: Can't be parallelized yet. Needs ZIL-5055
describe("Revert Contract Call", function () {
  let contract: Contract;
  let signer: SignerWithAddress;

  before(async function () {
    contract = await hre.deployContract("Revert");
    signer = contract.signer as SignerWithAddress;
  });

  it("Should not be reverted despite its child possibly reverting", async function () {
    const owner = contract.signer;
    await expect((await contract.callChainReverted()).wait()).not.to.be.reverted;
    await expect((await contract.callChainOk()).wait()).not.to.be.reverted;
  });

  it("Should be reverted without any reason if specified gasLimit is not enough to complete txn", async function () {
    const txn = await contract.outOfGas({gasLimit: 100000});
    expect(txn).not.to.be.reverted;
    await expect(txn.wait()).eventually.to.be.rejected;
  });
});
