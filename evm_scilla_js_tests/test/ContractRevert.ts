import {expect} from "chai";
import hre from "hardhat";
import {Contract} from "ethers";
import {SignerWithAddress} from "@nomiclabs/hardhat-ethers/signers";

// FIXME: Can't be parallelized yet. Needs ZIL-5055
describe("Revert Contract Call", function () {
  let contract: Contract;
  let signer: SignerWithAddress;

  before(async function () {
    contract = await hre.deployContract("Revert");
    signer = contract.signer as SignerWithAddress;
  });

  it("Will revert the transaction when revert is called", async function () {
    try {
      await contract.revertCall({value: 1000});
    } catch (error: any) {
      expect(error.error.reason).eq("execution reverted");
    }
  });

  it("Should revert transaction with a custom message if the called function reverts with custom message", async function () {
    const REVERT_MESSAGE = "reverted!!";
    try {
      await contract.revertCallWithMessage(REVERT_MESSAGE, {value: 1000});
    } catch (error: any) {
      expect(error.error.reason).eq(`execution reverted: ${REVERT_MESSAGE}`);
    }
  });

  it("Should revert with an error object if the called function reverts with custom error", async function () {
    const owner = signer;
    try {
      await contract.revertCallWithCustomError({value: 1024});
    } catch (error: any) {
      const data = error.error.error.error.data;
      const iface = (await hre.ethers.getContractFactory("Revert")).interface;
      const decodedError = iface.parseError(data);
      const {value, sender} = decodedError.args;

      expect(decodedError.name).to.eq("FakeError");
      expect(value).eq(1024);
      expect(sender).eq(owner.address);
    }
  });

  it("Should not be reverted despite its child possibly reverting", async function () {
    await expect((await contract.callChainReverted()).wait()).not.to.be.reverted;
    await expect((await contract.callChainOk()).wait()).not.to.be.reverted;
  });

  it("Should be reverted without any reason if specified gasLimit is not enough to complete txn", async function () {
    const txn = await contract.outOfGas({gasLimit: 100000});
    expect(txn).not.to.be.reverted;
    await expect(txn.wait()).eventually.to.be.rejected;
  });
});
