import {SignerWithAddress} from "@nomiclabs/hardhat-ethers/signers";
import {expect} from "chai";
import {Contract} from "ethers";
import hre from "hardhat";

describe("While Calling a method on erroneous contract with given gas limit #parallel", function () {
  let contract: Contract;
  before(async function () {
    contract = await hre.deployContract("Erroneous");
  });

  it("it should return to the client and nonce/balance should be affected @block-1", async function () {
    let signer = contract.signer;
    const funds = await signer.getBalance();
    const nonce = await signer.getTransactionCount();
    const tx = await contract.foo({gasLimit: 5000000});
    await expect(tx.wait()).to.be.rejected;
    expect(funds).to.be.greaterThan(await signer.getBalance());
    expect(nonce).to.be.lessThan(await signer.getTransactionCount());
  });
});
