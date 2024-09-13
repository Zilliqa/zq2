const {validation} = require("@zilliqa-js/util");
const {assert, expect} = require("chai");
import {ScillaContract} from "hardhat-scilla-plugin";
import {parallelizer} from "../../helpers";
import hre from "hardhat";

describe("Scilla library deploy", () => {
  let additionLibAddress: string;
  let mutualLibAddress: string;
  let contract1: ScillaContract;
  let contract2: ScillaContract;

  before(async function () {
    if (!hre.isZilliqaNetworkSelected() || !hre.isScillaTestingEnabled()) {
      this.skip();
    }

    let library = await parallelizer.deployScillaLibrary("AdditionLib");
    if (library.address === undefined) {
      throw new Error("Failed to deploy the `AdditionLib` library");
    }
    additionLibAddress = library.address;

    library = await parallelizer.deployScillaLibrary("MutualLib");
    if (library.address === undefined) {
      throw new Error("Failed to deploy the `MutualLib` library");
    }
    mutualLibAddress = library.address;
  });

  it("Should deploy libraries successfully", async () => {
    expect(additionLibAddress).to.be.properAddress;
    expect(additionLibAddress).to.be.properAddress;
  });

  it("Should be possible to deploy TestContract1 which imports AdditonLib and MutualLib", async () => {
    console.log(`${additionLibAddress} ${mutualLibAddress}`);
    contract1 = await parallelizer.deployScillaContractWithLibrary("TestContract1", [
      {name: "AdditionLib.scillib", address: additionLibAddress!.toLocaleLowerCase()},
      {name: "MutualLib.scillib", address: mutualLibAddress!.toLocaleLowerCase()}
    ]);

    expect(contract1.address).to.be.properAddress;
    expect(validation.isAddress(contract1.address)).to.be.true;
  });

  it("Should be possible to deploy TestContract2 which imports MutualLib", async () => {
    contract2 = await parallelizer.deployScillaContractWithLibrary("TestContract2", [
      {name: "MutualLib.scillib", address: mutualLibAddress!}
    ]);

    expect(contract2.address).to.be.properAddress;
    expect(validation.isAddress(contract2.address)).to.be.true;
  });

  it("Should be possible to call TestContract1 transition", async () => {
    const tx = await contract1.Sending(contract2.address);
    expect(tx.receipt.success).equal(true);
    expect(tx).to.have.eventLog("Bool const of T2 type");
  });
});
