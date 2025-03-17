import {ScillaContract} from "hardhat-scilla-plugin";
import {expect} from "chai";
import hre from "hardhat";

describe("Scilla RejectedTransition #parallel", function () {
  let contract: ScillaContract;

  before(async function () {
    contract = await hre.deployScillaContract2("RejectedTransition");
  });

  it("Rejected transition shouldn't change the state of the contract @block-1", async function () {
    expect(contract.address).to.be.properAddress;
    expect(await contract.f_s1()).to.be.eq("421");
    await contract.f1();
    expect(await contract.f_s1()).to.be.eq("421");
  })
});
