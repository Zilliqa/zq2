import {ScillaContract} from "hardhat-scilla-plugin";
import {expect} from "chai";
import hre, {ethers} from "hardhat";
import {parallelizer} from "../../helpers";
import {BN, units, Zilliqa} from "@zilliqa-js/zilliqa";

describe("Move Zil #parallel", function () {
  const ZIL_AMOUNT = units.toQa(0.1, units.Units.Zil);
  let contract: ScillaContract;
  let contract2: ScillaContract;
  let contract3: ScillaContract;
  let zilliqa: Zilliqa;

  before(async function () {
    if (!hre.isZilliqaNetworkSelected() || !hre.isScillaTestingEnabled()) {
      this.skip();
    }

    zilliqa = new Zilliqa(hre.getNetworkUrl());

    if (hre.parallel) {
      [contract, contract2, contract3] = await Promise.all([
        hre.deployScillaContract2("SendZil"),
        hre.deployScillaContract2("SendZil"),
        hre.deployScillaContract2("SendZil")
      ]);
    } else {
      contract = await parallelizer.deployScillaContract("SendZil");
      contract2 = await parallelizer.deployScillaContract("SendZil");
      contract3 = await parallelizer.deployScillaContract("SendZil");
    }
  });

  it("Should be deployed successfully @block-1", async function () {
    expect(contract.address).to.be.properAddress;
    expect(contract2.address).to.be.properAddress;
    expect(contract3.address).to.be.properAddress;
  });

  it("Should have updated balance if accept is called @block-1", async function () {
    const tx = await contract.acceptZil({amount: new BN(ZIL_AMOUNT)});
    expect(tx).to.have.eventLogWithParams("currentBalance", {value: new BN(ZIL_AMOUNT).toString()});
  });

  it("Should have untouched balance if accept is NOT called", async function () {
    const tx = await contract.dontAcceptZil({amount: ZIL_AMOUNT});

    // Exactly equal to what is has from previous transition
    expect(tx).to.have.eventLogWithParams("currentBalance", {value: new BN(ZIL_AMOUNT).toString()});
  });

  it("Should be possible to fund a user", async function () {
    const account = ethers.Wallet.createRandom();
    await contract.fundUser(account.address, ZIL_AMOUNT);

    const balanceResponse = await zilliqa.blockchain.getBalance(account.address);
    const balance = Number.parseInt(balanceResponse.result.balance);
    expect(balance).to.be.eq(ZIL_AMOUNT);
  });

  it("Should be possible to fund a user with an AddFunds message", async function () {
    const account = ethers.Wallet.createRandom();
    const result = await contract.fundUserWithTag(account.address, ZIL_AMOUNT);
    const balanceResponse = await zilliqa.blockchain.getBalance(account.address);
    const balance = Number.parseInt(balanceResponse.result.balance);
    expect(balance).to.be.eq(ZIL_AMOUNT);
  });

  it("Should be possible to fund a contract", async function () {
    await contract.fundContracts(contract2.address, 1_000_000, contract3.address, 233_000_000);

    let balanceResponse = await zilliqa.blockchain.getBalance(contract2.address!);
    let balance = Number.parseInt(balanceResponse.result.balance);
    expect(balance).to.be.eq(1_000_000);

    balanceResponse = await zilliqa.blockchain.getBalance(contract3.address!);
    balance = Number.parseInt(balanceResponse.result.balance);
    expect(balance).to.be.eq(233_000_000);

    balanceResponse = await zilliqa.blockchain.getBalance(contract.address!);
    const newBalance = new BN(balanceResponse.result.balance);
    expect(newBalance).to.be.eq(ZIL_AMOUNT.sub(new BN(1_000_000 + 233_000_000)));
  });

  it("Should be possible to call a contract transition through another contract", async function () {
    await contract.callOtherContract(contract2.address, "updateTestField", 1234);

    expect(await contract2.test_field()).to.be.eq(1234);
  });

  it("Shouldn't fund the recipient contract if the calling transition doesn't exist", async function () {
    let balanceResponse = await zilliqa.blockchain.getBalance(contract2.address!);
    const oldBalance = new BN(balanceResponse.result.balance);

    await contract.callOtherContractWithAmount(contract2.address, "non_existent", 1_000_000);

    balanceResponse = await zilliqa.blockchain.getBalance(contract2.address!);
    const newBalance = new BN(balanceResponse.result.balance);

    expect(oldBalance).to.be.eq(newBalance);
  });
});
