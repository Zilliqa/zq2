import {ScillaContract} from "hardhat-scilla-plugin";
import {expect} from "chai";
import hre from "hardhat";
import { Account, BN } from "@zilliqa-js/zilliqa";
import { getNonce, getZilBalance } from "../../helpers/SignersHelper";

describe("Scilla RejectedTransition #parallel", function () {
  let contract: ScillaContract;
  let signer: Account;

  before(async function () {
    signer = hre.allocateZilSigner();
    contract = await hre.deployScillaContractWithSigner("RejectedTransition", signer);
  });

  it("should deploy the contract with f_s1 set to '421'", async function () {
    expect(contract.address).to.be.properAddress;
    expect(await contract.f_s1()).to.be.eq("421");
  });

  it("Rejected transition shouldn't change the state of the contract @block-1", async function () {
    const beforeNonce = await getNonce(hre, signer.address);
    const beforeBalance = await getZilBalance(hre, signer.address);
  
    let tx = await contract.f1();
  
    const gasPrice: BN = tx.gasPrice;
    const gasFee = gasPrice.muln(tx.receipt.cumulative_gas)
    const afterNonce = await getNonce(hre, signer.address);
    const afterBalance = await getZilBalance(hre, signer.address);
  
    expect(await contract.f_s1()).to.be.eq("421");
    
    // Even tough the transition is rejected, the nonce should be incremented
    expect(afterNonce).to.be.eq(beforeNonce + 1);

    // Even tough the transition is rejected, the gas fee should be deducted
    expect(beforeBalance).to.be.eq(afterBalance.add(gasFee));
  })
});
