import {expect} from "chai";
import hre, {ethers} from "hardhat";
import {web3} from "hardhat";
import {Contract} from "ethers";

describe("ERC20Precompile tests #parallel", function () {
    let contract: Contract;
    before(async function () {
        contract = await hre.deployContract("ERC20Precompile");
    });

    it("should return same balance as get balance api call @block-1", async function () {
        const signers = await ethers.getSigners();
        const signer = signers.pop()!;
        const apiBalance = await signer.getBalance()
        const erc20Balance = await contract.balanceOf(await signer.getAddress());
        expect(apiBalance).to.be.eq(erc20Balance);
    });


});
