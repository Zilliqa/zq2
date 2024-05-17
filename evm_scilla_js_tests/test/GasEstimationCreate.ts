import hre from "hardhat";
import {expect} from "chai";

describe("Estimation test with Create/Create2", function () {
    before(async function () {
        this.contract = await hre.deployContract("GasTestCreate");
        expect(this.contract.address).to.be.properAddress;
    });

    it("Should return proper address when Create is performed [@transactional]", async function () {
        const estimated = await this.contract.estimateGas.deploy();
        const result = await this.contract.deploy({gasLimit: estimated});
        await result.wait();

        expect(await this.contract.test()).to.be.properAddress;
    });

    it("Should return proper address when Create is performed [@transactional]", async function () {
        const estimated = await this.contract.estimateGas.deploy2(1234);
        const result = await this.contract.deploy2(1234, {gasLimit: estimated});
        await result.wait();

        expect(await this.contract.test()).to.be.properAddress;
    });
});