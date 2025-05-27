import {assert} from "chai";
import hre, {ethers} from "hardhat";
import sendJsonRpcRequest from "../../helpers/JsonRpcHelper";
import logDebug from "../../helpers/DebugHelper";

const METHOD = "eth_sendRawTransaction";

describe("Calling " + METHOD, function () {
  describe("When on Zilliqa network", function () {
    it("should return a send raw transaction", async function () {
      const private_keys: string[] = hre.network["config"]["accounts"] as string[];
      const fromAccount = new ethers.Wallet(private_keys[0], hre.ethers.provider);
      const destination = ethers.Wallet.createRandom();
      const toAddress = destination.address;
      const nonce = await fromAccount.getTransactionCount(); // nonce starts counting from 0

      const tx = {
        to: toAddress,
        value: ethers.utils.parseUnits("1000000", "wei"),
        gasLimit: 300000,
        gasPrice: ethers.utils.parseUnits("2000", "gwei"),
        nonce: nonce,
        chainId: hre.getEthChainId(),
        data: "0x"
      };

      const signedTx = await fromAccount.signTransaction(tx);

      await sendJsonRpcRequest(METHOD, 1, [signedTx], (result, status) => {
        logDebug("Result:", result);

        // The result contains a transaction hash that is every time different and should match the hash returned in the result
        assert.equal(status, 200, "has status code");
        assert.property(result, "result", result.error ? result.error.message : "error");
        assert.isString(result.result, "is string");
        assert.match(result.result, /^0x/, "should be HEX starting with 0x");
        assert.equal(
          result.result,
          ethers.utils.keccak256(signedTx),
          "has result:" + result.result + ", expected transaction hash:" + ethers.utils.keccak256(signedTx)
        );
      });
    });
  });
});
