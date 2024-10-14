import {JsonRpcProvider} from "@ethersproject/providers";
import {Account} from "@zilliqa-js/account";
import {Wallet} from "ethers";
import {HardhatRuntimeEnvironment} from "hardhat/types";

export default class SignerPool {
  public takeEthSigner(): Wallet {
    if (this.eth_signers.length == 0) {
      throw new Error(
        "No more signers to return. Either you haven't initialized this pool, or you just ran out of signers."
      );
    }

    return this.eth_signers.pop()!;
  }

  public takeZilSigner(): Account {
    if (this.zil_signers.length == 0) {
      throw new Error(
        "No more signers to return. Either you haven't initialized this pool, or you just ran out of signers."
      );
    }

    return this.zil_signers.pop()!;
  }

  public initSigners(hre: HardhatRuntimeEnvironment, privateKeys: string[]) {
    // FIXME: Creating a custom prover is not needed in the new versions of hardhat/ethers.js
    const url = hre.getNetworkUrl();
    const customProvider = new JsonRpcProvider(url);
    customProvider.pollingInterval = 200;
    const signers = privateKeys.map((prvKey) => {
      return new hre.ethers.Wallet(prvKey, customProvider);
    });

    this.releaseEthSigner(...signers);

    this.zil_signers.push(...privateKeys.map((key) => new Account(key)));
  }

  public releaseEthSigner(...signer: Wallet[]) {
    this.eth_signers.push(...signer);
  }

  public releaseZilSigner(...signer: Account[]) {
    this.zil_signers.push(...signer);
  }

  public getZilSigner(index: number): Account {
    return this.zil_signers[index];
  }

  public count(): [eth_count: number, zil_count: number] {
    return [this.eth_signers.length, this.zil_signers.length];
  }

  private eth_signers: Wallet[] = [];
  private zil_signers: Account[] = [];
}
