import {extendEnvironment} from "hardhat/config";
import {HardhatRuntimeEnvironment} from "hardhat/types/runtime";
import SingerPool from "./helpers/parallel-tests/SignerPool";
import {Contract, ethers, Signer, Wallet} from "ethers";
import {JsonRpcProvider, TransactionRequest, TransactionResponse} from "@ethersproject/providers";
import {ScillaContract, Setup} from "hardhat-scilla-plugin";
import {Account} from "@zilliqa-js/zilliqa";

declare module "hardhat/types/runtime" {
  interface HardhatRuntimeEnvironment {
    zilliqaSetup: Setup;
    signer_pool: SingerPool;
    debug: boolean;
    parallel: boolean;
    scillaTesting: boolean;
    isEthernalPluginEnabled: () => boolean;
    isScillaTestingEnabled: () => boolean;
    isZilliqaNetworkSelected: () => boolean;
    getEthChainId: () => number;
    getZilliqaChainId: () => number;
    getNetworkUrl: () => string;
    getWebsocketUrl: () => string;
    getWeb3ClientVersion: () => string;
    getProtocolVersion: () => number;
    getMiningState: () => boolean;
    getNetworkName: () => string;
    getEthSignerForContractDeployment: () => Promise<Wallet>;
    getZilSignerForContractDeployment: () => Account;
    allocateEthSigner: () => Wallet;
    allocateZilSigner: () => Account;
    releaseEthSigner: (...signer: Wallet[]) => void;
    releaseZilSigner: (...signer: Account[]) => void;
    sendEthTransaction: (txn: TransactionRequest) => Promise<{response: TransactionResponse; signer_address: string}>;
    deployScillaContract2: (name: string, ...args: any[]) => Promise<ScillaContract>;
    deployScillaContractWithSigner: (name: string, signer: Account, ...args: any[]) => Promise<ScillaContract>;
    deployContract: (name: string, ...args: any[]) => Promise<Contract>;
    deployContractWithSigner: (name: string, signer: Signer, ...args: any[]) => Promise<Contract>;
  }
}

extendEnvironment((hre: HardhatRuntimeEnvironment) => {
  hre.isScillaTestingEnabled = () => {
    return hre.scillaTesting;
  };

  hre.isZilliqaNetworkSelected = () => {
    return (hre as any).network.config.zilliqaNetwork;
  };

  hre.getEthChainId = () => {
    return (hre as any).network.config.chainId;
  };

  hre.getZilliqaChainId = () => {
    return (hre as any).network.config.chainId! - 0x8000;
  };

  hre.getNetworkUrl = () => {
    return (hre as any).network.config.url;
  };

  hre.getWebsocketUrl = () => {
    return (hre as any).network.config.websocketUrl;
  };

  hre.getWeb3ClientVersion = () => {
    return (hre as any).network.config.web3ClientVersion;
  };

  hre.getProtocolVersion = () => {
    return (hre as any).network.config.protocolVersion;
  };

  hre.getMiningState = () => {
    return (hre as any).network.config.miningState;
  };

  hre.getNetworkName = () => {
    return (hre as any).network.name;
  };

  hre.getEthSignerForContractDeployment = async (): Promise<Wallet> => {
    if (hre.parallel) {
      return hre.signer_pool.takeEthSigner();
    } else {
      const privateKeys: string[] = hre.getPrivateKeys();
      if (privateKeys.length === 0) {
        throw new Error("Please specify at least one account in the config.");
      }

      const url = hre.getNetworkUrl();
      const customProvider = new JsonRpcProvider(url);
      customProvider.pollingInterval = 200;
      const signer = new ethers.Wallet(privateKeys[0], customProvider);

      return signer;
    }
  };

  hre.getZilSignerForContractDeployment = (): Account => {
    if (hre.parallel) {
      return hre.signer_pool.takeZilSigner();
    } else {
      return hre.signer_pool.getZilSigner(0);
    }
  };

  /// If you call this function, consequently you must call `releaseEthSigner`, otherwise you'll run out of signers.
  hre.allocateEthSigner = (): Wallet => {
    return hre.signer_pool.takeEthSigner();
  };

  /// If you call this function, consequently you must call `releaseZilSigner`, otherwise you'll run out of signers.
  hre.allocateZilSigner = (): Account => {
    return hre.signer_pool.takeZilSigner();
  };

  hre.releaseEthSigner = (...signer: Wallet[]) => {
    hre.signer_pool.releaseEthSigner(...signer);
  };

  hre.releaseZilSigner = (...signer: Account[]) => {
    hre.signer_pool.releaseZilSigner(...signer);
  };

  hre.sendEthTransaction = async (txn: TransactionRequest) => {
    const signer = hre.allocateEthSigner();
    const response = await signer.sendTransaction(txn);
    hre.releaseEthSigner(signer);

    return {response, signer_address: await signer.getAddress()};
  };

  hre.deployScillaContract2 = async (name: string, ...args: any[]): Promise<ScillaContract> => {
    const signer = hre.getZilSignerForContractDeployment();
    hre.setActiveAccount(signer);
    return hre.deployScillaContract(name, ...args);
  };

  hre.deployScillaContractWithSigner = async (
    name: string,
    signer: Account,
    ...args: any[]
  ): Promise<ScillaContract> => {
    hre.setActiveAccount(signer);
    let contract = await hre.deployScillaContract(name, ...args);
    return contract.connect(signer);
  };

  hre.deployContract = async (name: string, ...args: any[]): Promise<Contract> => {
    const signer = await hre.getEthSignerForContractDeployment();
    return hre.deployContractWithSigner(name, signer, ...args);
  };

  hre.deployContractWithSigner = async (name: string, signer: Signer, ...args: any[]): Promise<Contract> => {
    const factory = await hre.ethers.getContractFactory(name);
    return (await factory.connect(signer).deploy(...args)).deployed();
  };
});
