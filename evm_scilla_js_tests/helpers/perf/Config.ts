import {Value} from "@zilliqa-js/zilliqa";

export enum ScenarioType {
  Transfer,
  ReadBalance,
  CallContract
}

export enum TransferType {
  Zil = "Zil",
  Evm = "Evm",
  Mixed = "Mixed"
}

export interface TransferConfig {
  iterations: number;
  type: TransferType;
}

export interface ReadBalanceConfig {
  iterations: number;
}

export enum TransitionType {
  Zil = "Zil",
  Evm = "Evm"
}

export interface CallContract {
  name: string;
  address: string;
  type: TransitionType;
  transitions: TransitionCall[];
}

export interface TransitionCall {
  name: string;
  iterations: number;
  args: Value[] | any[];
}

export interface CallContractConfig {
  calls: CallContract[];
}

export interface Scenario {
  type: ScenarioType;
  config: TransferConfig | ReadBalanceConfig | CallContractConfig;
}

export interface PerfConfig {
  sourceOfFunds: string;
  scenarios: Scenario[];
}
