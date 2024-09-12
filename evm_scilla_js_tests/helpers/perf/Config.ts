import {Value} from "@zilliqa-js/zilliqa";

export enum ScenarioType {
  Transfer,
  ReadBalance,
  CallContract
}

export enum EvmOrZil {
  Zil = "Zil",
  Evm = "Evm"
}

export interface TransferConfig {
  iterations: number;
  type: EvmOrZil;
}

export interface ReadBalanceConfig {
  iterations: number;
  type: EvmOrZil;
  accounts: string[];
}

export interface CallContract {
  name: string;
  address: string;
  type: EvmOrZil;
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

export interface ScenarioStep {
  type: ScenarioType;
  disabled?: boolean;
  config: TransferConfig | ReadBalanceConfig | CallContractConfig;
}

export interface Scenario {
  name: string;
  disabled?: boolean;
  steps: ScenarioStep[];
}

export interface PerfConfig {
  sourceOfFunds: string;
  scenarios: Scenario[];
}
