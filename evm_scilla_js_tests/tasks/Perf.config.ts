import {PerfConfig, ScenarioType, EvmOrZil} from "../helpers/perf";

export const perfConfig: PerfConfig = {
  sourceOfFunds: "0000000000000000000000000000000000000000000000000000000000000002",
  scenarios: [
    {
      name: "Ghormesabzi",
      steps: [
        {
          type: ScenarioType.Transfer,
          config: {
            iterations: 5,
            type: EvmOrZil.Zil
          }
        },
        {
          type: ScenarioType.ReadBalance,
          config: {
            type: EvmOrZil.Zil,
            iterations: 5,
            accounts: ["0x6813eb9362372eef6200f3b1dbc3f819671cba69", "0x1eff47bc3a10a45d4b230b5d10e37751fe6aa718"]
          }
        },
        {
          type: ScenarioType.ReadBalance,
          config: {
            type: EvmOrZil.Evm,
            iterations: 5,
            accounts: ["0x9cb422d2fabe9622ed706ad5d9d3ffd2cdd1c001", "0xace5f1e883d3e02a1b2c78f6909a8c0430c6fb12"]
          }
        }
      ]
    }
  ]
};

// {
//   type: ScenarioType.CallContract,
//   config: {
//     calls: [
//   {
//     name: "Chain id contract",
//     iterations: 10,
//     transition: "EventChainID",
//     address: "0xBd13D9eE89487ccC296FbD7021773519d9E1686C",
//     args: []
//   },
//   {
//     name: "ForwardZil",
//     address: "0x3a4BF00f4713761a02AbA0b918B925381F6EaBd0",
//     type: TransitionType.Evm,
//     transitions: [
//       {
//         iterations: 10,
//         name: "transfer",
//         args: ["0x6813eb9362372eef6200f3b1dbc3f819671cba69", 1_000_000]
//       }
//     ]
//   }
//       {
//         name: "Hello world",
//         address: "0x02296cc2dA71C19D8Bb4bCa01C2fc5564593B7aa",
//         type: EvmOrZil.Zil,
//         transitions: [
//           {
//             iterations: 100,
//             name: "getHello",
//             args: []
//           },
//           {
//             iterations: 100,
//             name: "setHello",
//             args: [
//               {
//                 vname: "msg",
//                 value: "Hello",
//                 type: "String"
//               }
//             ]
//           }
//         ]
//       }
//     ]
//   }
// },
// {
