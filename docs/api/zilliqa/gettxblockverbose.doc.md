# Title

GetTxBlockVerbose

# Keywords

tx,block,get,verbose,number

# Status

PartiallyImplemented

# Description

`GetTxBlockVerbose` returns the verbose details of a specified transaction block

This API is partially implemented - see (<https://github.com/Zilliqa/zq2/issues/79>)

Note: the `Rewards` field is included for backwards compatibility and will always return `0`.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetTxBlockVerbose",
    "params": ["1002353"]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": {
    "body": {
      "B1": [
        false,
        false,
        false,
        false,
        false,
        true,
        true,
        true,
        true
        // Output truncated
      ],
      "B2": [
        false,
        false,
        false,
        false,
        false,
        true
        // Output truncated
      ],
      "BlockHash": "57996c6d950367a64cf6fe46a0c04441eee99e6014fc6336a0c970108fc5f4a1",
      "CS1": "BF3D3B005DC7406E24F629103D34840719C198A1703784F835CAAC65D3FD486D041330A7C3A7D03225D7D0C317A5BBD97C75B53820EA6C565615DED9B0945C12",
      "HeaderSign": "EC5E7E260C54909F905D74A52BDF683F70AFD4B6AE1EDE4E50F79527A598C953A7FA86892BECBD6C4D7E3BF015123D5AB4D43E41B764328F76131E9046EF7C9B",
      "MicroBlockInfos": [
        {
          "MicroBlockHash": "5a904694af8ed81235309e802f1868699d7760c10c39b1626fca86ecc3689c4f",
          "MicroBlockShardId": 0,
          "MicroBlockTxnRootHash": "0000000000000000000000000000000000000000000000000000000000000000"
        },
        {
          "MicroBlockHash": "8b06628d337814eed480e8f49ba5be6d6e93593dea3b1413c48c99231536e29f",
          "MicroBlockShardId": 1,
          "MicroBlockTxnRootHash": "0000000000000000000000000000000000000000000000000000000000000000"
        },
        {
          "MicroBlockHash": "91141ac9ea2abf17adbf5797d49fa560072731df9dd81ea46f55446dfc46d1ae",
          "MicroBlockShardId": 2,
          "MicroBlockTxnRootHash": "0000000000000000000000000000000000000000000000000000000000000000"
        },
        {
          "MicroBlockHash": "32f97f1c4afdd123f1cfdd5e3bbdfcd86bbb7fb499fdae4d27fe2ed328a19c00",
          "MicroBlockShardId": 3,
          "MicroBlockTxnRootHash": "0000000000000000000000000000000000000000000000000000000000000000"
        }
      ]
    },
    "header": {
      "BlockNum": "3167",
      "CommitteeHash": "704380e65d66155ca878cfa607a26a919749acae0ac545f6f100f7a0ab20efee",
      "DSBlockNum": "32",
      "GasLimit": "2000000",
      "GasUsed": "0",
      "MbInfoHash": "dc1b3a968bdf92715af63e3da8bfc2560d2b7b15c17299fd2c07bd0778a0b66e",
      "MinerPubKey": "0x0223E276FFF18295630C6C41BE9565DDC8E41B3B3E6E79CA1A6699616AD2C756AF",
      "NumMicroBlocks": 4,
      "NumPages": 0,
      "NumTxns": 0,
      "PrevBlockHash": "4476876bb0297ee6bf4d4b7aed176a1e270ba71b07c45740111368f945c8233d",
      "Rewards": "0",
      "StateDeltaHash": "0000000000000000000000000000000000000000000000000000000000000000",
      "StateRootHash": "72219f58dab5e832a36eaf67b445831afd5e67f8f9dfac418cf792cb87fdac31",
      "Timestamp": "1549336642054789",
      "TxnFees": "0",
      "Version": 1
    }
  }
}
```

# Arguments

| Parameter | Type   | Required | Description                                               |
| --------- | ------ | -------- | --------------------------------------------------------- |
| `id`      | string | Required | `"1"`                                                     |
| `jsonrpc` | string | Required | `"2.0"`                                                   |
| `method`  | string | Required | `"GetTxBlockVerbose"`                                     |
| `params`  | string | Required | Specified TX block number to return. Example: `"1002353"` |
