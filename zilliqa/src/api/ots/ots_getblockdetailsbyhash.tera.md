# Title

ots_getBlockDetailsByHash

# Keywords

ots,block,details,hash

# Description

Returns details of a block for otterscan by hash

# Curl

```shell
    curl -d '{
        "id": "1",
        "jsonrpc": "2.0",
        "method": "ots_getBlockDetailsByHash",
        "params": [ "0x7dbeae485c26511423301be854c6cdec6b07170427f3270ac1748782f4fe4a8f" ]
    }' -H "Content-Type: application/json" -X POST "https://api.zq2-devnet.zilliqa.com/"
```

# Response

```json
{
  "jsonrpc": "2.0",
  "result": {
    "block": {
      "number": "0x3e8",
      "hash": "0x7dbeae485c26511423301be854c6cdec6b07170427f3270ac1748782f4fe4a8f",
      "parentHash": "0x71d2d959e0eb73b429686c0c1107e4183f04c0a54752d4fe519a1f0c54ab7cdb",
      "nonce": "0x0",
      "sha3Uncles": "0x0000000000000000000000000000000000000000000000000000000000000000",
      "transactionsRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
      "stateRoot": "0xd639a448087e7d087fb2d0fef4a1bd95237a965277dcbf7ee33344384491d409",
      "receiptsRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
      "miner": "0x768af8c0b4792ed2948186857f1122f3cd6a695d",
      "difficulty": "0x0",
      "totalDifficulty": "0x0",
      "extraData": "0x",
      "size": "0x0",
      "gasLimit": "0x1",
      "gasUsed": "0x0",
      "timestamp": "0x6602d4bc",
      "transactionCount": 0,
      "uncles": [],
      "baseFeePerGas": "0x0"
    },
    "issuance": {
      "blockReward": "0x0",
      "uncleReward": "0x0",
      "issuance": "0x0"
    },
    "totalFees": "0x0"
  },
  "id": "1"
}
```

# Arguments

| Parameter | Type   | Required | Description             |
| --------- | ------ | -------- | ----------------------- |
| `hash`    | string | Required | The block hash to query |
