# Title

ots_hasCode

# Keywords

ots,code

# Description

Indicates whether an address has code associated with it at a particular block.

# Curl

```shell
    curl -d '{
        "id": "1",
        "jsonrpc": "2.0",
        "method": "ots_hasCode",
        "params": [ "0xB85fF091342e2e7a7461238796d5224fA81ca556", 1000 ]
    }' -H "Content-Type: application/json" -X POST "https://api.zq2-devnet.zilliqa.com/"
```

# Response

```json
{
  "jsonrpc": "2.0",
  "result": false,
  "id": "1"
}
```

# Arguments

| Parameter | Type    | Required | Description               |
| --------- | ------- | -------- | ------------------------- |
| `address` | address | Required | The address to query      |
| `block`   | number  | Required | The block number to query |
