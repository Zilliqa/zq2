# Title

txpool_inspect

# Keywords

pool,transaction

# Description

Returns a textual summary of all the transactions currently pending for inclusion in the next block(s), as well as the ones that are being scheduled for future execution. This is a method specifically tailored to developers to quickly see the transactions in the pool and find any potential issues.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "txpool_inspect",
    "params": []
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{
  "pending": {
    "0x26588a9301b0428d95e6fc3a5024fce8bec12d51": {
      "31813": "0x3375ee30428b2a71c428afa5e89e427905f95f7e: 0 wei + 500000 × 20000000000 wei"
    },
    "0x2a65aca4d5fc5b5c859090a6c34d164135398226": {
      "563662": "0x958c1fa64b34db746925c6f8a3dd81128e40355e: 1051546810000000000 wei + 90000 gas × 20000000000 wei",
      "563663": "0x77517b1491a0299a44d668473411676f94e97e34: 1051190740000000000 wei + 90000 gas × 20000000000 wei"
    }
  },
  "queued": {
    "0x0f6000de1578619320aba5e392706b131fb1de6f": {
      "6": "0x8383534d0bcd0186d326c993031311c0ac0d9b2d: 9000000000000000000 wei + 21000 gas × 20000000000 wei"
    }
  }
}
```

# Arguments

| Parameter | Type   | Required | Description             |
| --------- | ------ | -------- | ----------------------- |
