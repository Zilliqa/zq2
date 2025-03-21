# Title

txpool_content

# Keywords

pool,transaction

# Description

Returns the exact details of all the transactions currently pending for inclusion in the next block(s), as well as the ones that are being scheduled for future execution only.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "txpool_content",
    "params": []
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{
  "pending": {
    "0x0216d5032f356960cd3749c31ab34eeff21b3395": {
      "806": {
        "blockHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "blockNumber": null,
        "from": "0x0216d5032f356960cd3749c31ab34eeff21b3395",
        "gas": "0x5208",
        "gasPrice": "0xba43b7400",
        "hash": "0xaf953a2d01f55cfe080c0c94150a60105e8ac3d51153058a1f03dd239dd08586",
        "input": "0x",
        "nonce": "0x326",
        "to": "0x7f69a91a3cf4be60020fb58b893b7cbb65376db8",
        "transactionIndex": null,
        "value": "0x19a99f0cf456000"
      }
    }
  },
  "queued": {
    "0x976a3fc5d6f7d259ebfb4cc2ae75115475e9867c": {
      "3": {
        "blockHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "blockNumber": null,
        "from": "0x976a3fc5d6f7d259ebfb4cc2ae75115475e9867c",
        "gas": "0x15f90",
        "gasPrice": "0x4a817c800",
        "hash": "0x57b30c59fc39a50e1cba90e3099286dfa5aaf60294a629240b5bbec6e2e66576",
        "input": "0x",
        "nonce": "0x3",
        "to": "0x346fb27de7e7370008f5da379f74dd49f5f2f80f",
        "transactionIndex": null,
        "value": "0x1f161421c8e0000"
      }
    }
  }
}
```

# Arguments

| Parameter | Type   | Required | Description             |
| --------- | ------ | -------- | ----------------------- |
