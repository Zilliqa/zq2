# Title

txpool_contentFrom

# Keywords

pool,transaction,address

# Description

Retrieves the transactions contained within the transaction pool, returning pending as well as queued transactions of the specified address, grouped by nonce.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "txpool_contentFrom",
    "params": ["0x0216d5032f356960cd3749c31ab34eeff21b3395"]
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
  "queued": {}
}
```

# Arguments

| Parameter | Type    | Required | Description                                     |
| --------- | ------- | -------- | ----------------------------------------------- |
| address   | Address | Yes      | Address for which to return transaction details |
