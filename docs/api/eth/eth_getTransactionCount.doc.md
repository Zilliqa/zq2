# Title

eth_getTransactionCount

# Keywords

transaction,count,get

# Description

Return the number of transactions sent from an address at a particular block. This is equivalent to the nonce of this account at the end of the block.

## Parameters

{{ macro_address }}
{{ macro_blockid }}

# Curl

```sh
curl -d '{
   "id": "1",
   "jsonrpc": "2.0",
   "method": "eth_getTransactionCount",
   "params": [ "0x97Ef723bC7e64cDD01E40B753c0C1f0d2A98Bf6D",  "latest"
]}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{"jsonrpc":"2.0","result":"0x0","id":"1"}
```

# Arguments

| Parameter | Type   | Required | Description                 |
|-----------|--------|----------|-----------------------------|
| `id`      | string | Required | `"1"`                       |
| `jsonrpc` | string | Required | `"2.0"`                     |
| `method`  | string | Required | `"eth_getTransactionCount"` |
| `params`  | array  | Requred  | `[ address, block_number]`  |
