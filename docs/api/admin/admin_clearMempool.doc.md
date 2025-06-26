# Title

admin_clearMempool

# Keywords

admin,clear,mempool,transactions

# Description

Clears all pending transactions from the node's mempool. This is an administrative function that removes all transactions waiting to be included in a block.

!!! warning
    This operation will remove all pending transactions from the mempool. These transactions will need to be resubmitted.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "admin_clearMempool",
    "params": []
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": null
}
```

# Arguments

| Parameter | Type   | Required | Description                 |
|-----------|--------|----------|-----------------------------|
| `id`      | string | Required | `"1"`                       |
| `jsonrpc` | string | Required | `"2.0"`                     |
| `method`  | string | Required | `"admin_clearMempool"`      |
| `params`  | array  | Required | Empty array `[]`            |
