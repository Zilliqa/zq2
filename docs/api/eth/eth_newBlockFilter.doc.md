# Title

eth_newBlockFilter

# Keywords

new,block,filter,create

# Description

Creates a filter in the node, to notify when a new block arrives. To check if the state has changed, call eth_getFilterChanges.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "eth_newBlockFilter",
    "params": []
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": "0x1" // Filter id
}
```

# Arguments

| Parameter | Type   | Required | Description           |
|-----------|--------|----------|-----------------------|
| `id`      | string | Required | `"1"`                 |
| `jsonrpc` | string | Required | `"2.0"`               |
| `method`  | string | Required | `"eth_newBlockFilter"` |
| `params`  | array  | Required | Empty array `[]`       |
```

```md
# Title

eth_newPendingTransactionFilter

# Keywords

new,pending,transaction,filter,create

# Description

Creates a filter in the node to notify when new pending transactions arrive. To check if the state has changed, call eth_getFilterChanges.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "eth_newPendingTransactionFilter",
    "params": []
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": "0x1" // Filter id
}
```

# Arguments

| Parameter | Type   | Required | Description                            |
|-----------|--------|----------|----------------------------------------|
| `id`      | string | Required | `"1"`                                  |
| `jsonrpc` | string | Required | `"2.0"`                                |
| `method`  | string | Required | `"eth_newPendingTransactionFilter"`     |
| `params`  | array  | Required | Empty array `[]`                        |
