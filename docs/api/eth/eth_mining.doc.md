# Title

eth_mining

# Keywords

eth,mining

# Description

Returns if the node is mining. zq2 nodes always return `false`.

# Curl

```sh
 curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "eth_mining",
    "params": [
 ]}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{"jsonrpc":"2.0","result":false,"id":"1"}
```

# Arguments

| Parameter | Type   | Required | Description     |
|-----------|--------|----------|-----------------|
| `id`      | string | Required | `"1"`           |
| `jsonrpc` | string | Required | `"2.0"`         |
| `method`  | string | Required | `"eth_mining"`  |
| `params`  | array  | Requred  | can be anything |
