# Title

eth_blockNumber

# Keywords

block,number,count

# Description

Returns a hexadecimal integer representing the most recent block this node has executed and knows to be final.

# Curl

```sh
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "eth_blockNumber"
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{"jsonrpc":"2.0","result":"0x4b3","id":1}
```

# Arguments

| Parameter | Type   | Required | Description         |
|-----------|--------|----------|---------------------|
| `id`      | string | Required | `"1"`               |
| `jsonrpc` | string | Required | `"2.0"`             |
| `method`  | string | Required | `"eth_blockNumber"` |
| `params`  | empty  | Optional | `[]` if present     |
