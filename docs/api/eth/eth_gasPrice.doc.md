# Title

eth_getGasPrice

# Keywords

gas,price,get

# Description

Return the current gas price in Wei.

# Curl

```sh
curl -d '{
  "id": "1",
  "jsonrpc": "2.0",
  "method": "eth_gasPrice"
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{"jsonrpc":"2.0","result":"0x454b7a4e100","id":"1"}
```

# Arguments

| Parameter | Type   | Required | Description      |
|-----------|--------|----------|------------------|
| `id`      | string | Required | `"1"`            |
| `jsonrpc` | string | Required | `"2.0"`          |
| `method`  | string | Required | `"eth_gasPrice"` |
| `params`  | empty  | Optional | `[]` if present  |


