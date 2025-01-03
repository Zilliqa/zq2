# Title

GetNodeType

# Keywords

node,type,get

# Status

Deprecated

# Description

Returns node type. For backwards compatibility reasons, in ZQ2 this always returns "Seed".

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetNodeType",
    "params": [""]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{ "id": "1", "jsonrpc": "2.0", "result": "Seed" }
```

# Arguments

| Parameter | Type   | Required | Description       |
| --------- | ------ | -------- | ----------------- |
| `id`      | string | Required | `"1"`             |
| `jsonrpc` | string | Required | `"2.0"`           |
| `method`  | string | Required | `"GetNodeType"`   |
| `params`  | string | Required | Empty string `""` |
