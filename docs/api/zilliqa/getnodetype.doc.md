# Title

GetNodeType

# Keywords

node,type,get

# Status

NotDocumented

# Description

Returns node type. The possible return values are:

- `"Leader"` if we are currently the lead node
- `"Validator"` otherwise

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
{ "id": "1", "jsonrpc": "2.0", "result": "Validator" }
```

# Arguments

| Parameter | Type   | Required | Description       |
| --------- | ------ | -------- | ----------------- |
| `id`      | string | Required | `"1"`             |
| `jsonrpc` | string | Required | `"2.0"`           |
| `method`  | string | Required | `"GetNodeType"`   |
| `params`  | string | Required | Empty string `""` |
