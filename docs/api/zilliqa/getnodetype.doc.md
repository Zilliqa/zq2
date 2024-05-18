# Title

GetNodeType

# Keywords

node,type,get

# Status

NotDocumented

# Description

Returns node type. The possible return values are:

- `"Not in network, synced till epoch [epoch number]"` if the server has not joined the network and is synced until a specific epoch.
- `"Seed"` if the server is in lookup node mode and is an archival lookup node.
- `"Lookup"` if the server is in lookup node mode

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

