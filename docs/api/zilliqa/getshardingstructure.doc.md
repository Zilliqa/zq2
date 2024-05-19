# Title

GetShardingStructure

# Keywords

get,sharding,structure

# Status

NeverImplemented

# Description

Retrieves the sharding structure from the lookup server. In Zilliqa 2.0, this is replaced by the XShard on-chain query mechanism.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetShardingStructure",
    "params": [""]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{ "id": "1", "jsonrpc": "2.0", "result": { "NumPeers": [0] } }
```

# Arguments

| Parameter | Type   | Required | Description              |
| --------- | ------ | -------- | ------------------------ |
| `id`      | string | Required | `"1"`                    |
| `jsonrpc` | string | Required | `"2.0"`                  |
| `method`  | string | Required | `"GetShardingStructure"` |
| `params`  | string | Required | Empty string `""`        |
