# Title

GetNumPeers

# Keywords

peers,get,number,count

# Status

NotDocumented

# Description

Returns total number of peers including committee peers.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetNumPeers",
    "params": [""]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{ "id": "1", "jsonrpc": "2.0", "result": 600 }
```

# Arguments

| Parameter | Type   | Required | Description       |
| --------- | ------ | -------- | ----------------- |
| `id`      | string | Required | `"1"`             |
| `jsonrpc` | string | Required | `"2.0"`           |
| `method`  | string | Required | `"GetNumPeers"`   |
| `params`  | string | Required | Empty string `""` |
