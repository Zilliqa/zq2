# Title

net_peerCount

# Keywords

net,count,peers

# Description

Returns the number of peers currently connected to the client. In zq2, always returns `"0x0"`.

# Curl

```sh
 curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "net_peerCount",
    "params": [
 ]}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{"jsonrpc":"2.0","result":"0x0","id":"1"}
```

# Arguments

| Parameter | Type   | Required | Description       |
|-----------|--------|----------|-------------------|
| `id`      | string | Required | `"1"`             |
| `jsonrpc` | string | Required | `"2.0"`           |
| `method`  | string | Required | `"net_peerCount"` |
| `params`  | array  | Requred  | can be anything   |

