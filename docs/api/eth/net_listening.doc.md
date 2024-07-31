# Title

net_listening

# Keywords

net,listening,query,client

# Description

Returns true if a client is actively listening for network connections. Always returns `true`.

# Curl

```sh
 curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "net_listening",
    "params": [
 ]}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{"jsonrpc":"2.0","result":true,"id":"1"}
```

# Arguments

| Parameter | Type   | Required | Description       |
|-----------|--------|----------|-------------------|
| `id`      | string | Required | `"1"`             |
| `jsonrpc` | string | Required | `"2.0"`           |
| `method`  | string | Required | `"net_listening"` |
| `params`  | array  | Requred  | can be anything   |



