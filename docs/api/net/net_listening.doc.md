# Title

net_listening

# Keywords

net, listening, network, status

# Description

Returns whether the node is currently listening for network connections.

This endpoint always returns `true` as the node is always listening for network connections.

## Parameters

None

# Curl

```shell
curl -d '{
  "id": "1",
  "jsonrpc": "2.0",
  "method": "net_listening",
  "params": []
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{"jsonrpc":"2.0","result":true,"id":"1"}
```

# Arguments

| Parameter | Type   | Required | Description                 |
|-----------|--------|----------|-----------------------------|
| `id`      | string | Required | `"1"`                       |
| `jsonrpc` | string | Required | `"2.0"`                     |
| `method`  | string | Required | `"net_listening"`           |
| `params`  | array  | Required | `[]`                        |