# Title

net_peerCount

# Keywords

net, peer, count, network

# Description

Returns the number of peers currently connected to the node.

The response is returned as a hexadecimal string representing the number of connected peers.

## Parameters

None

# Curl

```shell
curl -d '{
  "id": "1",
  "jsonrpc": "2.0",
  "method": "net_peerCount",
  "params": []
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{"jsonrpc":"2.0","result":"0x5","id":"1"}
```

# Arguments

| Parameter | Type   | Required | Description                 |
|-----------|--------|----------|-----------------------------|
| `id`      | string | Required | `"1"`                       |
| `jsonrpc` | string | Required | `"2.0"`                     |
| `method`  | string | Required | `"net_peerCount"`           |
| `params`  | array  | Required | `[]`                        |