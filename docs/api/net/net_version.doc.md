# Title

net_version

# Keywords

net, version, network, chain, id

# Description

Returns the current network ID (chain ID) of the node.

The network ID is used to identify different networks (e.g., mainnet, testnet) and is returned as a string.

## Parameters

None

# Curl

```shell
curl -d '{
  "id": "1",
  "jsonrpc": "2.0",
  "method": "net_version",
  "params": []
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{"jsonrpc":"2.0","result":"1","id":"1"}
```

# Arguments

| Parameter | Type   | Required | Description                 |
|-----------|--------|----------|-----------------------------|
| `id`      | string | Required | `"1"`                       |
| `jsonrpc` | string | Required | `"2.0"`                     |
| `method`  | string | Required | `"net_version"`             |
| `params`  | array  | Required | `[]`                        |