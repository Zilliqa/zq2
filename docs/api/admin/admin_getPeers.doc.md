# Title

admin_getPeers

# Keywords

admin,peers,network,swarm,sync

# Description

Returns information about the peers currently connected to this node, including both swarm peers and sync peers.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "admin_getPeers",
    "params": []
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "swarm_peers": [
      "12D3KooWBmwkafWE9JFWqFBe7tBXm1Q4t6R2nV4p8J3xQ5m7L9kS",
      "12D3KooWCrMTaGRNkpqXeQBrv4RqP8Kd2wNmH5xY7zA9BcEfGhIj"
    ],
    "sync_peers": [
      "12D3KooWDxMnP7qR8sKfWe5YnT4vBcDfGhIjK3L9mNpQ2rStUvWx"
    ]
  }
}
```

# Arguments

| Parameter | Type   | Required | Description                 |
|-----------|--------|----------|-----------------------------|
| `id`      | string | Required | `"1"`                       |
| `jsonrpc` | string | Required | `"2.0"`                     |
| `method`  | string | Required | `"admin_getPeers"`          |
| `params`  | array  | Required | Empty array `[]`            |
