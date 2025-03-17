# Title

eth_mining

# Keywords

eth,mining

# Description

Returns if the node is synchronising with the main chain.

# Curl

```sh
 curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "eth_syncing",
    "params": [
 ]}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

If the node is synchronised,

```
{"jsonrpc":"2.0","result":false,"id":"1"}
```

If the node is not synchronised:

```
{"jsonrpc":"2.0","id":"1","result":{"startingBlock":0,"currentBlock":24,"highestBlock":1781}}
```

This tells you that this node started syncing at 0 (we started at
genesis), has validated and committed block 24 and believes that the
highest block in the chain is somewhere near block 1781.

# Arguments

| Parameter | Type   | Required | Description     |
|-----------|--------|----------|-----------------|
| `id`      | string | Required | `"1"`           |
| `jsonrpc` | string | Required | `"2.0"`         |
| `method`  | string | Required | `"eth_syncing"`  |
| `params`  | array  | Required | can be anything |
