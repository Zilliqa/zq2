# Title

eth_chainId

# Keywords

eth,chain,id,get,fetch

# Description

Returns the EVM chain id for this chain as an unsigned hex integer. In Zilliqa and Zilliqa 2, the EVM chain id is the Zilliqa native chain id OR'd with `0x8000`. You can retrieve the Zilliqa native chain id with a call to `GetBlockChainInfo`.

# Curl

```sh
 curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "eth_chainId"
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```
{"jsonrpc":"2.0","result":"0x82bc","id":"1"}
```

# Arguments

| Parameter | Type   | Required | Description     |
|-----------|--------|----------|-----------------|
| `id`      | string | Required | `"1"`           |
| `jsonrpc` | string | Required | `"2.0"`         |
| `method`  | string | Required | `"eth_chainId"` |
| `params`  | empty  | Optional | `[]` if present |
