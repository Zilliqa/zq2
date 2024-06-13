# Title

eth_accounts

# Keywords

accounts

# Description

Returns a list of addresses for the accounts owned by this client. Not applicable in Zilliqa 2.0 and thus returns the empty list.

# Curl

```sh
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "eth_accounts"
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response


```sh
{"jsonrpc":"2.0","result":[],"id":"1"}
```

# Arguments

| Parameter | Type   | Required | Description      |
|-----------|--------|----------|------------------|
| `id`      | string | Required | `"1"`            |
| `jsonrpc` | string | Required | `"2.0"`          |
| `method`  | string | Required | `"eth_accounts"` |
| `params`  | empty  | Optional | `[]` if present  |
