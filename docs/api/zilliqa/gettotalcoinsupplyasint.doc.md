# Title

GetTotalCoinSupplyAsInt

# Keywords

get,coin,supply,int,total

# Description

`GetTotalCoinSupplyAsInt` Returns the total supply (ZIL) of coins in the network. This is represented as a
`Rounded Number`.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetTotalCoinSupplyAsInt",
    "params": [""]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": 13452081092
}
```

# Arguments

| Parameter | Type   | Required | Description                                       |
| --------- | ------ | -------- | ------------------------------------------------- |
| `id`      | string | Required | `"1"`                                             |
| `jsonrpc` | string | Required | `"2.0"`                                           |
| `method`  | string | Required | `"GetTotalCoinSupply or GetTotalCoinSupplyAsInt"` |
| `params`  | string | Required | Empty string `""`                                 |
