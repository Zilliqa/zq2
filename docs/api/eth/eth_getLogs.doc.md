# Title

eth_getLogs

# Keywords

get,eth,logs

# Description

Returns logs matching the filter in the parameters.

## Parameters

{{ macro_filter }}

If `blockHash` is specified, it is an error to also specify `fromBlock` or `toBlock`. If `fromBlock` or `toBlock` is specified, it is an error to also specify `blockHash`.
`fromBlock` must be less than or equal to `toBlock`.

{{ macro_blocknumber }}
{{ macro_topicspec }}

## Return values

We return a list of log objects

{{ macro_logobject }}

# Curl

```sh
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "eth_getLogs",
    "params": [ { "fromBlock": "0x779", "toBlock": "0x779" } ]}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{"jsonrpc":"2.0","result":[{"removed":false,"logIndex":"0x0","transactionIndex":"0x0","transactionHash":"0xcfd9d4473c9467f7fc1fe6f602599c8559ea78953acaae205551bb6c2f55472f","blockHash":"0x224a67320685771e1e0c428b1a271af8339cbd542d1726642c3a14519f25ae9e","blockNumber":"0x779","address":"0xbca0f6f4cbfe8ac37096b674de8f96c701c43f7c","data":"0x00000000000000000000000000000000000000000000000000000000000f4240","topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","0x0000000000000000000000000000000000000000000000000000000000000000","0x000000000000000000000000cb57ec3f064a16cadb36c7c712f4c9fa62b77415"]}],"id":"1"}
```

# Arguments


| Parameter | Type   | Required | Description        |
|-----------|--------|----------|--------------------|
| `id`      | string | Required | `"1"`              |
| `jsonrpc` | string | Required | `"2.0"`            |
| `method`  | string | Required | `"DSBlockListing"` |
| `params`  | array  | Requred  | `[ filter ]`       |

