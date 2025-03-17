# Title

eth_newFilter

# Keywords

new,filter,create,logs

# Description

Creates a filter object, based on filter options, to notify when the state changes (logs).
To check if the state has changed, call eth_getFilterChanges.

Topics are order-dependent. A transaction with a log with topics [A, B] will be matched by the following topic filters:
* `[]` "anything"
* `[A]` "A in first position (and anything after)"
* `[null, B]` "anything in first position AND B in second position"
* `[A, B]` "A in first position AND B in second position"
* `[[A, B], [A, B]]` "A or B in first position AND A or B in second position"

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "eth_newFilter",
    "params": [{
        "fromBlock": "0x1",
        "toBlock": "0x2",
        "address": "0xb59f67a8bff5d8cd03f6ac17265c550ed8f33907",
        "topics": ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"]
    }]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": "0x1" // Filter id
}
```

# Arguments

| Parameter | Type   | Required | Description                                        |
|-----------|--------|----------|----------------------------------------------------|
| `id`      | string | Required | `"1"`                                              |
| `jsonrpc` | string | Required | `"2.0"`                                            |
| `method`  | string | Required | `"eth_newFilter"`                                  |
| `params`  | array  | Required | `[filter_object]` Filter options object:           |

Filter Object Fields:

| Field       | Type            | Required | Description                               |
|-------------|-----------------|----------|-------------------------------------------|
| `fromBlock` | string/tag      | Optional | Block from which to start looking for logs |
| `toBlock`   | string/tag      | Optional | Block at which to stop looking for logs    |
| `address`   | string/array    | Optional | Contract address(es) from which to get logs |
| `topics`    | array           | Optional | Array of 32-byte hex strings to filter by   |
| `blockHash` | string          | Optional | Hash of block to get logs from (cannot be used with fromBlock/toBlock) |
