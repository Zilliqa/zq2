# Title

eth_getBlockByNumber

# Keywords

block,get,number

# Description

Returns information about a block by block number.

## Parameters

{{ macro_blocknumber }}
{{ macro_hydrated }}

## Results

An array of blocks.

{{ macro_returned_block }}

# Curl

```sh
```

# Response

```json
```

# Arguments

| Parameter | Type   | Required | Description                  |
|-----------|--------|----------|------------------------------|
| `id`      | string | Required | `"1"`                        |
| `jsonrpc` | string | Required | `"2.0"`                      |
| `method`  | string | Required | `"DSBlockListing"`           |
| `params`  | array  | Requred  | `[ block_number, hydrated ]` |

