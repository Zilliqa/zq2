# Title

eth_getTransactionReceipt

# Keywords

get,transaction,receipt,eth

# Description

Retrieve a transaction receipt, or return `null`.

## Parameters

A transaction hash.

## Returns

{{ macro_transaction_receipt }}

# Curl


# Response

# Arguments

| Parameter | Type   | Required | Description            |
|-----------|--------|----------|------------------------|
| `id`      | string | Required | `"1"`                  |
| `jsonrpc` | string | Required | `"2.0"`                |
| `method`  | string | Required | `"eth_getBlockByHash"` |
| `params`  | array  | Required | `[ txn_hash ]`         |

