# Title

GetTransactionsForTxBlockEx

# Keywords

txn,transaction,get,block,txblock,tx,page

# Description

This API behaves similarly to `GetTransactionsForTxBlock` except that
it returns the transactions in batches (or pages) of 2,500.

The number of pages available is defined by the `NumPages` header
value in the `GetTxBlock` or `GetLatestTxBlock` response. Page
indexing is zero-based and indicated in the request after the block
number.

For example, to retrieve all the transactions for a block with
`NumPages=3`, one must call `GetTransactionsForTxBlockEx` three times
with page number 0, 1, and 2.

## Block Parameters

| Parameter      | Type   | Required | Description                                              |
| -------------- | ------ | -------- | -------------------------------------------------------- |
| `Block number` | string | Required | Specifed TX block number to return. Example: `"1002353"` |
| `Page number`  | string | Required | Page number (zero-based). Example: `"2"`                 |

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetTransactionsForTxBlockEx",
    "params": ["1002353", "2"]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": {
    "CurrPage": 2,
    "NumPages": 5,
    "Transactions": [
      [
        "0a9b4733bff6be2d48020f42e561a89d735eeb809eda257b6a56712223e842eb",
        "01924067b8d120de35c72bf7213faa12d8b6d20dfc867a027a39799090fd2bad",
        ..."321fe2ed656c622c14d4c7919080086bc95fa57f52a235966cf2c3661dc2fbc5",
        "3e0eee38171169b7f179035fd02e40f74d698d05733597115ef67ae2034a7b48"
      ],
      [
        "000d1ab6963ff7c3db82fcce858e93fa264f7d39010099482ab965a518566195",
        "6374f8d23d2aa96e3b205a677ad0569bf087d8a099ce90c2869bfca8588f11eb",
        ..."6ad9c1aca7106ace4b836c677ac4a850f611349725358c541741842fb12b4d8d",
        "d116b78ddd5a30bc1a27495f9227af1cd62a90766eaaba7610a395aeab78ee10"
      ],
      [],
      []
    ]
  }
}
```

# Arguments

| Parameter | Type   | Required | Description                     |
| --------- | ------ | -------- | ------------------------------- |
| `id`      | string | Required | `"1"`                           |
| `jsonrpc` | string | Required | `"2.0"`                         |
| `method`  | string | Required | `"GetTransactionsForTxBlockEx"` |
| `params`  | array  | Required | Block parameters                |

