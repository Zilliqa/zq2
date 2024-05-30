# Title

GetTxnBodiesForTxBlockEx

# Keywords

txn,get,bodies,tx,transaction,block,page

# Description

This API behaves similar to `GetTxBodiesForTxBlock` except that it
returns the transactions in batches (or pages) of 2,500.

The number of pages available is defined by the `NumPages` header
value in the `GetTxBlock` or `GetLatestTxBlock` response. Page
indexing is zero-based and indicated in the request after the block
number.

For example, to retrieve all the transactions for a block with `NumPages=3`, one
must call `GetTxBodiesForTxBlockEx` three times with page number 0, 1, and 2.

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
    "method": "GetTxnBodiesForTxBlockEx",
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
      {
        "ID": "0a9b4733bff6be2d48020f42e561a89d735eeb809eda257b6a56712223e842eb",
        "amount": "0",
        "gasLimit": "1",
        "gasPrice": "2000000000",
        "nonce": "96538",
        "receipt": {
          "cumulative_gas": "1",
          "epoch_num": "1002353",
          "success": true
        },
        "senderPubKey": "0x0235372F21184432428ABCDF99385FFF3A4EC346942B51FACBE9589DDF482C5D45",
        "signature": "0x1A7CD80504D1BD75C50F751C08FC36ACC0F1A94852048179BCC927A3D5BC297AF01FB0A9CADBEC9AB870D330C8E2931E7025AE1293CE66B7429ABC44E785F16B",
        "toAddr": "43b358e23092e2d367cedcd08c513fdca2162c01",
        "version": "65537"
      },
      ...{
        "ID": "d116b78ddd5a30bc1a27495f9227af1cd62a90766eaaba7610a395aeab78ee10",
        "amount": "0",
        "gasLimit": "1",
        "gasPrice": "2000000000",
        "nonce": "98068",
        "receipt": {
          "cumulative_gas": "1",
          "epoch_num": "1002353",
          "success": true
        },
        "senderPubKey": "0x02FBB56136F2BBC10C963CCB8FA19287926A655023AB137BB018D2C65238D0F481",
        "signature": "0xC6C4B4060026631F6F79BB5D6B163A51729E11A92D0E217F3ABCD38D2A8E733C62A9EBADA184DEAD5859BBE68ABD888E3A0B194B260FF7A9ACD58523A37EF896",
        "toAddr": "43b358e23092e2d367cedcd08c513fdca2162c01",
        "version": "65537"
      }
    ]
  }
}
```

# Arguments

| Parameter | Type   | Required | Description                  |
| --------- | ------ | -------- | ---------------------------- |
| `id`      | string | Required | `"1"`                        |
| `jsonrpc` | string | Required | `"2.0"`                      |
| `method`  | string | Required | `"GetTxnBodiesForTxBlockEx"` |
| `params`  | array  | Required | Block parameters             |

