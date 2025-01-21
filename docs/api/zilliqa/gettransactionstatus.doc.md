# Title

GetTransactionStatus

# Keywords

transaction,get,status

# Description

Returns the status of a specified transaction. Note that in Zilliqa 2, this API will work for any transaction, and since there are no DS epochs any longer, the transaction pool is not cleared at a DS epoch boundary.
Status codes have been simplified since Zilliqa 1

## Response Fields

| Field               | Description                                                                | Type    |
|---------------------|----------------------------------------------------------------------------|---------|
| `ID`                | Transaction hash as a string                                               | string  |
| `_id`               | null                                                                       | null    |
| `amount`            | Amount of ZIL transferred in the transaction                               | string  |
| `data`              | Data of the transaction                                                    | string  |
| `epochInserted`     | Block number of the transaction (or empty string if not yet in a block)    | string  |
| `epochUpdated`      | Block number of the transaction (or empty string if not yet in a block)    | string  |
| `gasLimit`          | Gas limit of the transaction                                               | string  |
| `gasPrice`          | Gas price of the transaction                                               | string  |
| `lastModified`      | Timestamp of transaction block (or now if not yet in a block)              | string  |
| `modificationState` | Modification state code (see table below)                                  | integer |
| `status`            | Status code (see table below)                                              | integer |
| `nonce`             | Nonce of the transaction                                                   | string  |
| `senderAddr`        | Sender address                                                             | string  |
| `signature`         | Signature                                                                  | string  |
| `success`           | Transaction created successfully                                           | boolean |
| `toAddr`            | Recipient address                                                          | string  |
| `version`           | Version                                                                    | string  |



## Status Codes

| `modificationState` | `status` | Description                                    |
| ------------------- | -------- | ---------------------------------------------- |
| 1                   | 2        | Pending in mempool or in a non-finalized block |
| 2                   | 3        | Confirmed (in a finalized block)               |
| 2                   | 255      | Error                                          |


# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetTransactionStatus",
    "params": ["1bb178b023f816e950d862f6505cd79a32bb97e71fd78441cbc3486940a2e1b7"]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": {
    "ID": "0d151c2bd14f7fc6a14e7a363d34eb6c125e68c36cd12064ee874a93a30d3f09",
    "_id": null,
    "amount": "200000000000000",
    "data": "",
    "epochInserted": "4",
    "epochUpdated": "4",
    "gasLimit": "50000",
    "gasPrice": "2000000016",
    "lastModified": "3042000",
    "modificationState": 1,
    "nonce": "1",
    "senderAddr": "0x0308484dfdba78ab585254e34c80c317cd97a26090c2a63d7f456c09344207994d",
    "signature": "0x4201654cfa78e273aba03dcd563b1dfedd265a2e983c8efe8f9ea2a1d240601add4f37d1b7cdad605af73c193fec66c8a59ac4e8178048a6a3cf080a7632e6b7",
    "status": 1,
    "success": true,
    "toAddr": "0x00000000000000000000000000000000deadbeef",
    "version": "45875201"
  }
}
```

# Arguments


| Parameter | Type   | Required | Description                                              |
| --------- | ------ | -------- | -------------------------------------------------------- |
| `id`      | string | Required | `"1"`                                                    |
| `jsonrpc` | string | Required | `"2.0"`                                                  |
| `method`  | string | Required | `"GetTransactionStatus"`                                 |
| `params`  | string | Required | Transaction hash of 32 bytes of a specified transaction. |
