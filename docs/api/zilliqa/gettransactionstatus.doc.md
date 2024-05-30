# Title

GetTransactionStatus

# Keywords

transaction,get,status

# Description

Returns the status of a specified transaction. Note that in Zilliqa 2, this API will work for any transaction, and since there are no DS epochs any longer, the transaction pool is not cleared at a DS epoch boundary.

## Response Fields

| Field               | Description                                     |
| ------------------- | ----------------------------------------------- |
| `_id`               | Object ID (internal database field)             |
| `epochInserted`     | Tx epoch when this transaction was first logged |
| `epochUpdated`      | Tx epoch when this transaction was last updated |
| `lastModified`      | Timestamp for this transaction's last update    |
| `modificationState` | See next table below                            |
| `status`            | See next table below                            |
| Other fields        | Transaction-related fields                      |

## Status Codes

| `modificationState` | `status` | Description                                                             |
| ------------------- | -------- | ----------------------------------------------------------------------- |
| 0                   | 1        | Pending - Dispatched                                                    |
| 1                   | 2        | Pending - Soft-confirmed (awaiting Tx block generation)                 |
| 1                   | 4        | Pending - Nonce is higher than expected                                 |
| 1                   | 5        | Pending - Microblock gas limit exceeded                                 |
| 1                   | 6        | Pending - Consensus failure in network                                  |
| 2                   | 3        | Confirmed                                                               |
| 2                   | 10       | Rejected - Transaction caused math error                                |
| 2                   | 11       | Rejected - Scilla invocation error                                      |
| 2                   | 12       | Rejected - Contract account initialization error                        |
| 2                   | 13       | Rejected - Invalid source account                                       |
| 2                   | 14       | Rejected - Gas limit higher than shard gas limit                        |
| 2                   | 15       | Rejected - Unknown transaction type                                     |
| 2                   | 16       | Rejected - Transaction sent to wrong shard                              |
| 2                   | 17       | Rejected - Contract & source account cross-shard issue                  |
| 2                   | 18       | Rejected - Code size exceeded limit                                     |
| 2                   | 19       | Rejected - Transaction verification failed                              |
| 2                   | 20       | Rejected - Gas limit too low                                            |
| 2                   | 21       | Rejected - Insufficient balance                                         |
| 2                   | 22       | Rejected - Insufficient gas to invoke Scilla checker                    |
| 2                   | 23       | Rejected - Duplicate transaction exists                                 |
| 2                   | 24       | Rejected - Transaction with same nonce but same/higher gas price exists |
| 2                   | 25       | Rejected - Invalid destination address                                  |
| 2                   | 26       | Rejected - Failed to add contract account to state                      |
| 2                   | 27       | Rejected - Nonce is lower than expected                                 |
| 2                   | 255      | Rejected - Internal error                                               |


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
    "ID": "1bb178b023f816e950d862f6505cd79a32bb97e71fd78441cbc3486940a2e1b7",
    "_id": {
      "$oid": "5fd053b0d127fe45cc5eea24"
    },
    "amount": "0",
    "data": "{\"_tag\":\"AddAccount\",\"params\":[{\"vname\":\"address\",\"type\":\"ByStr20\",\"value\":\"0x0434cdcf27e2294b3539cb6ffe2cc328d7f9757e\"},{\"vname\":\"datetime_added\",\"type\":\"String\",\"value\":\"1607488428\"}]}",
    "epochInserted": "2152402",
    "epochUpdated": "2152405",
    "gasLimit": "30000",
    "gasPrice": "2000000000",
    "lastModified": "1607488477842011",
    "modificationState": 2,
    "nonce": "131",
    "senderAddr": "b8fe5ab2e66c71274216688cf852e6d9f10b94e7",
    "signature": "0xBAA6964C66AE0608C6CEFBAAB69138E9358A1604C647DFFEF94E7022F2AB33D67F70802F71E934A0690BE4BA81CC3866B2FB668B29C528E6B77B1285533A2E2C",
    "status": 3,
    "success": true,
    "toAddr": "db4955ba4b1a957200ee0a36cf5f84eb4d7447e5",
    "version": "21823489"
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
