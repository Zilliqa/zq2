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

A block structure, or `null` if no such block is known to this node.

{{ macro_returned_block }}

If `hydrated` is `true`, blocks contain returned transactions.

{{ macro_returned_transaction }}

# Curl

```sh
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "eth_getBlockByNumber",
    "params": [ "0x4f60", true
 ]}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
 ```

# Response

```json
{
  "jsonrpc": "2.0",
  "result": {
    "number": "0x4f60",
    "view": "0x4f61",
    "hash": "0x4d834e76f63b80eae3f4dedf675b04bbbf2d8f188f7023ca09f4ed346b6893c2",
    "parentHash": "0x50b3b76c3a4f19ac20e498744d8e0ff9a110b9130acb3ba786c80c26738ee9ae",
    "nonce": "0x0000000000000000",
    "sha3Uncles": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "transactionsRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "stateRoot": "0x680b514e8fe0bf0cbc34173a7911b1d8c79a357830cb28d22c5ae53078ef8dfd",
    "receiptsRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "miner": "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
    "difficulty": "0x0",
    "totalDifficulty": "0x0",
    "extraData": "0x",
    "gasLimit": "0x501bd00",
    "gasUsed": "0x8484",
    "timestamp": "0x667aef3b",
    "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "size": "0x0",
    "transactions": [
      {
        "blockHash": "0x4d834e76f63b80eae3f4dedf675b04bbbf2d8f188f7023ca09f4ed346b6893c2",
        "blockNumber": "0x4f60",
        "from": "0xcb57ec3f064a16cadb36c7c712f4c9fa62b77415",
        "gas": "0xb709",
        "gasPrice": "0x454b7a4e100",
        "hash": "0x1d6fea3e5707aa24a7a1ce6f661adab0655c2e2438dddee16dacdf3d6cf14ee4",
        "input": "0x19ff1d21",
        "nonce": "0x1",
        "to": "0x45c3e57617b87c0e24d66b3eb4860a87bfeef25a",
        "transactionIndex": "0x0",
        "value": "0x0",
        "v": "0x1059c",
        "r": "0x8a08e389457722e33b4bd4429321ec3b4bbe09a8b67c6199d81fa65ea813c699",
        "s": "0x7756145d26b4496e0a0a83870cc52d9a195c4017e712b344e1a2a09811832b07",
        "chainId": "0x82bc",
        "type": "0x0"
      }
    ],
    "uncles": [],
    "quorumCertificate": {
      "signature": "0xb6b62fb4c527863d9e0d8f4335cd4beceace8ea2fa37dae18c62755d599dd59934a23a03ba66e4e876449e853b345697164b9e1b9c12676abf98111a59d449960d61b6155ab38b32556021832aef440fffa355503b01ee83cfa6ba62680f1fc5",
      "cosigned": "[1, 0, 1, 1]",
      "view": "0x4f60",
      "block_hash": "0x50b3b76c3a4f19ac20e498744d8e0ff9a110b9130acb3ba786c80c26738ee9ae"
    }
  },
  "id": "1"
}
```

# Arguments

| Parameter | Type   | Required | Description                  |
|-----------|--------|----------|------------------------------|
| `id`      | string | Required | `"1"`                        |
| `jsonrpc` | string | Required | `"2.0"`                      |
| `method`  | string | Required | `"eth_getBlockByNumber"`     |
| `params`  | array  | Required  | `[ block_number, hydrated ]` |

