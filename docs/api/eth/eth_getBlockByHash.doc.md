# Title

eth_getBlockByHash

# Keywords

block,get,hash

# Description

Returns information about a block by block hash

## Parameters

{{ macro_blockhash }}
{{ macro_hydrated }}

## Results

An array of blocks.

{{ macro_returned_block }}

If `hydrated` is `true`, blocks contain returned transactions.

{{ macro_returned_transaction }}

# Curl

```sh
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "eth_getBlockByHash",
    "params": [ "0x0cea164183f2d8409fe034fddd0d27016a0f49cf895d3b2a9bd92c7cca3c47c2", true ]}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json

  "jsonrpc": "2.0",
  "result": {
    "number": "0xb10",
    "hash": "0x0cea164183f2d8409fe034fddd0d27016a0f49cf895d3b2a9bd92c7cca3c47c2",
    "parentHash": "0x328ade4282f75c0e241c6226206b857ee9b3a46cebef414ba8e71c58de9567ad",
    "nonce": "0x0000000000000000",
    "sha3Uncles": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "transactionsRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "stateRoot": "0x28556763de24be1a4579af01d482a690fb5f5529f03ffdc42e04498b3d37802c",
    "receiptsRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "miner": "0x6813eb9362372eef6200f3b1dbc3f819671cba69",
    "difficulty": "0x0",
    "totalDifficulty": "0x0",
    "extraData": "0x",
    "gasLimit": "0x501bd00",
    "gasUsed": "0x8484",
    "timestamp": "0x666c1946",
    "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "size": "0x0",
    "transactions": [
      {
        "blockHash": "0x0cea164183f2d8409fe034fddd0d27016a0f49cf895d3b2a9bd92c7cca3c47c2",
        "blockNumber": "0xb10",
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
    "uncles": []
  },
  "id": "1"
}
```

# Arguments

| Parameter | Type   | Required | Description                  |
|-----------|--------|----------|------------------------------|
| `id`      | string | Required | `"1"`                        |
| `jsonrpc` | string | Required | `"2.0"`                      |
| `method`  | string | Required | `"eth_getBlockByHash"`     |
| `params`  | array  | Required  | `[ block_hash, hydrated ]` |


