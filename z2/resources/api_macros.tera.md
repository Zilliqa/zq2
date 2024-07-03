This file contains macros (each headed with an h1) used in documentation. The header itself is not reproduced.

Use these macros with {{ macro_<MacroName> }}. Macro names are lowercased.

# address

### Address

The address of the account to query as a hex value.

# transaction

### Transaction

| Parameter   | Type   | Required | Description                                                                        |
|-------------|--------|----------|------------------------------------------------------------------------------------|
| `from`      | string | required | The address of the sender of this message call                                     |
| `to`        | string | optional | The recipient address                                                              |
| `gas`       | string | optional | Gas to give this message call, as a hex number in a string                         |
| `gas_price` | string | optional | Gas price to give this message call as a hex number in a string                    |
| `data`      | string | required | The calldata                                                                       |
| `value`     | string | optional | Value to send with this call, as a hex number in a string. Assumed 0 if not given. |


# blockhash

### Block hash

A block hash, as a hex number in a JSON string eg. `"0xf77e76c25038b0be1fbd12a4f3e404173802bf0c9a9e62deef7949201d59ebfb"`

# blocknumber

### Block Number

The block number can be:

 * A hex number in a string: eg. `"0x800"`
 * A block hash as a string eg. `"0xf77e76c25038b0be1fbd12a4f3e404173802bf0c9a9e62deef7949201d59ebfb`
 * `"earliest"` for the earliest block
 * `"latest"` for the latest block
 * `"safe"` for the block that the node's high quorum certificate points to
 * `"finalized"` for the latest finalized block.
 * `"pending"` is the block that is about to be created.

# blocknumber_optional

### Block Number

The block number can be:

 * A hex number in a string: eg. `"0x800"`
 * A block hash as a string eg. `"0xf77e76c25038b0be1fbd12a4f3e404173802bf0c9a9e62deef7949201d59ebfb`
 * `"earliest"` for the earliest block
 * `"latest"` for the latest block
 * `"safe"` for the last block known to be safe.
 * `"finalized"` for the latest finalized block - in Zilliqa 2 this is the same as the `safe` block.
 * `"pending"` is a synonym for `latest`.

If the block number is not provided, `latest` is assumed.

# blockid

### Block ID

A block identifier, as specified by https://eips.ethereum.org/EIPS/eip-1898.

# hydrated

### Hydrated

If this parameter is `true`, we return transaction objects. If `false`, we return a list of hashes.

# returned_block

### Block

| Parameter                      | Type   | Required | Description                                                                              |
|--------------------------------|--------|----------|------------------------------------------------------------------------------------------|
| `hash`                         | string | required | Block hash as a hex number                                                               |
| `parentHash`                   | string | required | Hash of the parent of this block                                                         |
| `sha3Uncles`                   | string | required | Since zq2 has no uncles, this field is always 0x0                                        |
| `miner`                        | string | required | Set to the address that received the reward for generating this block                    |
| `stateRoot`                    | string | required | The state root hash for this block                                                       |
| `transactionsRoot`             | string | required | Always 0x0                                                                               |
| `receiptsRoot`                 | string | required | Always 0x0                                                                               |
| `logsBloom`                    | string | required | Always 0x0                                                                               |
| `difficulty`                   | number | required | 0                                                                                        |
| `number`                       | string | required | Block number in hex                                                                      |
| `gasLimit`                     | string | required | Gas limit for this block, in hex                                                         |
| `gasUsed`                      | string | required | Gas used in this block, in hex                                                           |
| `timestamp`                    | string | required | Hex value of the number of seconds between the UNIX epoch and the creation of this block |
| `extraData`                    | string | required | Hex value of extra data for this block; currently always 0x0                             |
| `mixHash`                      | string | required | hex number, always 0x0                                                                   |
| `nonce`                        | string | required | hex number, always 0x0                                                                   |
| `totalDifficulty`              | number | required | 0                                                                                        |
| `size`                         | number | required | Always 0                                                                                 |
| `transactions`                 | array  | required | An array of either transaction hashes or returned transaction objects                    |
| `uncles`                       | array  | required | Always empty                                                                             |
| `quorum_certificate`           | object | required | zq2-specific quorum certificate                                                          |
| `aggregate_quorum_certificate` | object | optional | An aggregate quorum certificate, if one was attached to this block                       |

The `quorum_certificate` contains:

| Parameter   | Type   | Required | Description                                            |
|-------------|--------|----------|--------------------------------------------------------|
| `signature` | string | required | Hex string; the BLS aggregate signature of the block hash in this view |
| `cosigned`  | array |  required | An array of integers; `1` means this committee member participated in the signature, `0` that they did not |
| `view`      | string | required | Hex string; the view number for this QC |
| `block_hash` | string | rquired | Hex string; the block hash |

Sometimes, a quorum certificate cannot be established for a proposal due to validator failure or some other cause. When this happens, an `aggregate_quorum_certificate` appears in the next block, with the `quorum_certificate` providing a copy of the highest QC within this aggregate.

| Parameter   | Type   | Required | Description                                            |
|-------------|--------|----------|--------------------------------------------------------|
| `qcs`       | array | required | A vector of `quorum_certificate`s. |
| `signature` | string | required | Hex string; the BLS aggregate signature of the qcs in this aggregate |
| `cosigned`  | array |  required | An array of integers; `1` means this committee member participated in the signature, `0` that they did not |
| `view`      | string | required | Hex string; the view number for this QC |

We do not currently report:

  * `baseFeePerGas`
  * `withdrawalsRoot`
  * `blobGasUsed`
  * `excessBlobGas`
  * `parentBeaconBlockRoot`

# returned_transaction

### Returned transaction

| Parameter              | Type   | Required | Description                                                           |
|------------------------|--------|----------|-----------------------------------------------------------------------|
| `blockHash`            | string | required | Hash of the block in which this transaction appears                   |
| `blockNumber`          | string | required | Hex number of the block in which this transaction appears             |
| `from`                 | string | required | From address of this transaction                                      |
| `gas`                  | string | required | Hex number - the amount of gas used by this transaction               |
| `gasPrice`             | string | required | Hex number - the gas price charged for this transaction, per gas unit |
| `maxFeePerGas`         | string | optional | Hex number - max fee per gas for this transaction. See EIP-1559.      |
| `maxPriorityFeePerGas` | string | optional | Hex number - max priority fee per gas. See EIP-1559.                  |
| `hash`                 | string | required | The transaction hash for this transaction                             |
| `input`                | string | required | The input for this transaction                                        |
| `nonce`                | string | required | Hex number; the nonce for this transaction.                           |
| `to`                   | string | required | To address for this transaction                                       |
| `value`                | string | required | Hex number; the value sent with this transaction                      |
| `v`                    | string | required | Hex number; the `v` parameter for the signature for this transaction  |
| `r`                    | string | required | Hex number; the `r` parameter for the signature on this transaction   |
| `s`                    | string | required | Hex number; the `s` parameter for the signature on this transaction   |
| `chainId`              | string | optional | Hex number. The (EVM) chain id for this zq2 chain                     |
| `access_list`          | array  | optional | EIP-1559 access list.                                                 |
| `type`                 | string | required | Hex number; type of this transaction                                  |


# filter

### Filter

| Parameter   | Type   | Required | Description                                                            |
|-------------|--------|----------|------------------------------------------------------------------------|
| `fromBlock` | string | optional | Starting block number, inclusive; if not present, `latest` is assumed  |
| `toBlock`   | string | optional | Ending block number, inclusive; if not present, `latest` is assumed    |
| `address`   | string | optional | Contract address or list of addresses from which logs should originate |
| `topics`    | string | optional | Topic elements - see later                                             |
| `blockHash` | string | optional | If present, we search the specific block matching this hash            |

# topicspec

### Topic specifications

Topic elements represent an alternative that matches any of the contained topics.

Examples (from Erigon):

    * `[]`                          matches any topic list
    * `[[A]]`                       matches topic A in first position
    * `[[], [B]]` or `[None, [B]]`  matches any topic in first position AND B in second position
    * `[[A], [B]]`                  matches topic A in first position AND B in second position
    * `[[A, B], [C, D]]`            matches topic (A OR B) in first position AND (C OR D) in second position

# logobject

## Log object

| Parameter          | Type   | Required | Description                                                                               |
|--------------------|--------|----------|-------------------------------------------------------------------------------------------|
| `removed`          | bool   | required | Always `false`                                                                            |
| `logIndex`         | string | required | Hex string; the (0-based) index of this log within the current transaction receipt        |
| `transactionIndex` | string | required | Hex string; the (0-based) index of this transaction within the current block              |
| `transactionHash`  | string | required | Hash of the transaction that generated this log                                           |
| `blockHash`        | string | required | Hash of the block in which the transaction that generated this log appears                |
| `blockNumber`      | string | required | Hex string; the number of the block in which this transaction appears                     |
| `address`          | string | required | The address from which this log was emitted                                               |
| `data`             | string | required | Hex string; the data associated with this log entry                                       |
| `topics`           | string | required | An array containing the topics associated with this log entry, as an array of hex strings |
