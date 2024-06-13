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


# blocknumber

### Block Number

The block number can be:

 * A hex number in a string: eg. `"0x800"`
 * A block hash as a string eg. `"0xf77e76c25038b0be1fbd12a4f3e404173802bf0c9a9e62deef7949201d59ebfb`
 * `"earliest"` for the earliest block
 * `"latest"` for the latest block
 * `"safe"` for the last block known to be safe.
 * `"finalized"` for the latest finalized block - in Zilliqa 2 this is the same as the `safe` block.
 * `"pending"` is a synonym for `latest`.

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

# hydrated

### Hydrated

If this parameter is `true`, we return transaction objects. If `false`, we return a list of hashes.

# returned_transaction

### Transaction

| Parameter       | Type   | Required | Description                                                                        |
|-----------------|--------|----------|------------------------------------------------------------------------------------|
| `baseFeePerGas` | string | required | Base fee in hex format (all ZQ2 blocks are treated as post-EIP-1559)               |
| `difficulty`    | string | required | Difficulty, as hex. Always 0 (`"0x0"`)                                             |
| `extraData`     | string | required | The extra data field of this block                                                 |
| `gasLimit`      | string | required | Gas limit for this block as a hex number.                                          |
| `gasUsed`       | string | required | Gas used in this block as a hex number.                                            |
| `hash`          | string | required | Block hash as a hex number                                                         |
| `logsBloom`
| `from`          | string | required | The address of the sender of this message call                                     |
| `to`            | string | optional | The recipient address                                                              |
| `gas`           | string | optional | Gas to give this message call, as a hex number in a string                         |
| `gas_price`     | string | optional | Gas price to give this message call as a hex number in a string                    |
| `data`          | string | required | The calldata                                                                       |
| `value`         | string | optional | Value to send with this call, as a hex number in a string. Assumed 0 if not given. |
