# Title

CreateTransaction

# Keywords

transaction,create

# Description

Create a new Transaction object and send it to the network to be processed. 

## Transaction Parameters

| Parameter   | Type    | Required | Description                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | ------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `version`   | number  | Required | `(MSG_VERSION & 0xffff) | (chain_id << 16)`. `MSG_VERSION` is 1. <br/><br/> **-** For mainnet, it is `65537`. <br/> **-** For Developer testnet, it is `21823489`.                                                                                                                                                                                                                                               |
| `nonce`     | number  | Required | Transaction nonce. The value should be `current account nonce + 1`. Zilliqa-native nonces start at 1.                                                                                                                                                                                     |
| `toAddr`    | string  | Required | Recipient's account address. For Zilliqa 2, this need not be checksummed and can be either a hex address (`4BAF5faDA8e5Db92C3d3242618c5B47133AE003C`) with or without a leading `0x` and with or without a checksum, or a bech32 address (`zil1fwh4ltdguhde9s7nysnp33d5wye6uqpugufkz7`). For deploying new contracts, set this to `"0000000000000000000000000000000000000000"`.                                                                                                                                                                   |
| `amount`    | string  | Required | Transaction amount to be sent to the recipent's address. This is measured in the smallest price unit **Qa** (or 10^-12 **Zil**) in Zilliqa.                                                                                                                                                                                                                                                                                                     |
| `pubKey`    | string  | Required | Sender's public key of 33 bytes, in hex, without leading `0x`.                                                                                                                                                                                                                                                                                                                                                                                                                |
| `gasPrice`  | string  | Required | An amount that a sender is willing to pay per unit of gas for processing this transaction. This is measured in the smallest price unit **Qa** (or 10^-12 **Zil**) in Zilliqa.                                                                                                                                                                                                                                                                   |
| `gasLimit`  | string  | Required | Gas limit, in gas units.                                                                                                                       |
| `code`      | string  | Optional | When deploying a new smart contract, the code for the contract. Otherwise, empty or absent.                                                                                                                                                                                                                                                                                                                                                             |
| `data`      | string  | Optional | `String`-ified JSON object specifying the transition parameters to be passed to a specified smart contract. <br/><br/> - When creating a contract, this JSON object contains the **init** parameters. <br/> - When calling a contract, this JSON object contains the **msg** parameters. <br/><br/> _For more information on the Scilla interpreter, please visit the [documentation](https://scilla.readthedocs.io/en/latest/interface.html)._ |
| `signature` | string  | Required | A hex-encoded, no prefixing `0x`, **EC-Schnorr** signature of 64 bytes of the entire Transaction object; see below.                                                                                                                                                                                                                                                                                                                                                   |

Additional fields may be specified, but will be ignored.

## Signature computation

To compute the signature of a transaction, we first encode the transaction as a protobuf using the declaration:

```
message ProtoTransactionCoreInfo
{
    uint32 version         = 1;
    oneof oneof2 { uint64 nonce = 2; }
    bytes toaddr           = 3;
    ByteArray senderpubkey = 4;
    ByteArray amount       = 5;
    ByteArray gasprice     = 6;
    uint64 gaslimit        = 7;
    oneof oneof8 { bytes code = 8; }
    oneof oneof9 { bytes data = 9; }
}
```

Byte arrays are stored big endian. Take the encoding of this structure
and call it `msgBytes`. Examples of protobuf encoding can be obtained
from the Zilliqa rust (`zilliqa-rs`), golang (`gozilliqa-sdk`) and Javascript (`zilliqa-js`) SDKs.

Now take the public key as bytes, `publicKeyBytes`.

Invent a random `k`, and in `secp256k1`, with `G` the generator of the group and `N` its modulus and using '.' for concatenation and '*' for multiplication, compute:

```
Q = compress( k * G )
r = SHA256( Q . publicKeyBytes . msgBytes ) mod N
s = k - (r * privateKey)
```

Now represent `r` and `s` as big-endian 0-padded 32-byte byte arrays, and concatenate them - `r . s` - to form an EC-Schnorr signature for the transaction, encode it in hex with no leading `0x`, and put it in the `signature` field eg. `9fe2d73db6cc4635c54dfdeb6c6965ed14a172ac5ba4dc77f9bdfe230394d62b47c8c5702cb757b460b2fc407090ed2c1d6732855ac891fea46ca3e86ab6ec4a`.

# Curl

With private key `0x2`:

```shell
    curl -d '{
        "id": "1",
        "jsonrpc": "2.0",
        "method": "CreateTransaction",
        "params": [
        {
            "amount": "10000000",
            "code": "",
            "data": "",
            "gasLimit": "50000",
            "gasPrice": "2000000016",
            "nonce": 4,
            "priority": false,
            "pubKey": "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            "signature": "9fe2d73db6cc4635c54dfdeb6c6965ed14a172ac5ba4dc77f9bdfe230394d62b47c8c5702cb757b460b2fc407090ed2c1d6732855ac891fea46ca3e86ab6ec4a",
            "toAddr": "4BAF5faDA8e5Db92C3d3242618c5B47133AE003C",
            "version": 45875201
        }
    ]
    }' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```


# NodeJs

```js
let tx = zilliqa.transactions.new({
  version: 65537,
  toAddr: "0x4BAF5faDA8e5Db92C3d3242618c5B47133AE003C",
  amount: units.toQa("1", units.Units.Zil),
  gasPrice: units.toQa("2000", units.Units.Li),
  gasLimit: Long.fromNumber(50),
});

// Send a transaction to the network
tx = await zilliqa.blockchain.createTransaction(tx);
console.log(tx.id);
```

# Java

```java
public class App {
    public static void main(String[] args) throws IOException {
        Wallet wallet = new Wallet();
        wallet.setProvider(new HttpProvider("{{ _api_url }}"));
        wallet.addByPrivateKey("e19d05c5452598e24caad4a0d85a49146f7be089515c905ae6a19e8a578a6930");
        Transaction transaction = Transaction.builder()
                .version(String.valueOf(pack(1, 8)))
                .toAddr("4baf5fada8e5db92c3d3242618c5b47133ae003c".toLowerCase())
                .senderPubKey("0246e7178dc8253201101e18fd6f6eb9972451d121fc57aa2a06dd5c111e58dc6a")
                .amount("1000000000000")
                .gasPrice("2000000000")
                .gasLimit("50")
                .code("")
                .data("")
                .provider(new HttpProvider("{{ _api_url }}"))
                .build();
        transaction = wallet.sign(transaction);
        // Send a transaction to the network
        HttpProvider.CreateTxResult result = TransactionFactory.createTransaction(transaction);
        System.out.println(result);
    }
}
```

# Python

```python
from pyzil.account import Account
from pyzil.zilliqa import chain
chain.set_active_chain(chain.MainNet)

account = Account(private_key="0xe19d05c5452598e24caad4a0d85a49146f7be089515c905ae6a19e8a578a6930")

payload = {
    "to_addr": "0x4BAF5faDA8e5Db92C3d3242618c5B47133AE003C",
    "amount": "1000000000000",
    "nonce": account.get_nonce() + 1,
    "gas_price": "2000000000",
    "gas_limit": 50,
    "code": "",
    "data": "",
    "priority": False,
}

params = chain.active_chain.build_transaction_params(account.zil_key, **payload)
txn_info = chain.active_chain.api.CreateTransaction(params)
print(txn_info)
```

# Go

```go
func SendTransaction() {
    wallet := NewWallet()
    wallet.AddByPrivateKey("e19d05c5452598e24caad4a0d85a49146f7be089515c905ae6a19e8a578a6930")
    provider := provider2.NewProvider("{{_api_url}}")

    tx := &transaction.Transaction{
        Version:      strconv.FormatInt(int64(util.Pack(1, 1)), 10),
        SenderPubKey: "0246E7178DC8253201101E18FD6F6EB9972451D121FC57AA2A06DD5C111E58DC6A",
        ToAddr:       "4BAF5faDA8e5Db92C3d3242618c5B47133AE003C",
        Amount:       "10000000",
        GasPrice:     "2000000000",
        GasLimit:     "50",
        Code:         "",
        Data:         "",
        Priority:     false,
    }

    err := wallet.Sign(tx, *provider)
    if err != nil {
        fmt.Println(err)
    }

    rsp := provider.CreateTransaction(tx.ToTransactionPayload())

    if rsp.Error != nil {
        fmt.Println(rsp.Error)
    } else {
        result := rsp.Result.(map[string]interface{})
        hash := result["TranID"].(string)
        fmt.Printf("hash is %s\n", hash)
        tx.Confirm(hash, 1000, 3, provider)
    }
}
```

# Response

```json
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": {
    "Info": "Txn processed",
    "TranID": "2d1eea871d8845472e98dbe9b7a7d788fbcce226f52e4216612592167b89042c"
  }
}
```

# Arguments

| Parameter | Type   | Required | Description                                              |
| --------- | ------ | -------- | -------------------------------------------------------- |
| `id`      | string | Required | `"1"`                                                    |
| `jsonrpc` | string | Required | `"2.0"`                                                  |
| `method`  | string | Required | `"CreateTransaction"`                                    |
| `params`  | N/A    | Required | See table above for the Transaction parameters required: |

