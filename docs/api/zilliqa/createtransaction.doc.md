# Title

CreateTransaction

# Keywords

transaction,create

# Description

Create a new Transaction object and send it to the network to be processed. 

## Transaction Parameters

| Parameter   | Type    | Required | Description                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | ------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `version`   | number  | Required | The decimal conversion of the bitwise concatenation of `CHAIN_ID` and `MSG_VERSION` parameters. <br/><br/> **-** For mainnet, it is `65537`. <br/> **-** For Developer testnet, it is `21823489`.                                                                                                                                                                                                                                               |
| `nonce`     | number  | Required | A transaction counter in each account. This prevents replay attacks where a transaction sending eg. 20 coins from A to B can be replayed by B over and over to continually drain A's balance. <br/><br/> It's value should be `Current account nonce + 1`.                                                                                                                                                                                      |
| `toAddr`    | string  | Required | Recipient's account address. This is represented as a `String`. <br/><br/> **NOTE:** This address has to be checksummed for every 6th bit, but the "0x" prefix is optional. <br/><br/> For deploying new contracts, set this to `"0000000000000000000000000000000000000000"`.                                                                                                                                                                   |
| `amount`    | string  | Required | Transaction amount to be sent to the recipent's address. This is measured in the smallest price unit **Qa** (or 10^-12 **Zil**) in Zilliqa.                                                                                                                                                                                                                                                                                                     |
| `pubKey`    | string  | Required | Sender's public key of 33 bytes.                                                                                                                                                                                                                                                                                                                                                                                                                |
| `gasPrice`  | string  | Required | An amount that a sender is willing to pay per unit of gas for processing this transaction. This is measured in the smallest price unit **Qa** (or 10^-12 **Zil**) in Zilliqa.                                                                                                                                                                                                                                                                   |
| `gasLimit`  | string  | Required | The amount of gas units that is needed to be process this transaction.                                                                                                                       |
| `code`      | string  | Optional | The smart contract source code. This is present only when deploying a new contract.                                                                                                                                                                                                                                                                                                                                                             |
| `data`      | string  | Optional | `String`-ified JSON object specifying the transition parameters to be passed to a specified smart contract. <br/><br/> - When creating a contract, this JSON object contains the **init** parameters. <br/> - When calling a contract, this JSON object contains the **msg** parameters. <br/><br/> _For more information on the Scilla interpreter, please visit the [documentation](https://scilla.readthedocs.io/en/latest/interface.html)._ |
| `signature` | string  | Required | An **EC-Schnorr** signature of 64 bytes of the entire Transaction object as stipulated above.                                                                                                                                                                                                                                                                                                                                                   |
| `priority`  | boolean | Optional | A flag for this transaction to be processed by the DS committee. Now ignored.                                                                                                             |


# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "CreateTransaction",
    "params": [{
      "version": 65537,
      "nonce": 1,
          "toAddr": "0x4BAF5faDA8e5Db92C3d3242618c5B47133AE003C",
          "amount": "1000000000000",
          "pubKey": "0205273e54f262f8717a687250591dcfb5755b8ce4e3bd340c7abefd0de1276574",
          "gasPrice": "2000000000",
          "gasLimit": "50",
          "code": "",
          "data": "",
          "signature": "29ad673848dcd7f5168f205f7a9fcd1e8109408e6c4d7d03e4e869317b9067e636b216a32314dd37176c35d51f9d4c24e0e519ba80e66206457c83c9029a490d",
          "priority": false
        }]
}' -H "Content-Type: application/json" -X POST "{{_api_url}}"
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
    "Info": "Non-contract txn, sent to shard",
    /*
    Other possible Info:
    Contract Creation txn, sent to shard
    Contract Txn, Shards Match of the sender and reciever
    Contract Txn, Sent To Ds
    */
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
| `params`  | N/A    | Required | See table below for the Transaction parameters required: |

