# Title

GetTxnBodiesForTxBlockEx

# Keywords

txn,get,bodies,tx,block,transaction

# Description

Returns the validated transactions (in verbose form) included within a specified final transaction block.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetTxnBodiesForTxBlock",
    "params": ["2"]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# NodeJs

```js
const txns = await zilliqa.blockchain.getTxnBodiesForTxBlock("2");
console.log(txns.result);
```

# Java

```java
public class App {
    public static void main(String[] args) throws IOException {
        HttpProvider client = new HttpProvider("{{ _api_url }}");
        Rep<List<List<String>>> transactionList = client.getTxnBodiesForTxBlock("2");
        System.out.println(new Gson().toJson(transactionList));
    }
}
```

# Python

```python
from pyzil.zilliqa import chain
chain.set_active_chain(chain.MainNet)
print(chain.active_chain.api.GetTxnBodiesForTxBlock("2"))
```


# Go

```go
func GetTxnBodiesForTxBlock() {
  provider := NewProvider("{{ _api_url }}")
  response := provider.GetTxnBodiesForTxBlock("1")
  result, _ := json.Marshal(response)
  fmt.Println(string(result))
}
```

# Response

```json
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": [
    {
      "ID": "562432bc45c14c788c43c469756453375cbe80cc9c1bc30fa0dfbe77e4220221",
      "amount": "1",
      "gasLimit": "1",
      "gasPrice": "1000000000",
      "nonce": "1",
      "receipt": {
        "cumulative_gas": "1",
        "epoch_num": "2",
        "success": true
      },
      "senderPubKey": "0x03393C256D33127CE18FC3646EC88FCE62DBF661300B4017E2FE57E8023B55BCFE",
      "signature": "0xCC12816DCE156FECFA1D6EF129D13FA2A5677E159CDF0CAFADF2CD33FBA0D239EE1284D4083BFBA4B895B97419FE78AB249C99AA7A7B7F314F17D353F44E784D",
      "toAddr": "b07065cfde6060ad36af3913c65bfb04211608d1",
      "version": "131073"
    },
    {
      "ID": "9ebc07e3e15b08dd82b2f2d57eead1b7dea4d06bef33364bbec5f80fc1d1d130",
      "amount": "2",
      "gasLimit": "1",
      "gasPrice": "1000000000",
      "nonce": "2",
      "receipt": {
        "cumulative_gas": "1",
        "epoch_num": "2",
        "success": true
      },
      "senderPubKey": "0x03393C256D33127CE18FC3646EC88FCE62DBF661300B4017E2FE57E8023B55BCFE",
      "signature": "0x846D90B698B4739979AB8B7F25BDEE5125A36447770D4AC6386606ACD25704747B38DEDE85F0AD26A663F0863199CA336109EB080A6354BB7CC3683C8FC47796",
      "toAddr": "b07065cfde6060ad36af3913c65bfb04211608d1",
      "version": "131073"
    }
  ]
}
```

# Arguments

| Parameter | Type   | Required | Description                                        |
| --------- | ------ | -------- | -------------------------------------------------- |
| `id`      | string | Required | `"1"`                                              |
| `jsonrpc` | string | Required | `"2.0"`                                            |
| `method`  | string | Required | `"GetTxnBodiesForTxBlock"`                         |
| `params`  | string | Required | Specifed TX block number to return. Example: `"2"` |

