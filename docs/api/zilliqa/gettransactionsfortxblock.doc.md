# Title

GetTransactionsForTxBlock

# Keywords

txn,get,transactions,block

# Description

Returns the validated transactions included within a specified final transaction block as an array of length 1, since there are no more shards or DS committee.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetTransactionsForTxBlock",
    "params": ["2"]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# NodeJs

```js
const txns = await zilliqa.blockchain.getTransactionsForTxBlock("2");
console.log(txns.result);
```

# Java

```java
public class App {
    public static void main(String[] args) throws IOException {
        HttpProvider client = new HttpProvider("{{ _api_url }}");
        Rep<List<List<String>>> transactionList = client.getTransactionsForTxBlock("2");
        System.out.println(new Gson().toJson(transactionList));
    }
}
```

# Python

```python
from pyzil.zilliqa import chain
chain.set_active_chain(chain.MainNet)
print(chain.active_chain.api.GetTransactionsForTxBlock("2"))
```

# Go

```go
func GetTransactionsForTxBlock() {
    provider := NewProvider("{{ _api_url }}")
    response := provider.GetTransactionsForTxBlock("1")
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
    [
      "2398362e23635582ed58f83dbcff7af2d8ccb017f6ff2bb49d343e7b8bb8bd68",
      "3f337358c07c4e984714da804985f23eca9a9dd14aa8ba1ddd89583cf5110bf0",
      "35823ae3377b91792fa34fa5577fa267385374e08da51555f63a537942d5adb6",
      "04e5f20de988a4afea17408c87a8d4f73d14082f13df552cce849e4ddd4cfffc"
    ],
  ]
}
```

# Arguments

| Parameter | Type   | Required | Description                                        |
| --------- | ------ | -------- | -------------------------------------------------- |
| `id`      | string | Required | `"1"`                                              |
| `jsonrpc` | string | Required | `"2.0"`                                            |
| `method`  | string | Required | `"GetTransactionsForTxBlock"`                      |
| `params`  | string | Required | Specifed TX block number to return. Example: `"2"` |





