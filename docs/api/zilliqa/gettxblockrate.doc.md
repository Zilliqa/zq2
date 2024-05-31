# Title

GetTxBlockRate

# Keywords

get,tx,transaction,block,rate

# Description

Returns the current Transaction blockrate per second for the network.

# Curl

 ```shell
 curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetTxBlockRate",
    "params": [""]
 }' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# NodeJs

```js
const txBlockRate = await zilliqa.blockchain.getTxBlockRate();
console.log(txBlockRate.result);
```

# Java

```java
public class App {
    public static void main(String[] args) throws IOException {
        HttpProvider client = new HttpProvider("{{ _api_url }}");
        Rep<Double> txBlockRate = client.getTxBlockRate();
        System.out.println(new Gson().toJson(txBlockRate));
    }
}
```

# Python

```python
from pyzil.zilliqa import chain
chain.set_active_chain(chain.MainNet)
print(chain.active_chain.api.GetTxBlockRate())
```

# Go

```go
func GetTxBlockRate() {
    provider := NewProvider("{{ _api_url }}")
    response := provider.GetTxBlockRate()
    result, _ := json.Marshal(response)
    fmt.Println(string(result))
}
```

# Response

```json
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": 0.014138050978963283
}
```

# Arguments

| Parameter | Type   | Required | Description        |
| --------- | ------ | -------- | ------------------ |
| `id`      | string | Required | `"1"`              |
| `jsonrpc` | string | Required | `"2.0"`            |
| `method`  | string | Required | `"GetTxBlockRate"` |
| `params`  | string | Required | Empty string `""`  |
