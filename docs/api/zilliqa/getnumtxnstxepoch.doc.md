# Title

GetNumTxnsTxEpoch

# Keywords

tx,count,get,number

# Description

Returns the number of validated transactions included in this Transaction epoch. This is represented as a `String`.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetNumTxnsTxEpoch",
    "params": [""]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# NodeJs

```js
const numTxnsTxEpoch = await zilliqa.blockchain.getNumTxnsTxEpoch();
console.log(numTxnsTxEpoch.result);
```

# Java

```java
public class App {
    public static void main(String[] args) throws IOException {
        HttpProvider client = new HttpProvider("{{ _api_url }}");
        Rep<String> numTxnsTxEpoch = client.getNumTxnsTxEpoch();
        System.out.println(new Gson().toJson(numTxnsTxEpoch));
    }
}
```

# Python

```python
from pyzil.zilliqa import chain
chain.set_active_chain(chain.MainNet)
print(chain.active_chain.api.GetNumTxnsTxEpoch())
```

# Go

```go
func GetNumTxnsTxEpoch() {
    provider := NewProvider("{{ _api_url }}")
    response := provider.GetNumTxnsTxEpoch()
    result, _ := json.Marshal(response)
    fmt.Println(string(result))
}
```

# Response


```json
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": "38"
}
```

# Arguments

| Parameter | Type   | Required | Description           |
| --------- | ------ | -------- | --------------------- |
| `id`      | string | Required | `"1"`                 |
| `jsonrpc` | string | Required | `"2.0"`               |
| `method`  | string | Required | `"GetNumTxnsTxEpoch"` |
| `params`  | string | Required | Empty string `""`     |


