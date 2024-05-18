# Title

GetNumTxBlocks

# Keywords

get,number,count,tx,blocks

# Description

Returns the current number of Transaction blocks in the network. This is represented as a `String`.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetNumTxBlocks",
    "params": [""]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# NodeJs

```js
const numTxBlock = await zilliqa.blockchain.getNumTxBlocks();
console.log(numTxBlock.result);
```

# Java

```java
public class App {
    public static void main(String[] args) throws IOException {
        HttpProvider client = new HttpProvider("{{ _api_url }}");
        Rep<String> numTxBlocks = client.getNumTxBlocks();
        System.out.println(new Gson().toJson(numTxBlocks));
    }
}
```

# Python

```python
from pyzil.zilliqa import chain
chain.set_active_chain(chain.MainNet)
print(chain.active_chain.api.GetNumTxBlocks())
```

# Go

```go
func GetNumTxBlocks() {
    provider := NewProvider("{{ _api_url }}")
    response := provider.GetNumTxBlocks()
    result, _ := json.Marshal(response)
    fmt.Println(string(result))
 }
 ```

# Response

```json
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": "589790"
}
```

# Arguments


| Parameter | Type   | Required | Description        |
| --------- | ------ | -------- | ------------------ |
| `id`      | string | Required | `"1"`              |
| `jsonrpc` | string | Required | `"2.0"`            |
| `method`  | string | Required | `"GetNumTxBlocks"` |
| `params`  | string | Required | Empty string `""`  |
