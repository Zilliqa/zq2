# Title

GetNumDSBlocks

# Keywords

DS,get,blocks,count,number

# Status

NotDocumented

# Description

Returns the current number of validated Directory Service blocks in the network. This is represented as a `String`.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetNumDSBlocks",
    "params": [""]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# NodeJs

```js
const numDsBlock = await zilliqa.blockchain.getNumDSBlocks();
console.log(numDsBlock.result);
```

# Java

```java
public class App {
    public static void main(String[] args) throws IOException {
        HttpProvider client = new HttpProvider("{{ _api_url }}");
        Rep<String> numDSBlocks = client.getNumDSBlocks();
        System.out.println(new Gson().toJson(numDSBlocks));
    }
}
```

# Python

```python
from pyzil.zilliqa import chain
chain.set_active_chain(chain.MainNet)
print(chain.active_chain.api.GetNumDSBlocks())
```

# Go

```go
func GetNumDSBlocks() {
    provider := NewProvider("{{ _api_url }}")
    response := provider.GetNumDSBlocks()
    result, _ := json.Marshal(response)
    fmt.Println(string(result))
}
```

# Response

```json
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": "5899"
}
```

# Arguments

| Parameter | Type   | Required | Description        |
| --------- | ------ | -------- | ------------------ |
| `id`      | string | Required | `"1"`              |
| `jsonrpc` | string | Required | `"2.0"`            |
| `method`  | string | Required | `"GetNumDSBlocks"` |
| `params`  | string | Required | Empty string `""`  |

