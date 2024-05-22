# Title

GetPrevDSDifficulty

# Keywords

get,difficulty,DS

# Status

NeverImplemented

# Description

Returns the minimum DS difficulty of the previous block. This is represented as an `Number`.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetPrevDSDifficulty",
    "params": [""]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# NodeJs

```js
const prevDSDifficulty = await zilliqa.blockchain.getPrevDSDifficulty();
console.log(prevDSDifficulty.result);
```

# Java

```java
public class App {
    public static void main(String[] args) throws IOException {
        HttpProvider client = new HttpProvider("{{ _api_url }}");
        Rep<Integer> prevDSDifficulty = client.getPrevDSDifficulty();
        System.out.println(new Gson().toJson(prevDSDifficulty));
    }
}
```

# Python

```python
from pyzil.zilliqa import chain
chain.set_active_chain(chain.MainNet)
print(chain.active_chain.api.GetPrevDSDifficulty())
```

# Go

```go
func GetPrevDSDifficulty() {
    provider := NewProvider("{{ _api_url }}")
    response := provider.GetPrevDSDifficulty()
    result, _ := json.Marshal(response)
    fmt.Println(string(result))
}
```

# Response

```json
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": 149
}
```

# Arguments

| Parameter | Type   | Required | Description             |
| --------- | ------ | -------- | ----------------------- |
| `id`      | string | Required | `"1"`                   |
| `jsonrpc` | string | Required | `"2.0"`                 |
| `method`  | string | Required | `"GetPrevDSDifficulty"` |
| `params`  | string | Required | Empty string `""`       |
