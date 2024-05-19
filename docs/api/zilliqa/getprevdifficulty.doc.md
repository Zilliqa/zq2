# Title

GetPrevDifficulty

# Keywords

get,difficulty

# Status

NeverImplemented

# Description

Returns the minimum shard difficulty of the previous block. This is represented as an `Number`. This is no longer required in Zilliqa 2.0 because of the change to proof of stake consensus.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetPrevDifficulty",
    "params": [""]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# NodeJs

```js
const prevDifficulty = await zilliqa.blockchain.getPrevDifficulty();
console.log(prevDifficulty.result);
```

# Java

```java
public class App {
    public static void main(String[] args) throws IOException {
        HttpProvider client = new HttpProvider("{{ _api_url }}");
        Rep<Integer> prevDifficulty = client.getPrevDifficulty();
        System.out.println(new Gson().toJson(prevDifficulty));
    }
}
```

# Python

```python
from pyzil.zilliqa import chain
chain.set_active_chain(chain.MainNet)
print(chain.active_chain.api.GetPrevDifficulty())
```

# Go

```go
func GetPrevDifficulty() {
    provider := NewProvider("{{ _api_url }}}")
    response := provider.GetPrevDifficulty()
    result, _ := json.Marshal(response)
    fmt.Println(string(result))
}
```

# Response

```json
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": 91
}
```

# Arguments

| Parameter | Type   | Required | Description           |
| --------- | ------ | -------- | --------------------- |
| `id`      | string | Required | `"1"`                 |
| `jsonrpc` | string | Required | `"2.0"`               |
| `method`  | string | Required | `"GetPrevDifficulty"` |
| `params`  | string | Required | Empty string `""`     |
