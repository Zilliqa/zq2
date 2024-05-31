# Title

GetCurrentMiniEpoch

# Keywords

mini,epoch,get,current

# Description

Returns the current TX block number of the network. This is represented as a `String`.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetCurrentMiniEpoch",
    "params": [""]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# NodeJs

```js
const currentMiniEpoch = await zilliqa.blockchain.getCurrentMiniEpoch();
console.log(currentMiniEpoch.result);
```

# Java


```java
public class App {
    public static void main(String[] args) throws IOException {
        HttpProvider client = new HttpProvider("{{ _api_url }}");
        Rep<String> currentMiniEpoch = client.getCurrentMiniEpoch();
        System.out.println(new Gson().toJson(currentMiniEpoch));
    }
}
```

# Python

```python
from pyzil.zilliqa import chain
chain.set_active_chain(chain.MainNet)
print(chain.active_chain.api.GetCurrentMiniEpoch())
```

# Go

```go
func GetCurrentMiniEpoch() {
    provider := NewProvider("{{ _api_url }}")
    response := provider.GetCurrentMiniEpoch()
    result, _ := json.Marshal(response)
    fmt.Println(string(result))
}
```

# Response

```json
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": "589793"
}
```

# Arguments

| Parameter | Type   | Required | Description             |
| --------- | ------ | -------- | ----------------------- |
| `id`      | string | Required | `"1"`                   |
| `jsonrpc` | string | Required | `"2.0"`                 |
| `method`  | string | Required | `"GetCurrentMiniEpoch"` |
| `params`  | string | Required | Empty string `""`       |
