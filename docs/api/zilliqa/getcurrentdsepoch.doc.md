# Title

GetCurrentDSEpoch

# Keywords

DS,epoch,get,current

# Status

NotYetDocumented

# Description

Returns the current number of DS blocks in the network. This is represented as a
`String`.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetCurrentDSEpoch",
    "params": [""]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Nodejs

```js
const currentDSEpoch = await zilliqa.blockchain.getCurrentDSEpoch();
console.log(currentDSEpoch.result);
```

# Java

```java
public class App {
    public static void main(String[] args) throws IOException {
        HttpProvider client = new HttpProvider("{{ _api_url }}");
        Rep<String> currentDSEpoch = client.getCurrentDSEpoch();
        System.out.println(new Gson().toJson(currentDSEpoch));
    }
}
```

# Python

```python
from pyzil.zilliqa import chain
chain.set_active_chain(chain.MainNet)
print(chain.active_chain.api.GetCurrentDSEpoch())
```

# Go

```go
func GetCurrentDSEpoch() {
  provider := NewProvider("{{ _api_url }}")
  response := provider.GetCurrentDSEpoch()
  result, _ := json.Marshal(response)
  fmt.Println(string(result))
}
```

# Response

```json
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": "5898"
}
```

# Arguments

| Parameter | Type   | Required | Description           |
| --------- | ------ | -------- | --------------------- |
| `id`      | string | Required | `"1"`                 |
| `jsonrpc` | string | Required | `"2.0"`               |
| `method`  | string | Required | `"GetCurrentDSEpoch"` |
| `params`  | string | Required | Empty string `""`     |
