# Title

GetDSBlockRate

# Keywords

DS,block,get,rate

# Status

NotYetDocumented

# Description

Returns the current Directory Service blockrate per second.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetDSBlockRate",
    "params": [""]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# NodeJs

```js
const dsBlockRate = await zilliqa.blockchain.getDSBlockRate();
console.log(dsBlockRate.result);
```

# Java

```java
public class App {
    public static void main(String[] args) throws IOException {
        HttpProvider client = new HttpProvider("{{ _api_url }}");
        Rep<Double> dsBlockRate = client.getDSBlockRate();
        System.out.println(new Gson().toJson(dsBlockRate));
    }
}
```

# Python

```python
from pyzil.zilliqa import chain
chain.set_active_chain(chain.MainNet)
print(chain.active_chain.api.GetDSBlockRate())
```

# Go

```go
func GetDSBlockRate() {
    provider := NewProvider("{{ _api_url }}")
    response := provider.GetDSBlockRate()
    result, _ := json.Marshal(response)
    fmt.Println(string(result))
}
```

# Response

```json
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": 0.00014142137245459714
}
```

# Arguments

| Parameter | Type   | Required | Description        |
| --------- | ------ | -------- | ------------------ |
| `id`      | string | Required | `"1"`              |
| `jsonrpc` | string | Required | `"2.0"`            |
| `method`  | string | Required | `"GetDSBlockRate"` |
| `params`  | string | Required | Empty string `""`  |
