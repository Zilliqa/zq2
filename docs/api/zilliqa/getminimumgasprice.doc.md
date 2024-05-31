# Title

GetMinimumGasPrice

# Keywords

gas,price,get,minimum

# Description

Returns the minimum gas price for this DS epoch, measured in the smallest price unit **Qa** (or 10^-12 **Zil**) in Zilliqa. This is represented as a `String`.

# Request

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetMinimumGasPrice",
    "params": [""]
}' -H "Content-Type: application/json" -X POST "{{_api_url}}"
```

# NodeJs

```js
const minimumGasPrice = await zilliqa.blockchain.getMinimumGasPrice();
console.log(minimumGasPrice.result);
```

# Java

```java
public class App {
    public static void main(String[] args) throws IOException {
        HttpProvider client = new HttpProvider("{{ _api_url }}");
        Rep<String> minimumGasPrice = client.getMinimumGasPrice();
        System.out.println(new Gson().toJson(minimumGasPrice));
    }
}
```

# Python

```python
from pyzil.zilliqa import chain
chain.set_active_chain(chain.MainNet)
print(chain.active_chain.api.GetMinimumGasPrice())
```

# Go

```go
func GetMinimumGasPrice() {
    provider := NewProvider("{{ _api_url }}")
    response := provider.GetMinimumGasPrice()
    result, _ := json.Marshal(response)
    fmt.Println(string(result))
}
```

# Response

```json
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": "2000000000"
}
```

# Arguments


| Parameter | Type   | Required | Description            |
| --------- | ------ | -------- | ---------------------- |
| `id`      | string | Required | `"1"`                  |
| `jsonrpc` | string | Required | `"2.0"`                |
| `method`  | string | Required | `"GetMinimumGasPrice"` |
| `params`  | string | Required | Empty string `""`      |
