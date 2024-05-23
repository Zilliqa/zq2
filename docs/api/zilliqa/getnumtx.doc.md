# Title

GetNumTransactions

# Keywords

get,transactions,count

# Description

Returns the current number of validated Transactions in the network. This is represented as a `String.`

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetNumTransactions",
    "params": [""]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# NodeJs

```js
const numTransactions = await zilliqa.blockchain.getNumTransactions();
console.log(numTransactions.result);
```

# Java

```java
public class App {
    public static void main(String[] args) throws IOException {
        HttpProvider client = new HttpProvider("{{ _api_url }}");
        Rep<String> numTransactions = client.getNumTransactions();
        System.out.println(new Gson().toJson(numTransactions));
    }
}
```

# Python

```python
from pyzil.zilliqa import chain
chain.set_active_chain(chain.MainNet)
print(chain.active_chain.api.GetNumTransactions())
```

# Go

```go
func GetNumTransactions() {
    provider := NewProvider("{{ _api_url }}")
    response := provider.GetNumTransactions()
    result, _ := json.Marshal(response)
    fmt.Println(string(result))
}
```

# Response

```json
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": "4350695"
}
```

# Arguments

| Parameter | Type   | Required | Description            |
| --------- | ------ | -------- | ---------------------- |
| `id`      | string | Required | `"1"`                  |
| `jsonrpc` | string | Required | `"2.0"`                |
| `method`  | string | Required | `"GetNumTransactions"` |
| `params`  | string | Required | Empty string `""`      |
