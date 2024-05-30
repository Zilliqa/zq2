# Title

GetContractAddressFromTransactionID

# Keywords

contract,address,get,transaction,id

# Description

Returns a smart contract address of 20 bytes. This is represented as a `String`.

**NOTE:** This only works for contract deployment transactions.

# Curl

```
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetContractAddressFromTransactionID",
    "params": ["AAF3089596437A7C6984FA2627B6F38B5F5B80FAEAAC6993C2E82C6A8EE2615E"]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# NodeJs

```js
const contractAddress =
  await zilliqa.blockchain.getContractAddressFromTransactionID(
    "AAF3089596437A7C6984FA2627B6F38B5F5B80FAEAAC6993C2E82C6A8EE2615E"
  );
console.log(contractAddress.result);
```

# Java

```java
public class App {
    public static void main(String[] args) throws IOException {
        HttpProvider client = new HttpProvider("{{ _api_url }}");
        Rep<String> contractAddress = client.getContractAddressFromTransactionID("AAF3089596437A7C6984FA2627B6F38B5F5B80FAEAAC6993C2E82C6A8EE2615E");
        System.out.println(new Gson().toJson(contractAddress));
    }
}
```

# Python

```python
from pyzil.zilliqa import chain
chain.set_active_chain(chain.MainNet)
print(chain.active_chain.api.GetContractAddressFromTransactionID(
     "AAF3089596437A7C6984FA2627B6F38B5F5B80FAEAAC6993C2E82C6A8EE2615E"
))
```

# Go

```go
func GetContractAddressFromTransactionID() {
    provider := NewProvider("{{ _api_url }}")
    response := provider.GetContractAddressFromTransactionID("AAF3089596437A7C6984FA2627B6F38B5F5B80FAEAAC6993C2E82C6A8EE2615E")
    result, _ := json.Marshal(response)
    fmt.Println(string(result))
}
```

# Response

```json
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": "c458f39c106582c1a49bac6bc76ec603e2ae0497"
}
```

# Arguments

| Parameter | Type   | Required | Description                                                                                                       |
| --------- | ------ | -------- | ----------------------------------------------------------------------------------------------------------------- |
| `id`      | string | Required | `"1"`                                                                                                             |
| `jsonrpc` | string | Required | `"2.0"`                                                                                                           |
| `method`  | string | Required | `"GetSmartContracts"`                                                                                             |
| `params`  | string | Required | A Transaction ID of 32 bytes. <br/> Example: `"AAF3089596437A7C6984FA2627B6F38B5F5B80FAEAAC6993C2E82C6A8EE2615E"` |

