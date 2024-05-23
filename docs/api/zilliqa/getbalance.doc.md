# Title

GetBalance

# Keywords

balance,zilliqa,get,account

# Description

- Returns the current `balance` of an account, measured in the smallest
  accounting unit **Qa** (or 10^-12 **Zil**). This is represented as a
  `String`.

- Returns the current `nonce` of an account. This is represented as a
  `Number`.

If the account does not exist, returns error code -5.

# Curl

```shell
curl -d '{
   "id": "1",
   "jsonrpc": "2.0",
     "method": "GetBalance",
     "params": ["1eefc4f453539e5ee732b49eb4792b268c2f3908"]
}' -H "Content-Type: application/json" -X POST "https://api.zq2-devnet.zilliqa.com/"
```

# NodeJs

```js
const balance = await zilliqa.blockchain.getBalance(
  "1eefc4f453539e5ee732b49eb4792b268c2f3908"
);
console.log(balance.result);
```

# Java

```java
public class App {
   public static void main(String[] args) throws IOException {
       HttpProvider client = new HttpProvider("{{_api_url}}");
       Rep<HttpProvider.BalanceResult> balance = client.getBalance("1eefc4f453539e5ee732b49eb4792b268c2f3908");
       System.out.println(new Gson().toJson(balance));
   }
}
```

# Python

```python
from pyzil.zilliqa import chain
chain.set_active_chain(chain.MainNet)
print(chain.active_chain.api.GetBalance("1eefc4f453539e5ee732b49eb4792b268c2f3908"))
```

# Go

```go
func TestGetBalance() {
  provider := NewProvider("https://api.zq2-devnet.zilliqa.com/")
  response := provider.GetBalance("9bfec715a6bd658fcb62b0f8cc9bfa2ade71434a")
  result, _ := json.Marshal(response)
  fmt.Println(string(result))
}
```

# Response

```json
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": {
    "balance": "18446744073637511711",
    "nonce": 16
  }
}
```

or, if the account does not exist:

```json
{"error":{"code":-5,"data":null,"message":"Account is not created"},"id":"1","jsonrpc":"2.0"}
```

# Arguments

| Parameter | Type   | Required | Description                                                                                                                                                                                              |
| --------- | ------ | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `id`      | string | Required | `"1"`                                                                                                                                                                                                    |
| `jsonrpc` | string | Required | `"2.0"`                                                                                                                                                                                                  |
| `method`  | string | Required | `"GetBalance"`                                                                                                                                                                                           |
| `params`  | string | Required | An User's account address of 20 bytes. <br/> Example: `"1eefc4f453539e5ee732b49eb4792b268c2f3908"` <br/><br/> Also supports Bech32 address <br/> Example: `"zil1rmhufazn2w09aeejkj0tg7fty6xz7wggup2tsh"` |
