# Title

GetTransaction

# Keywords

transaction,get,hash

# Description

Returns the details of a specified Transaction.
Querying for non-existent transactions or transactions that have not yet been mined will result in an error.

## Response Object

| Field | Type | Description |
| ----- | ---- | ----------- |
| `ID`  | Hex string without `0x` | The transaction hash. |
| `version` | Number as string | A 16 bit chain ID for the transaction, concatenated with a 16 bit type. Transaction types are provided in a table below. Transactions without a chain ID (such as some legacy Ethereum transactions) use a chain ID of 0. |
| `nonce` | Number as string | The transaction nonce. Transactions without a nonce (such as intershard transactions) will use a nonce of 0 here. |
| `toAddr` | Hex string without `0x` | The "to address" of the transaction. Transactions without a "to address" (such as contract creation Ethereum transactions) will use the zero address here. |
| `senderPubKey` | Hex string with `0x` | The public key of the sender of the transaction. All keys are encoded using the SEC1 compressed encoding scheme. Transactions without a sender (such as intershard transactions) will contain an empty string here. |
| `amount` | Number as string | The value of the transaction. This amount is always returned in units of Qa (10^-12 ZILs). For Zilliqa transactions, this means we return the exact amount that was passed into `CreateTransaction`. For Ethereum transactions, the true amount is truncated from 18 digits to 12.
| `signature` | Hex string with `0x` | The transaction signature. Zilliqa signatures are 64 bytes, consisting of `r` followed by `s`. Ethereum signatures are 65 bytes, consisting of `r`, followed by `s`, followed by the `v` value in 'Electrum' notation. Intershard transactions have no signature, so contain an empty string here.
| `receipt.accepted` | Optional boolean | If the transaction was a Zilliqa transaction and was a call to a Scilla contract, whether the called contract accepted the ZIL sent to it. |
| `receipt.cumulativeGas` | Number as string | The gas used by this transactions and all transactions in the same block that preceded it. This amount is always returned in units of Scilla gas. Internally, gas is tracked in units of EVM gas. When the true amount is not an exact multiple of the EVM to Scilla gas exchange rate, this value will be rounded. |
| `receipt.epochNum` | Number as string | The number of the block in which this transaction was mined. |
| `receipt.eventLogs` | Optional array | If the transaction was a Zilliqa transaction, the logs from any Scilla contracts that were executed. EVM logs are not included. |
| `receipt.errors` | Optional map | If the transaction was a Zilliqa transaction, a map of error codes produced by Scilla contracts, indexed by their call depth. |
| `receipt.exceptions` | Optional array | If the transaction was a Zilliqa transaction, a list of exceptions produced by Scilla contracts. |
| `receipt.success` | Boolean | Whether the transaction succeeded. |
| `gasPrice` | Number as string | The gas price of the transaction. This amount is always returned in units of Qa (10^-12 ZILs) per unit of Scilla gas. Truncation can occur here for Ethereum transactions.
| `gasLimit` | Number as string | The gas limit of the transaction. This amount is always returned in units of Scilla gas. Internally, gas is tracked in units of EVM gas. When the true amount is not an exact multiple of the EVM to Scilla gas exchange rate, this value will be rounded.
| `code` | Optional string | If the transaction was a Zilliqa transaction, the exact value of the transaction's code. Otherwise, if the transaction was a contract creation, a hex string with a `0x` prefix containing the payload of the transaction. |
| `data` | Optional string | If the transaction was a Zilliqa transaction, the exact value of the transaction's data. Otherwise, if the transaction was not a contract creation, a hex string with a `0x` prefix containing the payload of the transaction. |

### Transaction types

| Type | Value |
| ---- | ----- |
| Zilliqa | 1 |
| Ethereum Legacy | 2 |
| Ethereum EIP-2930 | 3 |
| Ethereum EIP-1559 | 4 |
| Intershard | 20 |

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetTransaction",
    "params": ["cd8727674bc05e0ede405597a218164e1c13c7103b9d0ba43586785f3d8cede5"]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# NodeJs

```js
const txn = await zilliqa.blockchain.getTransaction(
  "cd8727674bc05e0ede405597a218164e1c13c7103b9d0ba43586785f3d8cede5"
);
console.log(txn.result);
```

# Java

```java
public class App {
    public static void main(String[] args) throws IOException {
        HttpProvider client = new HttpProvider("{{ _api_url }}");
        Rep<Transaction> transaction = client.getTransaction("cd8727674bc05e0ede405597a218164e1c13c7103b9d0ba43586785f3d8cede5");
        System.out.println(new Gson().toJson(transaction));
    }
}
```

# Python

```python
from pyzil.zilliqa import chain
chain.set_active_chain(chain.MainNet)
print(chain.active_chain.api.GetTransaction("cd8727674bc05e0ede405597a218164e1c13c7103b9d0ba43586785f3d8cede5"))
```

# Go

```go
func GetTransaction() {
    provider := NewProvider("{{ _api_url }}")
    response := provider.GetTransaction("cd8727674bc05e0ede405597a218164e1c13c7103b9d0ba43586785f3d8cede5")
    result, _ := json.Marshal(response)
    fmt.Println(string(result))
}
```

# Response

```json
// Note: If the transaction is a for payment.
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": {
    "ID": "cd8727674bc05e0ede405597a218164e1c13c7103b9d0ba43586785f3d8cede5",
    "amount": "24999000000000",
    "gasLimit": "50",
    "gasPrice": "1000000000",
    "nonce": "1",
    "receipt": {
      "cumulative_gas": "1",
      "epoch_num": "589763",
      "success": true
    },
    "senderPubKey": "0x0347B5C6833ABD2AC0A6A7D85CF6BD0CC18084F6260B0C9DD2D491015BF2D47862",
    "signature": "0x593454623A6CE0FEA287E42583445B140F696F79CA508762B8AB44F202686CFA115A2AC36C31E643C9EB0D46A4E6CA8C4EEFD78D7E9A25220DC512C13C9600F0",
    "toAddr": "9148616bfdfab321bdd626682a8c446e193eabb2",
    "version": "65537"
  }
}
```

```json
// Note: If the transaction is for contract deployment.
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": {
    "ID": "f9170f9661a2ec5a90e6701618ba38d76257c00a1e5848d8f541e1ef52d11ede",
    "amount": "0",
    "code": "scilla_version 0\n\nimport BoolUtils IntUtils\n\n(* Twitter contract *)\n\n(***************************************************)\n(*               Associated library                *)\n(***************************************************)\nlibrary SocialPay\n\nlet one_msg =\n    fun (msg : Message) =>\n    let nil_msg = Nil {Message} in\n    Cons {Message} msg nil_msg\n\nlet two_msgs =\nfun (msg1 : Message) =>\nfun (msg2 : Message) =>\n  let msgs_tmp = one_msg msg2 in\n  Cons {Message} msg1 msgs_tmp\n\nlet is_valid_substring =\n  fun (tweet_text : String) =>\n  fun (start_pos : Uint32) =>\n  fun (hashtag_len : Uint32) =>\n    let string_length = builtin strlen tweet_text in\n    let valid_start_pos = builtin lt start_pos string_length in\n    let end_pos = builtin add start_pos hashtag_len in\n    let valid_end_pos = uint32_le end_pos string_length in\n    andb valid_start_pos valid_end_pos\n\n(* Error events *)\ntype Error =\n  | CodeNotAuthorized\n  | CodeRegisteredWithinWeek\n  | CodeUserNotRegistered\n  | CodeTweetAlreadyExists\n  | CodeTweetNotValid\n  | CodeTweetWithinDay\n\nlet make_error =\n  fun (result : Error) =>\n    let result_code = \n      match result with\n      | CodeNotAuthorized        => Int32 -1\n      | CodeRegisteredWithinWeek => Int32 -2\n      | CodeUserNotRegistered    => Int32 -3\n      | CodeTweetAlreadyExists   => Int32 -4\n      | CodeTweetNotValid        => Int32 -5\n      | CodeTweetWithinDay       => Int32 -6\n      end\n    in\n    { _exception : \"Error\"; code : result_code }\n\nlet tt = True\n\n(***************************************************)\n(*             The contract definition             *)\n(***************************************************)\n\ncontract SocialPay\n(\n    owner: ByStr20,\n    hashtag: String,\n    zils_per_tweet : Uint128,\n    blocks_per_day : Uint32,\n    blocks_per_week : Uint32,\n    donation_address : ByStr20\n)\n\n(* Map of tweet_id to recipient address *)\nfield verified_tweets: Map String ByStr20 = Emp String ByStr20\n\n(* Map of twitter_id to last withdraw block number *)\nfield last_withdrawal: Map String BNum = Emp String BNum\n\n(* Map of address to bool status of admin *)\nfield admins: Map ByStr20 Bool = Emp ByStr20 Bool\n\n(* Map of twitter_id to recipient address *)\nfield registered_users: Map String ByStr20 = Emp String ByStr20\n\n(* Emit Errors *)\nprocedure ThrowError(err: Error)\n  e = make_error err;\n  throw e\nend\n\nprocedure IsOwner(address: ByStr20)\n  is_owner = builtin eq address owner;\n  match is_owner with\n  | True =>\n  | False =>\n    err = CodeNotAuthorized;\n    ThrowError err\n  end\nend\n\nprocedure IsAdmin()\n  is_admin <- exists admins[_sender];\n  match is_admin with\n  | True =>\n  | False =>\n    err = CodeNotAuthorized;\n    ThrowError err\n  end\nend\n\nprocedure ConfigureAdmin(admin_address: ByStr20)\n  is_admin <- exists admins[admin_address];\n  match is_admin with\n  | True =>\n      delete admins[admin_address];\n      e = {_eventname : \"DeletedAdmin\"; admin_address: admin_address};\n      event e\n  | False =>\n      admins[admin_address] := tt;\n      e = {_eventname : \"AddedAdmin\"; admin_address: admin_address};\n      event e\n  end\nend\n\n(* Only owner can deposit ZIL *)\ntransition Deposit()\n  IsOwner _sender;\n  accept;\n  e = {_eventname : \"DepositSuccessful\"; sender: _sender; deposit_amount: _amount};\n  event e\nend\n\ntransition ConfigureAdmins(admin_addresses: List ByStr20)\n  IsOwner _sender;\n  forall admin_addresses ConfigureAdmin\nend\n\ntransition ConfigureUsers(twitter_id: String, recipient_address: ByStr20)\n  IsAdmin;\n  is_registered <- exists registered_users[twitter_id];\n  match is_registered with\n  | True =>\n      current_block <- & BLOCKNUMBER;\n      withdrawal <- last_withdrawal[twitter_id];\n      not_next_week_yet =\n          match withdrawal with\n          | Some last_withdraw_block =>\n              let next_week_block = builtin badd last_withdraw_block blocks_per_week in\n              builtin blt current_block next_week_block\n          | None =>\n              False\n          end;\n      match not_next_week_yet with\n      | True =>\n          err = CodeRegisteredWithinWeek;\n          ThrowError err\n      | False =>\n          registered_users[twitter_id] := recipient_address;\n          e = {_eventname : \"ConfiguredUserAddress\"; twitter_id: twitter_id; recipient_address: recipient_address};\n          event e\n      end\n  | False =>\n      registered_users[twitter_id] := recipient_address;\n      e = {_eventname : \"ConfiguredUserAddress\"; twitter_id: twitter_id; recipient_address: recipient_address};\n      event e\n  end\nend\n\n(* Only admins can call this transition                                         *)\n(* The following conditions are checked for (in that order):                    *)\n(*   1. Owner initiates the transition.                                         *)\n(*   2. The tweeter is already registered in the app his/her wallet             *)\n(*   3. The tweet hasn't been awarded before.                                   *)\n(*   4. Substring specs (start_pos) is valid.                                   *)\n(*   5. The substring matches the preset hashtag.                               *)\n(*   6. Sufficient time (blocks) have passed since the user was awarded before. *)\ntransition VerifyTweet (twitter_id: String, tweet_id: String, tweet_text: String, start_pos: Uint32)\n  IsAdmin;\n  get_recipient_address <- registered_users[twitter_id];\n  match get_recipient_address with\n  | None =>\n      err = CodeUserNotRegistered;\n      ThrowError err\n  | Some recipient_address =>\n      already_verified <- exists verified_tweets[tweet_id];\n      not_already_verified = negb already_verified;\n      hashtag_len = builtin strlen hashtag;\n      valid_substring = is_valid_substring tweet_text start_pos hashtag_len;\n      is_valid = andb valid_substring not_already_verified;\n      match is_valid with\n      | False =>\n          match already_verified with\n          | True =>\n              err = CodeTweetAlreadyExists;\n              ThrowError err\n          | False =>\n              err = CodeTweetNotValid;\n              ThrowError err\n          end\n      | True =>\n          match_hashtag = builtin substr tweet_text start_pos hashtag_len;\n          is_hashtag = builtin eq match_hashtag hashtag;\n          match is_hashtag with\n          | False =>\n              err = CodeTweetNotValid;\n              ThrowError err\n          | True =>\n              withdrawal <- last_withdrawal[twitter_id];\n              current_block <- & BLOCKNUMBER;\n              not_next_day_yet =\n                  match withdrawal with\n                  | Some last_withdraw_block =>\n                      let next_day_block = builtin badd last_withdraw_block blocks_per_day in\n                      builtin blt current_block next_day_block\n                  | None =>\n                      False\n                  end;\n              match not_next_day_yet with\n              | True =>\n                  err = CodeTweetWithinDay;\n                  ThrowError err\n              | False =>\n                  verified_tweets[tweet_id] := recipient_address;\n                  last_withdrawal[twitter_id] := current_block;\n                  e = {\n                          _eventname : \"VerifyTweetSuccessful\";\n                          sender: _sender;\n                          recipient: recipient_address;\n                          twitter_id: twitter_id;\n                          tweet_id: tweet_id;\n                          reward_amount: zils_per_tweet;\n                          matched_donation: zils_per_tweet\n                      };\n                  event e;\n                  msg_to_recipient = { \n                    _tag: \"\";\n                    _recipient: recipient_address;\n                    _amount: zils_per_tweet \n                  };\n                  msg_to_donation = {\n                    _tag: \"\";\n                    _recipient: donation_address;\n                    _amount: zils_per_tweet\n                  };\n                  msgs = two_msgs msg_to_recipient msg_to_donation;\n                  send msgs\n              end\n          end\n      end\n  end\nend\n\ntransition ReturnFund ()\n  IsOwner _sender;\n  current_bal <- _balance;\n  e = {\n    _eventname : \"ReturnFundSuccessful\";\n    returned_amount: current_bal\n  };\n  event e;\n  msg = {\n      _tag       : \"\";\n      _recipient : owner;\n      _amount    : current_bal\n  };\n  msgs = one_msg msg;\n  send msgs\nend",
    "data": "[{\"vname\":\"owner\",\"value\":\"0xf1a3d56321D6C0C9825bf3c34CB843719e99cBCA\",\"type\":\"ByStr20\"},{\"vname\":\"hashtag\",\"value\":\"#zilcovidheroes\",\"type\":\"String\"},{\"vname\":\"zils_per_tweet\",\"value\":\"25000000000000\",\"type\":\"Uint128\"},{\"vname\":\"blocks_per_day\",\"value\":\"1600\",\"type\":\"Uint32\"},{\"vname\":\"blocks_per_week\",\"value\":\"1600\",\"type\":\"Uint32\"},{\"vname\":\"donation_address\",\"value\":\"0x7AEB68fc38B29387D2e100db1E42c883C0519548\",\"type\":\"ByStr20\"},{\"vname\":\"_scilla_version\",\"type\":\"Uint32\",\"value\":\"0\"}]",
    "gasLimit": "25000",
    "gasPrice": "1000000000",
    "nonce": "9",
    "receipt": {
      "cumulative_gas": "10481",
      "epoch_num": "586524",
      "success": true
    },
    "senderPubKey": "0x020B94FDA851E2BF9392FF13D7CA33B417C5B95BCD0965238FF5074B7C8D31BC0D",
    "signature": "0x16196121EFEA86C9D91102EA200F02C88744E82B886C7AF72256F18615ADEE38EC18AFEE2739615896C5306F3C2642AA98CDFE113AC64A55981BBC2C82D31592",
    "toAddr": "0000000000000000000000000000000000000000",
    "version": "65537"
  }
}
```

```json
// Note: If the transaction is for contract call.
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": {
    "ID": "52605cee6955b3d14f5478927a90977b305325aff4ae0a2f9dbde758e7b92ad4",
    "amount": "50000000000000",
    "data": "{\"_tag\":\"sendFunds\",\"params\":[{\"vname\":\"accountValues\",\"type\":\"List (AccountValue)\",\"value\":[{\"constructor\":\"AccountValue\",\"argtypes\":[],\"arguments\":[\"0xc0e28525e9d329156e16603b9c1b6e4a9c7ed813\",\"50000000000000\"]}]}]}",
    "gasLimit": "25000",
    "gasPrice": "1000000000",
    "nonce": "3816",
    "receipt": {
      "accepted": true,
      "cumulative_gas": "878",
      "epoch_num": "589742",
      "success": true,
      "transitions": [
        {
          "addr": "0x9a65df55b2668a0f9f5f749267cb351a37e1f3d9",
          "depth": 0,
          "msg": {
            "_amount": "50000000000000",
            "_recipient": "0xc0e28525e9d329156e16603b9c1b6e4a9c7ed813",
            "_tag": "onFundsReceived",
            "params": []
          }
        }
      ]
    },
    "senderPubKey": "0x03DE40DF885B0E334D53FF5E5554589AAF46F2339FEBEE93213F2CCE52D1F488F4",
    "signature": "0xB19AB66C4410EE4833A9C5DEE600471DB4D711F6B61D2312988E6E70CC655409F18BB42BB6940B6263C8EA5CE08CAEC06111BDF19BE00D7E15F25515CAA45DAA",
    "toAddr": "9a65df55b2668a0f9f5f749267cb351a37e1f3d9",
    "version": "65537"
  }
}
```

```json
// Note: If the transaction has failed.
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": {
    "ID": "9b00b3b7d80dfb3818a6aaab0cb6fd3822b1bd7b3c6d5c6260579d12ae631a96",
    "amount": "0",
    "data": "{\"_tag\":\"ConfigureUsers\",\"params\":[{\"vname\":\"twitter_id\",\"type\":\"String\",\"value\":\"111111111\"},{\"vname\":\"recipient_address\",\"type\":\"ByStr20\",\"value\":\"0xAA9AC51920c75bDe16C8c27E529eDaFfcb15f530\"}]}",
    "gasLimit": "9000",
    "gasPrice": "1000000000",
    "nonce": "8260",
    "receipt": {
      "cumulative_gas": "1220",
      "epoch_num": "588004",
      "errors": {
        "0": [7]
      },
      "exceptions": [
        {
          "line": 87,
          "message": "Exception thrown: (Message [(_exception : (String \"Error\")) ; (code : (Int32 -2))])"
        },
        {
          "line": 100,
          "message": "Raised from IsAdmin"
        },
        {
          "line": 137,
          "message": "Raised from ConfigureUsers"
        }
      ],
      "success": false
    },
    "senderPubKey": "0x037B1722AAE35694A9F6E6C57DF5DD1274CBF568463AB50CEB6CBAD18C9BE291AA",
    "signature": "0x26676494B528757E602943DD2524277ED3850FE3F8E1060E8F36D8E18B5CB6D347698DB00DF0DD2C6786594BF420585ECA30D030C56FE946574AAD59456F110B",
    "toAddr": "7587a6d9b4def93c9c02475f5854c45eb4d9dac4",
    "version": "65537"
  }
}
```

# Arguments

| Parameter | Type   | Required | Description                                              |
| --------- | ------ | -------- | -------------------------------------------------------- |
| `id`      | string | Required | `"1"`                                                    |
| `jsonrpc` | string | Required | `"2.0"`                                                  |
| `method`  | string | Required | `"GetTransaction"`                                       |
| `params`  | string | Required | Transaction hash of 32 bytes of a specified transaction. |
