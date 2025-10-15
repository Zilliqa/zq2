# RPC Rate Limits

A rate-limit feature is introduced in version `v0.20.0`.
The purpose of this feature is to prevent abuse of the RPC API.

It has a fairly basic credit-limit mechanism:
1. Each caller is assigned a certain amount of credits at each time period.
2. Each RPC method has a certain credit-rate assigned to it.
3. The caller's credit balance is decremented by the credit rate of the RPC method, when the call is made.
4. If the caller's credit balance hits zero, the call will be rejected with an error response.

In the case when a caller has exhausted their credit limits, they will receive an error response with the following JSON structure:

```json
{"jsonrpc":"2.0","id":"2","error":{"code":-32000,"message":"RPC_RATE_LIMIT"}}
```

## Redis server

The credit-store uses Redis as the backend storage.
The `redis_server` field in the configuration file is used to specify the Redis server connection details e.g. `redis://user:pass@localhost:6379`.

## Custom Credit Rates
The credit rate for each RPC method can be defined in the `nodes.credit_rates` section of the configuration file.
This allows the rates to be easily changed without modifying the code.
A sample credit rate is provided in the `zilliqa/src/credits/rpc_pricing.toml` file.

Example:
```toml
[credit_rates]
eth_estimateGas = 300
eth_getBlockReceipts = 1000
eth_getBlockTransactionCountByNumber = 150
eth_sendRawTransaction = 80
eth_syncing = 5
```
When unspecified, the credit rate for that RPC method defaults to 500.

The pricing may be derived from empirical estimates of the total time it takes to service a request.
The arbitrary conversion rate used is `1 credit/ms`.

## Custom Rate Limits
Since each API server listens on a separate port, and provides a different set of RPC methods, the credit limits can be customized for each server, separately.
It is defined as the following object under the `default_credit` section of each API server.

This allows the limits to be customised, depending on service.
An externally facing port may have its credit limit reduced to prevent abuse, while an internal facing port may have its credit limit increased to allow for more requests.

The default credit object has two fields:
- `balance`: The amount of credits assigned at each time period.
- `period`: The time period (in seconds) for which the balance is valid.

Example:
```toml
default_credit = { balance = 10000, period = 60 }
```
In the example above, the default rate limit is set to 10000 credits per 60 seconds.
If unspecified, the default rate limit is, effectively, unlimited.
