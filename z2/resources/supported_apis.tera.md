---
id: {{ _id }}
title: Supported APIs
keywords: api,support,level,documented,implemented
---

# APIs

## Zilliqa 2 APIs

The APIs implemented in Zilliqa 2 aim to provide the greatest possible compatibility with applications running on other EVM chains, as well as with applications developed for Zilliqa 1. Expand the menu on the left to navigate through the detailed documentation of the supported API methods.

## Supported APIs

Zilliqa 2 supports APIs from a number of sources:

 * `erigon_` and `ots_` APIs are provided for compatibility with
   Zilliqa's fork of
   [otterscan](https://github.com/Zilliqa/otterscan). These APIs are
   intended to be compatible with [the otterscan json-rpc API
   spec](https://github.com/otterscan/otterscan/blob/develop/docs/custom-jsonrpc.md).

 * Ethereum APIs (generally prefixed with `eth_`) are specified by the
   [Ethereum JSON-RPC
   spec](https://ethereum.github.io/execution-apis/api-documentation/)
   and intended to be compatible with Zilliqa 1,
   [geth](https://geth.ethereum.org/) and
   [erigon](https://erigon.tech/).  Some reference material is also
   taken from [QuickNode](https://www.quicknode.com/docs/ethereum),
   [Infura](https://docs.infura.io/) and
   [Alchemy](https://docs.alchemy.com/reference).

  * Zilliqa legacy APIs are intended, as far as possible, to be compatible
    with existing Zilliqa 1 applications. There are various
    differences due to the different construction of Zilliqa 2 which
    are noted on the individual API pages.

## List of entry points

If an API is not mentioned in this table, support for it is not planned.
Please open an issue or PR for APIs that you think should be included.

🟢 = Fully supported

🟠 = Partially implemented, full support planned

🔴 = Not yet implemented, full support planned

🔵 = Inapplicable to Zilliqa 2; we have no plans to implement it.

🟣 = Implemented, but not yet documented.



| Method                                    | Status                                          |
| ----------------------------------------- | ----------------------------------------------- |
{% for api in apis -%}
| {%- if api.method.JsonRpc -%}
`{{ api.method.JsonRpc.name }}`
{%- endif -%}
{%- if api.method.Rest -%}
{{ `api.method.Rest.uri` }}
{%- endif -%}                               | {% if api.status == "Implemented" %}🟢
{%- elif api.status == "NotYetImplemented" -%}🔴
{%- elif api.status == "PartiallyImplemented" -%}🟠
{%- elif api.status == "NeverImplemented" -%}🔵
{%- elif api.status == "NotYetDocumented" -%}🟣
{%- endif -%}           |
{% endfor %}

