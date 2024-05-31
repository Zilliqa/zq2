---
id: {{ _id }}
title: Supported APIs
keywords: api,support,level,documented,implemented
---
---
# Supported APIs

If an API is not mentioned in this table, support for it is not planned.
Please open an issue or PR for APIs that you think should be included.

🟢 = Fully supported

🟠 = Partially implemented, full support planned

🔴 = Not yet implemented, full support planned

🔵 = Inapplicable to Zilliqa 2; we have no plans to implement it.

🟣 = Implemented, but not yet documented.



| Method                                    | Status                                          |
| ----------------------------------------- | ----------------------------------------------- |

{%- for api in apis -%}
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

