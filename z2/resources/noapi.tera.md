---
id: {{ _id }}
{% if title is defined -%}
title: {{ title }}
{%else -%}
{{ throw(message="No title section") }}
{% endif -%}
---
---

!!! warning

    This API is not yet documented in this version of Zilliqa 2; be aware that its behaviour may change.
