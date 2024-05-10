---
id: {{ _id }}
{% if title is defined -%}
title: {{ title }}
{%else -%}
{{ throw(message="No title section") }}
{% endif -%}
{% if keywords is defined -%}
keywords: {{ keywords }}
{% else -%}
{{ throw(message="No keywords section") }}
{% endif -%}
---
---

{% if description is defined %}
{{description}}
{% else %}
{{ throw(message="No description section") }}
{% endif %}

### Example Request

{% if curl is defined %}
=== "cURL"

{{ curl }}
{% endif %}

### Example response

{% if response is defined %}
{{ response }}
{% else %}
{{ throw(message="No response section") }}
{% endif %}

### Arguments

{% if arguments is defined %}
{{ arguments }}
{% else %}
{{ throw(message="No arguments section") }}
{% endif %}
