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

{% if status is defined %}
{% if status == "Implemented" -%}
{% else -%}
{% if status == "NotYetImplemented"  -%}
!!! warning

    This API is not yet implemented in this version of Zilliqa 2.0
{% else %}
{% if status == "PartiallyImplemented" -%}
!!! warning

    Whilst this API is implemented in this version of Zilliqa 2.0, the implementation is not yet complete. Use with caution!
{% else %}
{% if status == "NotYetDocumented" -%}
!!! warning

    This call works differently in Zilliqa 2; documentation on the differences will be available in a future version.
{% else -%}
{% filter indent4 -%}
{{ status }}
{% endfilter -%}
{% endif -%}
{% endif -%}
{% endif -%}
{% endif -%}
{% endif -%}

{% if description is defined %}
{{description}}
{% else -%}
{{ throw(message="No description section") }}
{% endif -%}

### Example Request

{% if curl is defined %}
=== "cURL"

{% filter indent4 -%}
{{ curl }}
{% endfilter -%}
{% endif %}

{% if nodejs is defined %}
=== "node.js"

{% filter indent4 -%}
{{ nodejs }}
{% endfilter -%}
{% endif %}

{% if java is defined %}
=== "java"

{% filter indent4 -%}
{{ java }}
{% endfilter -%}
{% endif %}

{% if python is defined %}
=== "python"

{% filter indent4 -%}
{{ python }}
{% endfilter -%}
{% endif %}

{% if go is defined %}
=== "go"

{% filter indent4 -%}
{{ go }}
{% endfilter -%}
{% endif %}

{% if rust is defined %}
=== "rust"

{% filter indent4 -%}
{{ rust }}
{% endfilter -%}
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
