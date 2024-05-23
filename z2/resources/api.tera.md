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
{% if status == "NeverImplemented" -%}
!!! warning

    This API is no longer relevant to Zilliqa 2.0 and will not be implemented; attempts to call it will
    result in an error. This documentation is retained for historical reasons.
{% elif status == "Implemented" -%}
{% elif status == "NotYetImplemented"  -%}
!!! warning

    This API is not yet implemented in this version of Zilliqa 2.0
{% elif status == "PartiallyImplemented" -%}
!!! warning

    Whilst this API is implemented in this version of Zilliqa 2.0, the implementation is not yet complete. Use with caution!
{% elif status == "NotYetDocumented" -%}
!!! warning

    This call works differently in Zilliqa 2; documentation on the differences will be available in a future version.
{% else -%}
{% filter indent4 -%}
{{ status }}
{% endfilter -%}
{% endif -%}

{% if description is defined %}
{{description}}
{% else -%}
{{ throw(message="No description section") }}
{% endif -%}
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
